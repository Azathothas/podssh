//! The roads to the quick tunnel's edge, raced (T-400): QUIC, HTTP/2 over
//! TCP and HTTP/2 inside WARP's tunnel, each a dial and the registration on
//! the connection that it made. The race is the relay hosts'
//! ([`crate::failover`], staggered): the first road starts at once, the next
//! when the one before has neither registered nor failed within the stagger
//! of 2 s, or at once when it failed, and the first connection that the edge
//! registers is kept. A road still dialing is dropped then, and a connection
//! that registered too is unregistered and closed, as its stop goes with the
//! race. The race takes whole registrations, not connections: a road that
//! connects and is refused is no road.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use podssh_ws::ProxyChoice;
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::edge::{self, Edge, EdgeIo};
use super::probe;
use super::quic::{self, EdgeConnection};
use super::register::{Connector, Registration};
use super::serve::{self, Ended, Step};
use crate::failover::{self, Attempt, Mode};

/// The roads' words, as the node's lines name them.
pub const QUIC: &str = "QUIC";
pub const HTTP2: &str = "HTTP/2";

/// A connection to the edge, by the transport that made it.
pub enum Link {
    Quic(EdgeConnection),
    Http2(Box<dyn EdgeIo>),
}

impl Link {
    /// Serve it as [`serve::serve`] does, over its transport.
    pub async fn serve<V, F>(
        self,
        registration: &Registration<'_>,
        visit: V,
        steps: mpsc::UnboundedSender<Step>,
        stop: impl Future<Output = ()>,
    ) -> Result<(), Ended>
    where
        V: FnMut(DuplexStream) -> F,
        F: Future<Output = ()> + Send + 'static,
    {
        match self {
            Link::Quic(edge) => edge.serve(registration, visit, steps, stop).await,
            Link::Http2(io) => serve::serve(io, registration, visit, steps, stop).await,
        }
    }
}

/// The dial of a road: its connection, or why it made none.
pub type Dial = Pin<Box<dyn Future<Output = Result<Link, String>> + Send>>;

/// A road to the edge: its words, and its dial.
pub struct Road {
    pub name: &'static str,
    pub dial: Dial,
}

/// QUIC to `found`, after the probe of UDP: where UDP is dropped, the race
/// goes on after the probe's 300 ms, not after QUIC's 5 s at each address.
pub fn quic(found: Edge) -> Road {
    let dial = async move {
        probe::edge(&found, probe::WAIT).await?;
        quic::connect_edge(&found).await.map(Link::Quic)
    };
    Road { name: QUIC, dial: Box::pin(dial) }
}

/// HTTP/2 over TCP to `found`, through `proxy` when there is one.
pub fn http2(proxy: ProxyChoice, found: Edge) -> Road {
    let dial = async move { edge::connect(&proxy, &found).await.map(Link::Http2) };
    Road { name: HTTP2, dial: Box::pin(dial) }
}

/// `roads` with the road named `first` before the others, which keep their
/// order: the road that won the last race starts the next one.
pub fn first_of(roads: &mut Vec<Road>, first: Option<&str>) {
    if let Some(at) = first.and_then(|first| roads.iter().position(|road| road.name == first)) {
        let road = roads.remove(at);
        roads.insert(0, road);
    }
}

/// Why a road gave way.
#[derive(Debug)]
pub enum Failed {
    /// Its dial made no connection.
    Dial(String),
    /// Its connection ended before the edge registered it.
    Ended(Ended),
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failed::Dial(why) => f.write_str(why),
            Failed::Ended(e) => write!(f, "{e}"),
        }
    }
}

/// A connection that the edge registered, served in a task of its own.
pub struct Serving {
    /// The road that made it, and where it landed.
    pub road: &'static str,
    pub location: String,
    /// Its steps after the registration.
    pub steps: mpsc::UnboundedReceiver<Step>,
    /// The word that ends it: an unregistration, then the close.
    pub(super) stop: watch::Sender<bool>,
    pub(super) served: JoinHandle<Result<(), Failed>>,
}

impl Serving {
    /// Ask for its end; its task unregisters and closes on its own.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }

    /// Its end: [`ended`].
    pub async fn finished(&mut self) -> Result<(), Ended> {
        ended(&mut self.served).await
    }
}

/// The end of a connection's task, served or stopped. Polled once it ended,
/// a handle is not polled again.
pub async fn ended(served: &mut JoinHandle<Result<(), Failed>>) -> Result<(), Ended> {
    match served.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(Failed::Ended(e))) => Err(e),
        // A connection that was kept had dialed; a task that panicked left
        // no connection.
        Ok(Err(Failed::Dial(_))) | Err(_) => Err(Ended::Closed),
    }
}

/// How a race ended.
pub struct Race {
    /// The connection kept.
    pub kept: Option<Serving>,
    /// Each road that failed, in the order of the roads.
    pub failed: Vec<(&'static str, Failed)>,
    /// Roads that registered in the same turn as the one kept: to stop.
    pub dismissed: Vec<Serving>,
    /// Roads before the one kept that had neither registered nor failed.
    pub silent: Vec<&'static str>,
}

/// Until `own` or `all` says stop, or its sender is gone.
async fn asked(mut own: watch::Receiver<bool>, mut all: watch::Receiver<bool>) {
    tokio::select! {
        _ = own.wait_for(|stop| *stop) => {}
        _ = all.wait_for(|stop| *stop) => {}
    }
}

/// One road of a race: its dial and its connection in a task, which `all`
/// or the race's stop ends; the attempt opens when the edge registered it.
async fn attempt<V, F>(
    road: Road,
    connector: Arc<Connector>,
    conn_index: u8,
    visit: V,
    all: watch::Receiver<bool>,
) -> Attempt<Serving, Failed>
where
    V: FnMut(DuplexStream) -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let Road { name, dial } = road;
    let (tell, mut steps) = mpsc::unbounded_channel();
    // Dropped with the attempt, when the race goes on without it: its task
    // reads that as its stop.
    let (stop, stopped) = watch::channel(false);
    let mut served = tokio::spawn(async move {
        let link = tokio::select! {
            link = dial => link.map_err(Failed::Dial)?,
            () = asked(stopped.clone(), all.clone()) => return Ok(()),
        };
        let registration = connector.registration(conn_index);
        link.serve(&registration, visit, tell, asked(stopped, all)).await.map_err(Failed::Ended)
    });
    let mut open = true;
    loop {
        tokio::select! {
            biased;
            step = steps.recv(), if open => match step {
                Some(Step::Registered { location }) => {
                    let result = Ok(Serving { road: name, location, steps, stop, served });
                    return Attempt { result, notes: Vec::new() };
                }
                Some(_) => {}
                // The task ended: its end follows.
                None => open = false,
            },
            ended = &mut served => {
                let why = match ended {
                    Ok(Err(why)) => why,
                    Ok(Ok(())) => Failed::Dial("stopped before its registration".into()),
                    Err(e) => Failed::Dial(format!("its task ended: {e}")),
                };
                return Attempt { result: Err(why), notes: Vec::new() };
            }
        }
    }
}

/// Race `roads` for the connection `conn_index` of `connector`, each
/// visitor to `visit`; `all` stops each connection of the race, the kept
/// one too, whenever it says so.
pub async fn race<V, F>(
    roads: Vec<Road>,
    connector: Arc<Connector>,
    conn_index: u8,
    visit: V,
    all: watch::Receiver<bool>,
) -> Race
where
    V: FnMut(DuplexStream) -> F + Clone + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let names: Vec<&'static str> = roads.iter().map(|road| road.name).collect();
    let mut roads: Vec<Option<Road>> = roads.into_iter().map(Some).collect();
    let start = |i: usize| {
        let road = roads[i].take().expect("the race starts each road once");
        attempt(road, connector.clone(), conn_index, visit.clone(), all.clone())
    };
    // A refusal for good is the tunnel's: each road would get it.
    let stops = |failed: &Failed| matches!(failed, Failed::Ended(Ended::Refused { retry: false, .. }));
    let raced = failover::race(names.len(), Mode::Staggered, start, stops, &mut |_: &str| {}).await;
    Race {
        kept: raced.kept.map(|(_, serving)| serving),
        failed: raced.failed.into_iter().map(|(i, why)| (names[i], why)).collect(),
        dismissed: raced.dismissed.into_iter().map(|(_, serving)| serving).collect(),
        silent: raced.silent.into_iter().map(|i| names[i]).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn road(name: &'static str) -> Road {
        Road { name, dial: Box::pin(async { Err::<Link, String>("a test's road".into()) }) }
    }

    #[test]
    fn the_road_that_won_starts_the_next_race_and_the_others_keep_their_order() {
        let names = |roads: &Vec<Road>| roads.iter().map(|r| r.name).collect::<Vec<_>>();
        let mut roads = vec![road(QUIC), road(HTTP2), road("WARP")];
        first_of(&mut roads, Some("WARP"));
        assert_eq!(names(&roads), ["WARP", QUIC, HTTP2]);
        first_of(&mut roads, Some(HTTP2));
        assert_eq!(names(&roads), [HTTP2, "WARP", QUIC]);
        // None, or a road that this race has not: the order stays.
        first_of(&mut roads, None);
        first_of(&mut roads, Some(QUIC));
        first_of(&mut roads, Some("a road of no race"));
        assert_eq!(names(&roads), [QUIC, HTTP2, "WARP"]);
    }
}
