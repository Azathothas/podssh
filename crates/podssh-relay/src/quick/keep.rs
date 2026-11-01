//! The node's connections to the quick tunnel's edge, kept (T-400, T-402): a
//! race of the roads that the node gives for each connection
//! ([`super::roads`]), the line of each registration, and a new race after
//! each loss, its wait doubled from 1 s to 30 s, or the edge's own after a
//! refusal for now. A second connection, of the index 1, starts once the
//! first registered, the road that won first at the head of its race. On the
//! edge's GOAWAY a connection's next race starts at once, under the other
//! index of its pair (0 and 2, 1 and 3), while the old connection keeps its
//! visitors for the drain. A refusal for good of the first connection, and a
//! first race in which no road reached the edge, end the node; the second
//! connection's end is its own. At the stop, each connection unregisters.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::DuplexStream;
use tokio::sync::watch;
use tokio::time::Instant;

use super::register::Connector;
use super::roads::{self, Failed, Road, Serving};
use super::serve::{Ended, Step, CLOSE_GRACE, DRAIN, UNREGISTER_WAIT};

/// The waits between races after a loss: doubled from the first, to the
/// most.
pub const RETRY_FIRST: Duration = Duration::from_secs(1);
pub const RETRY_MOST: Duration = Duration::from_secs(30);
/// How long the end, or the next race of its index, waits for a connection
/// that drains to unregister and close: the unregistration's wait, the
/// close's grace, and a second.
const END_WAIT: Duration = Duration::from_secs(UNREGISTER_WAIT.as_secs() + CLOSE_GRACE.as_secs() + 1);

/// What one race asks of the node's roads: the index of the connection, and
/// the road that won the last race, to start with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub conn_index: u8,
    pub first: Option<&'static str>,
}

/// The node's roads for a race, made for each race, as the edge's regions
/// are asked for again each time.
pub type Roads = Arc<dyn Fn(Plan) -> Made + Send + Sync>;
/// The making of a race's roads.
pub type Made = Pin<Box<dyn Future<Output = Vec<Road>> + Send>>;
/// Where the node's lines go.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// What the node gives to keep its connections.
pub struct Keep<V> {
    pub connector: Arc<Connector>,
    pub visit: V,
    pub roads: Roads,
    pub say: Say,
    /// Called once, after the line of the first registration: a detached
    /// node goes on then.
    pub ready: Box<dyn FnOnce() + Send>,
    /// How many connections the node keeps at once: 1, or 2 (T-402).
    pub connections: u8,
}

/// Why the node ends with no stop asked.
#[derive(Debug)]
pub enum Gone {
    /// No road reached the edge before any registration: what each said.
    Unreached(String),
    /// The edge refused the tunnel's connection for good: its line.
    Refused(String),
}

/// What the connections of one node share.
struct Shared<V> {
    connector: Arc<Connector>,
    visit: V,
    roads: Roads,
    say: Say,
    ready: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// The road that won the latest race of any connection: each next race
    /// starts with it, and the second connection waits for it.
    won: watch::Sender<Option<&'static str>>,
}

impl<V> Shared<V> {
    /// A line of the connection `conn_index`; the first's lines name none.
    fn tell(&self, conn_index: u8, line: String) {
        match conn_index {
            0 => (self.say)(line),
            n => (self.say)(format!("connection {n}: {line}")),
        }
    }
}

/// " (podssh speaks ...)" after an end that a change of cloudflared would
/// give (T-339).
fn speaks(e: &Ended) -> String {
    match e.may_be_the_protocol() {
        true => format!(" (podssh speaks {})", super::SPEAKS),
        false => String::new(),
    }
}

/// The line of each road that failed.
fn lost(failed: &[(&'static str, Failed)]) -> String {
    let each = failed.iter().map(|(road, why)| match why {
        Failed::Ended(e) => format!("{road}: {e}{}", speaks(e)),
        Failed::Dial(why) => format!("{road}: {why}"),
    });
    let each: Vec<String> = each.collect();
    match each.is_empty() {
        true => "no road to the edge".to_string(),
        false => each.join("; "),
    }
}

/// The end of `ended`, a connection's or a road's: the node's end for a
/// refusal for good; else the line of the wait, which a refusal for now
/// sets to the edge's.
fn after(ended: &Ended, wait: &mut Duration) -> Result<String, Gone> {
    match ended {
        Ended::Refused { cause, retry: false, .. } => {
            Err(Gone::Refused(format!("the edge refused the tunnel's connection: {cause}{}", speaks(ended))))
        }
        Ended::Refused { cause, after, .. } => {
            *wait = (*after).clamp(RETRY_FIRST, RETRY_MOST);
            let secs = wait.as_secs();
            Ok(format!("the edge refused the connection for now ({cause}){}; trying again in {secs} s", speaks(ended)))
        }
        e => Ok(format!("{e}{}; connecting again in {} s", speaks(e), wait.as_secs())),
    }
}

/// Wait `wait`, unless the end comes first, and double it for the next time.
async fn pause(wait: &mut Duration, end: &mut watch::Receiver<bool>) {
    tokio::select! {
        () = tokio::time::sleep(*wait) => {}
        _ = end.wait_for(|end| *end) => {}
    }
    *wait = (*wait * 2).min(RETRY_MOST);
}

/// How a connection that registered went.
enum Served {
    /// The edge sent GOAWAY: the connection drains in its task.
    GoingAway,
    /// It ended, at the end asked for or before it.
    Ended(Result<(), Ended>),
}

/// Until `serving` ends or the edge sends its GOAWAY, its lines said.
async fn served<V>(shared: &Shared<V>, serving: &mut Serving, conn_index: u8) -> Served {
    let mut open = true;
    loop {
        tokio::select! {
            // A GOAWAY and the close that follows it at once: the GOAWAY.
            biased;
            step = serving.steps.recv(), if open => match step {
                Some(Step::GoingAway) => return Served::GoingAway,
                Some(Step::Unregistered) => shared.tell(conn_index, "unregistered".into()),
                Some(_) => {}
                None => open = false,
            },
            ended = roads::ended(&mut serving.served) => return Served::Ended(ended),
        }
    }
}

/// The other index of the pair of `conn_index`: 0 and 2, 1 and 3, as the
/// edge took four connections of one quick tunnel (cfrs #54).
fn paired(conn_index: u8) -> u8 {
    conn_index ^ 2
}

/// One connection, the index `base` and its pair's, kept until `end`.
async fn connection<V, F>(shared: &Shared<V>, base: u8, mut end: watch::Receiver<bool>) -> Result<(), Gone>
where
    V: FnMut(DuplexStream) -> F + Clone + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let (mut wait, mut reached, mut index) = (RETRY_FIRST, false, base);
    // The connection that drains after a GOAWAY, while the next one serves.
    let mut draining: Option<Serving> = None;
    let kept = loop {
        if *end.borrow() {
            break Ok(());
        }
        let (began, plan) = (Instant::now(), Plan { conn_index: index, first: *shared.won.borrow() });
        let (made, ours, visitor, all) =
            ((*shared.roads)(plan), shared.connector.clone(), shared.visit.clone(), end.clone());
        let race = async move { roads::race(made.await, ours, index, visitor, all).await };
        let race = tokio::select! {
            race = race => race,
            _ = end.wait_for(|end| *end) => break Ok(()),
        };
        // Each connection that registered too is let go.
        for dismissed in &race.dismissed {
            dismissed.stop();
        }
        let Some(mut serving) = race.kept else {
            // A road that connected reached the edge, though it registered
            // nothing: the node goes on, as the edge is there.
            reached |= race.failed.iter().any(|(_, why)| matches!(why, Failed::Ended(_)));
            let refused = race.failed.iter().find_map(|(_, why)| match why {
                Failed::Ended(e @ Ended::Refused { .. }) => Some(e),
                _ => None,
            });
            let line = match refused.map(|refused| after(refused, &mut wait)) {
                Some(Ok(line)) => line,
                Some(Err(gone)) => break Err(gone),
                None if !reached && base == 0 => break Err(Gone::Unreached(lost(&race.failed))),
                None => format!("{}; trying again in {} s", lost(&race.failed), wait.as_secs()),
            };
            shared.tell(index, line);
            pause(&mut wait, &mut end).await;
            continue;
        };
        (reached, wait) = (true, RETRY_FIRST);
        shared.won.send_replace(Some(serving.road));
        for (road, why) in &race.failed {
            shared.tell(index, format!("{road} gave way: {why}"));
        }
        for road in &race.silent {
            shared.tell(index, format!("{road} gave way: it had not registered when {} did", serving.road));
        }
        let (took, road, location) = (began.elapsed().as_secs_f64(), serving.road, &serving.location);
        shared.tell(index, format!("registered at Cloudflare's {location}, over {road} (its race took {took:.1} s)"));
        let ready = shared.ready.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(ready) = ready {
            ready();
        }
        let ended = match served(shared, &mut serving, index).await {
            Served::GoingAway => {
                let drain = DRAIN.as_secs();
                let line = format!("the edge sent GOAWAY: a new connection now; its visitors stay up to {drain} s");
                shared.tell(index, line);
                // A drain that still runs holds the index that comes next:
                // it ends first.
                if let Some(mut older) = draining.replace(serving) {
                    older.stop();
                    let _ = tokio::time::timeout(END_WAIT, older.finished()).await;
                }
                index = paired(index);
                continue;
            }
            Served::Ended(ended) => ended,
        };
        let line = match ended.map_err(|e| after(&e, &mut wait)) {
            Ok(()) => break Ok(()),
            Err(Ok(line)) => line,
            Err(Err(gone)) => break Err(gone),
        };
        shared.tell(index, line);
        pause(&mut wait, &mut end).await;
    };
    // The connection that drains ends with the others: `end` asked for it,
    // or this asks.
    if let Some(mut old) = draining {
        old.stop();
        let _ = tokio::time::timeout(END_WAIT, old.finished()).await;
    }
    kept
}

/// Keep the node's connections to the edge until `stop`, or until the node
/// must end.
pub async fn keep<V, F>(keep: Keep<V>, stop: watch::Receiver<bool>) -> Result<(), Gone>
where
    V: FnMut(DuplexStream) -> F + Clone + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let Keep { connector, visit, roads, say, ready, connections } = keep;
    let won = watch::channel(None).0;
    let shared = Shared { connector, visit, roads, say, ready: Mutex::new(Some(ready)), won };
    // Each connection's end: the stop, or the node's end that the first
    // connection's end is. A stop whose sender is gone is a stop.
    let (ending, end) = watch::channel(false);
    let ending = Arc::new(ending);
    tokio::spawn({
        let (ending, mut stop) = (ending.clone(), stop);
        async move {
            let _ = stop.wait_for(|stop| *stop).await;
            ending.send_replace(true);
        }
    });
    let first = async {
        let kept = connection(&shared, 0, end.clone()).await;
        ending.send_replace(true);
        kept
    };
    let second = async {
        let (mut won, mut until) = (shared.won.subscribe(), end.clone());
        if connections < 2 {
            return;
        }
        tokio::select! {
            _ = won.wait_for(|road| road.is_some()) => {}
            _ = until.wait_for(|end| *end) => return,
        }
        // The second connection's end leaves the first serving.
        if let Err(Gone::Refused(line) | Gone::Unreached(line)) = connection(&shared, 1, end.clone()).await {
            shared.tell(1, format!("{line}; the node keeps one connection"));
        }
    };
    let (kept, ()) = tokio::join!(first, second);
    kept
}
