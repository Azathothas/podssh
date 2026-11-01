//! The node's connection to the quick tunnel's edge, kept (T-400): a race of
//! the roads that the node gives for each connection ([`super::roads`]), the
//! line of each registration, and a new race after each loss, its wait
//! doubled from 1 s to 30 s, or the edge's own after a refusal for now. A
//! refusal for good, and a first race in which no road reached the edge,
//! end the node; at the stop, the connection unregisters.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::DuplexStream;
use tokio::sync::watch;
use tokio::time::Instant;

use super::register::Connector;
use super::roads::{self, Failed, Road, Serving};
use super::serve::{Ended, Step};

/// The waits between races after a loss: doubled from the first, to the
/// most.
pub const RETRY_FIRST: Duration = Duration::from_secs(1);
pub const RETRY_MOST: Duration = Duration::from_secs(30);

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

/// What the node gives to keep its connection.
pub struct Keep<V> {
    pub connector: Arc<Connector>,
    pub visit: V,
    pub roads: Roads,
    pub say: Say,
    /// Called once, after the line of the first registration: a detached
    /// node goes on then.
    pub ready: Box<dyn FnOnce() + Send>,
}

/// Why the node ends with no stop asked.
#[derive(Debug)]
pub enum Gone {
    /// No road reached the edge before any registration: what each said.
    Unreached(String),
    /// The edge refused the tunnel's connection for good: its line.
    Refused(String),
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

/// Wait `wait`, unless the stop comes first, and double it for the next time.
async fn pause(wait: &mut Duration, stop: &mut watch::Receiver<bool>) {
    tokio::select! {
        () = tokio::time::sleep(*wait) => {}
        _ = stop.wait_for(|stop| *stop) => {}
    }
    *wait = (*wait * 2).min(RETRY_MOST);
}

/// Until `serving` ends, its lines said; its end, which `stop` asks for
/// through the race.
async fn served(serving: &mut Serving, say: &Say) -> Result<(), Ended> {
    let mut open = true;
    loop {
        tokio::select! {
            step = serving.steps.recv(), if open => match step {
                Some(Step::Unregistered) => say("unregistered".into()),
                Some(_) => {}
                None => open = false,
            },
            ended = roads::ended(&mut serving.served) => return ended,
        }
    }
}

/// Keep the node's connection to the edge until `stop`, or until the node
/// must end.
pub async fn keep<V, F>(keep: Keep<V>, mut stop: watch::Receiver<bool>) -> Result<(), Gone>
where
    V: FnMut(DuplexStream) -> F + Clone + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let Keep { connector, visit, roads, say, ready } = keep;
    let mut ready = Some(ready);
    let (mut wait, mut reached, mut first) = (RETRY_FIRST, false, None);
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let (began, plan) = (Instant::now(), Plan { conn_index: 0, first });
        let (made, ours, visitor, all) = ((*roads)(plan), connector.clone(), visit.clone(), stop.clone());
        let race = async move { roads::race(made.await, ours, 0, visitor, all).await };
        let race = tokio::select! {
            race = race => race,
            _ = stop.wait_for(|stop| *stop) => return Ok(()),
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
            let line = match refused {
                Some(refused) => after(refused, &mut wait)?,
                None if !reached => return Err(Gone::Unreached(lost(&race.failed))),
                None => format!("{}; trying again in {} s", lost(&race.failed), wait.as_secs()),
            };
            say(line);
            pause(&mut wait, &mut stop).await;
            continue;
        };
        (reached, wait, first) = (true, RETRY_FIRST, Some(serving.road));
        for (road, why) in &race.failed {
            say(format!("{road} gave way: {why}"));
        }
        for road in &race.silent {
            say(format!("{road} gave way: it had not registered when {} did", serving.road));
        }
        let (took, road, location) = (began.elapsed().as_secs_f64(), serving.road, &serving.location);
        say(format!("registered at Cloudflare's {location}, over {road} (its race took {took:.1} s)"));
        if let Some(ready) = ready.take() {
            ready();
        }
        let line = match served(&mut serving, &say).await {
            Ok(()) => return Ok(()),
            Err(e) => after(&e, &mut wait)?,
        };
        say(line);
        pause(&mut wait, &mut stop).await;
    }
}
