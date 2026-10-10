//! The changes of the node's links on stderr (T-104): one line for each drop, with the wait
//! before the next attempt, one for each connection that comes back after a drop, and one for a
//! refusal of the node key. A first connection says nothing: each run has one.

use std::io::Write;

use podssh_ts::node::{LinkChange, LinkEvent, LinkKind};
use tokio::sync::broadcast::{self, error::RecvError};

/// The line for `event`, or `None` for a change that is said with no line.
pub fn link_line(event: &LinkEvent) -> Option<String> {
    let link = match event.link {
        LinkKind::Control => "the connection to the control server".to_string(),
        LinkKind::Derp(region) => format!("the DERP link of region {region}"),
    };
    // A reason can hold a relay's own words: made safe for a terminal.
    let safe = |reason: &str| podssh_ws::text::one_line(reason);
    match &event.change {
        LinkChange::Connected { again: false } => None,
        LinkChange::Connected { again: true } => Some(format!("podssh ts: {link} is up again.")),
        LinkChange::Dropped { reason, retry_in } => Some(format!(
            "podssh ts: {link} dropped ({}); trying again in {:.1} s.",
            safe(reason),
            retry_in.as_secs_f32()
        )),
        LinkChange::Refused { reason } => Some(format!(
            "podssh ts: {link} was refused ({}): the relay does not admit this node's key, and it is not dialled again.",
            safe(reason)
        )),
    }
}

/// Write the line of each change that `events` gives to stderr, until the node ends. A receiver
/// that fell behind says how many changes it missed.
pub async fn print(mut events: broadcast::Receiver<LinkEvent>) {
    loop {
        let line = match events.recv().await {
            Ok(event) => link_line(&event),
            Err(RecvError::Lagged(missed)) => Some(format!("podssh ts: {missed} changes of the links were missed.")),
            Err(RecvError::Closed) => return,
        };
        if let Some(line) = line {
            let _ = writeln!(std::io::stderr(), "{line}");
        }
    }
}
