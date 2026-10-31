//! A link's first message, and a new link that takes a session up (T-351):
//! out of `carry.rs`, at its 500 lines. The connect's success comes first
//! on a new session, a reconnect's on a link that takes one up, each within
//! the wait of the probe; a message that IAP adds and podssh does not know
//! is skipped, as gcloud and IAP Desktop skip one.

use std::fmt::Display;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use super::super::close::{fate, Fate};
use super::super::flow::Flow;
use super::super::frame::{self, Message};
use super::super::Resume;
use super::{lock, Dial, Ended, Line, Say, RECONNECTS, RECONNECT_WAIT};
use crate::frame as ws;
use crate::session::{close_code_and_reason, RelaySession};

/// The first message of a link that counts: the connect's success, or a
/// reconnect's.
pub(super) enum First {
    Sid(Vec<u8>),
    Took(u64),
}

pub(super) enum Unopened {
    Closed { code: Option<u16>, reason: String },
    Silent,
    Fault(String),
}

/// Wait `wait` at most for the connect's success (`connect`), else for a
/// reconnect's; a message that IAP adds and podssh does not know is skipped.
pub(super) async fn first<S>(link: &RelaySession<S>, connect: bool, wait: Duration) -> Result<First, Unopened>
where
    S: AsyncRead + AsyncWrite,
{
    let read = async {
        loop {
            let f = match link.read_frame().await {
                Ok(f) => f,
                Err(e) => return Err(Unopened::Fault(e.to_string())),
            };
            match f.opcode {
                ws::OPCODE_BINARY => {}
                ws::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    return Err(Unopened::Closed { code, reason });
                }
                other => return Err(Unopened::Fault(format!("IAP sent a WebSocket message of opcode {other:#x}"))),
            }
            match frame::decode(&f.payload) {
                Ok(Message::ConnectSuccessSid(sid)) if connect => return Ok(First::Sid(sid)),
                Ok(Message::ReconnectSuccessAck(n)) if !connect => return Ok(First::Took(n)),
                Ok(Message::Unknown(_) | Message::LongClose { .. }) => {}
                Ok(other) => {
                    return Err(Unopened::Fault(format!("IAP sent {} before the session opened", what(&other))))
                }
                Err(e) => return Err(Unopened::Fault(e.to_string())),
            }
        }
    };
    tokio::time::timeout(wait, read).await.unwrap_or(Err(Unopened::Silent))
}

/// A message, as a line names it.
pub(super) fn what(message: &Message) -> &'static str {
    match message {
        Message::ConnectSuccessSid(_) => "a connect's success",
        Message::ReconnectSuccessAck(_) => "a reconnect's success",
        Message::Data(_) => "data",
        Message::Ack(_) => "an acknowledgement",
        Message::LongClose { .. } => "a long close",
        Message::Unknown(_) => "a message of a tag that podssh does not know",
    }
}

/// A Close's code and reason, for a line.
pub(super) fn words(code: Option<u16>, reason: &str) -> String {
    match (code, reason.is_empty()) {
        (Some(code), true) => format!("IAP's close {code}"),
        (Some(code), false) => format!("IAP's close {code}: {reason}"),
        (None, _) => "IAP's close with no code".into(),
    }
}

/// A new link that takes the session up, in [`RECONNECTS`] tries at most:
/// the reconnect's success, within `wait`, says which of the client's bytes
/// the server took, and the rest goes again.
pub(super) async fn take_up<S, E>(
    dial: &Dial<S, E>,
    sid: &[u8],
    flow: &Mutex<Flow>,
    say: &Say,
    wait: Duration,
) -> Result<RelaySession<S>, Ended>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    E: Display + Send + 'static,
{
    let mut pause = RECONNECT_WAIT;
    let mut last = String::new();
    for attempt in 1..=RECONNECTS {
        tokio::time::sleep(pause).await;
        pause *= 2;
        let resume = Resume { sid: sid.to_vec(), received: lock(flow).received() };
        let link = match dial(Some(resume)).await {
            Ok(link) => link,
            Err(e) => {
                last = e.to_string();
                say(Line::Verbose(format!("a new link to IAP did not open (try {attempt} of {RECONNECTS}): {last}")));
                continue;
            }
        };
        let took = match first(&link, false, wait).await {
            Ok(First::Took(took)) => took,
            Ok(First::Sid(_)) => return Err(Ended::Lost("IAP answered a reconnect with a new session".into())),
            Err(Unopened::Closed { code, reason }) => match fate(code) {
                Fate::End => return Err(Ended::Normal),
                Fate::Fail(_) => return Err(Ended::Closed { code, reason }),
                Fate::Reauthenticate | Fate::Resume => {
                    last = words(code, &reason);
                    continue;
                }
            },
            Err(Unopened::Silent) => {
                last = format!("no reconnect's success within {} s", wait.as_secs());
                continue;
            }
            Err(Unopened::Fault(why)) => {
                last = why;
                continue;
            }
        };
        let resend = lock(flow).resume(took);
        let resend = resend.map_err(|e| Ended::Lost(e.to_string()))?;
        say(Line::Verbose(format!("IAP took {took} bytes of this side's; {} messages go again", resend.len())));
        let mut sent = Ok(());
        for chunk in &resend {
            let message = frame::data(chunk).map_err(|e| Ended::Fault(e.to_string()))?;
            sent = link.send_binary(&message).await.map_err(|e| e.to_string());
            if sent.is_err() {
                break;
            }
        }
        match sent {
            Ok(()) => return Ok(link),
            Err(why) => last = why,
        }
    }
    Err(Ended::Lost(format!("no new link took the session up in {RECONNECTS} tries: {last}")))
}
