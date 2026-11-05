//! A far end's sessions handed to the binary that takes its place (T-668):
//! what [`super::keep::Keeper::hand_over`] gives for each session, in bytes
//! that the next binary reads, and what [`super::keep::Keeper::take_over`]
//! takes back there. The layer's state is its offsets, its replay buffer
//! and the bytes not yet written to the target, whole: a client's resume
//! on the next binary goes on from its offset, as after any lost link. The
//! target's connection moves by its own means ([`Movable`]), and the
//! caller passes the socket between the processes.
//!
//! The layer's records stay as they are: the next binary reads this state,
//! never the wire, so a build that changes the records still takes the
//! sessions of the one before, as long as it reads [`VERSION`].

pub mod wire;

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use zeroize::Zeroizing;

use super::link::{LinkParts, ReplayParts};
use super::pump::CarryParts;
use super::record::{cut_reason, MAX_REASON};
use super::replay::MAX_CAPACITY;
use super::secret::{Secret, SessionId};
pub use wire::Unreadable;
use wire::{Get, Put};

/// The version of the bytes of a session that this build writes, and the
/// only one that it reads.
pub const VERSION: u8 = 1;

/// The most bytes held for a target that a session hands over: twice the
/// largest buffer, as the pump holds at most that for a slow target.
const MAX_HELD: usize = 2 * MAX_CAPACITY + (1 << 20);

tokio::task_local! {
    /// The layer's session whose target opens in this task.
    static LAYER: SessionId;
}

/// Run `opening` as the opening of the target of the layer's session `id`:
/// what starts there (the end-to-end channel's task) learns the session's
/// id ([`current`]), so that a handover finds it by that id.
pub async fn scope<F: Future>(id: SessionId, opening: F) -> F::Output {
    LAYER.scope(id, opening).await
}

/// The layer's session whose target opens now, if one does.
pub fn current() -> Option<SessionId> {
    LAYER.try_with(|id| *id).ok()
}

/// A session's target, out of this process.
pub struct Moved {
    /// Its connection.
    pub socket: std::net::TcpStream,
    /// The state of the end-to-end channel above the connection, in the
    /// channel's own bytes (`crate::e2e::hold`); none where the layer
    /// carries the target's bytes as they are.
    pub channel: Option<Zeroizing<Vec<u8>>>,
}

/// The future of a target's move.
pub type Moving = Pin<Box<dyn Future<Output = Result<Moved, String>> + Send>>;

/// A target that the binary after this one can take: a TCP connection, or
/// the channel above one. One that cannot says why.
pub trait Movable: Sized + Send + 'static {
    fn move_out(self, id: SessionId) -> Moving;
}

impl Movable for tokio::net::TcpStream {
    fn move_out(self, _id: SessionId) -> Moving {
        Box::pin(async move {
            let socket = self.into_std().map_err(|e| format!("its connection to the target: {e}"))?;
            Ok(Moved { socket, channel: None })
        })
    }
}

/// What the layer kept of a session.
pub enum Kept {
    /// A session that waits for its client, with its target.
    Carried { link: LinkParts, carry: CarryParts },
    /// A session that ended here, or that the next binary cannot carry on:
    /// its id waits alone, and a resume hears `CLOSE` with `reason` (T-586).
    Closed { received: u64, reason: String },
}

/// One session of a far end, as it goes to the next binary.
pub struct LayerState {
    pub id: SessionId,
    pub secret: Secret,
    /// How long the session waits for its client from now, with no link.
    pub left: Duration,
    pub kept: Kept,
}

impl std::fmt::Debug for LayerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kept = match &self.kept {
            Kept::Carried { link, carry } => format!("{link:?}, {carry:?}"),
            Kept::Closed { received, reason } => format!("closed at {received}: {reason:?}"),
        };
        write!(f, "LayerState {{ {}, {} ms left, {kept} }}", self.id, self.left.as_millis())
    }
}

/// One session out of a far end: its layer's state, and its target or why
/// that does not move, for which the next binary ends the session at its
/// resume with those words.
pub struct Handed {
    pub state: LayerState,
    pub target: Result<Moved, String>,
}

const CARRIED: u8 = 1;
const CLOSED: u8 = 2;

impl LayerState {
    /// The state as bytes: [`VERSION`] first.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut put = Put::new();
        put.u8(VERSION);
        put.fixed(&self.id.0);
        put.fixed(self.secret.bytes());
        put.u64(u64::try_from(self.left.as_millis()).unwrap_or(u64::MAX));
        match &self.kept {
            Kept::Carried { link, carry } => {
                put.u8(CARRIED);
                put_link(&mut put, link);
                put.bytes(&carry.undelivered);
                put.bool(carry.app_ended);
                put.bool(carry.app_shut);
            }
            Kept::Closed { received, reason } => {
                put.u8(CLOSED);
                put.u64(*received);
                put.text(&cut_reason(reason));
            }
        }
        put.into_bytes()
    }

    /// The state from its bytes: another version, or bytes that do not hold
    /// together, are refused with why.
    pub fn decode(bytes: &[u8]) -> Result<LayerState, Unreadable> {
        let mut get = Get::new(bytes);
        let version = get.u8("the version")?;
        if version != VERSION {
            return Err(Unreadable(format!("a session of version {version}, where this binary reads {VERSION}")));
        }
        let id = SessionId(get.fixed("the session's id")?);
        let secret = Secret::from_bytes(get.fixed("the session's secret")?);
        let left = Duration::from_millis(get.u64("the time left")?);
        let kept = match get.u8("the kind of the session")? {
            CARRIED => {
                let link = get_link(&mut get)?;
                let undelivered = get.bytes("the bytes for the target", MAX_HELD)?.to_vec();
                let (app_ended, app_shut) = (get.bool("the target's end")?, get.bool("the target's shut")?);
                Kept::Carried { link, carry: CarryParts { undelivered, app_ended, app_shut } }
            }
            CLOSED => {
                let received = get.u64("the received offset")?;
                Kept::Closed { received, reason: get.text("the reason", MAX_REASON)? }
            }
            other => return Err(Unreadable(format!("a session of kind {other}"))),
        };
        get.end("the session")?;
        Ok(LayerState { id, secret, left, kept })
    }
}

fn put_link(put: &mut Put, link: &LinkParts) {
    put.u64(link.received);
    put.u64(link.sent);
    put.u64(link.acknowledged);
    match &link.replay {
        Some(replay) => {
            put.bool(true);
            put.u64(replay.start);
            put.u64(replay.capacity as u64);
            put.bytes(&replay.bytes);
        }
        None => put.bool(false),
    }
    put.bool(link.acks);
    put.u64(link.acked);
    put.u64(link.held);
    for flag in [link.heartbeat, link.moves, link.once, link.ends, link.end_sent, link.app_failed, link.peer_ended] {
        put.bool(flag);
    }
}

fn get_link(get: &mut Get<'_>) -> Result<LinkParts, Unreadable> {
    let (received, sent, acknowledged) = (get.u64("received")?, get.u64("sent")?, get.u64("acknowledged")?);
    let replay = match get.bool("the replay buffer")? {
        true => {
            let start = get.u64("the buffer's start")?;
            let capacity = get.u64("the buffer's capacity")?;
            let capacity = usize::try_from(capacity)
                .ok()
                .filter(|c| *c <= MAX_CAPACITY)
                .ok_or_else(|| Unreadable(format!("a replay buffer of {capacity} bytes")))?;
            Some(ReplayParts { start, capacity, bytes: get.bytes("the buffer", capacity)?.to_vec() })
        }
        false => None,
    };
    let (acks, acked, held) = (get.bool("acks")?, get.u64("acked")?, get.u64("held")?);
    let mut flags = [false; 7];
    for flag in &mut flags {
        *flag = get.bool("a feature of the link")?;
    }
    let [heartbeat, moves, once, ends, end_sent, app_failed, peer_ended] = flags;
    Ok(LinkParts {
        received,
        sent,
        acknowledged,
        replay,
        acks,
        acked,
        held,
        heartbeat,
        moves,
        once,
        ends,
        end_sent,
        app_failed,
        peer_ended,
    })
}

#[cfg(test)]
mod tests;
