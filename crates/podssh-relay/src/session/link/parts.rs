//! A link's state as plain values (T-668): what a far end hands to the
//! binary that takes its place, and takes back there, field by field. An
//! error that ended the last link is not one of them: a resume starts the
//! next link with none.

use super::Link;
use crate::session::offset::{Inbound, Outbound};
use crate::session::replay::Replay;

/// The replay buffer of a link: its first offset, its capacity and the bytes
/// that it keeps.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayParts {
    pub start: u64,
    pub capacity: usize,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for ReplayParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReplayParts {{ start: {}, capacity: {}, {} bytes }}", self.start, self.capacity, self.bytes.len())
    }
}

/// Each field of a [`Link`] that a handover carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkParts {
    pub received: u64,
    pub sent: u64,
    pub acknowledged: u64,
    pub replay: Option<ReplayParts>,
    pub acks: bool,
    pub acked: u64,
    pub held: u64,
    pub heartbeat: bool,
    pub moves: bool,
    pub once: bool,
    pub ends: bool,
    pub end_sent: bool,
    pub app_failed: bool,
    pub peer_ended: bool,
}

impl Link {
    /// The link's state, as values.
    pub fn parts(&self) -> LinkParts {
        LinkParts {
            received: self.inbound.received(),
            sent: self.outbound.sent(),
            acknowledged: self.outbound.acknowledged(),
            replay: self.replay.as_ref().map(|replay| ReplayParts {
                start: replay.start(),
                capacity: replay.capacity(),
                bytes: replay.contents(),
            }),
            acks: self.acks,
            acked: self.acked,
            held: self.held,
            heartbeat: self.heartbeat,
            moves: self.moves,
            once: self.once,
            ends: self.ends,
            end_sent: self.end_sent,
            app_failed: self.app_failed,
            peer_ended: self.peer_ended,
        }
    }

    /// A link from its values, once they hold together: a replay buffer
    /// that ends at the sent offset, within its capacity, and offsets that
    /// no acknowledgement passes. A state that does not would resume with a
    /// gap, so it is refused, with why.
    pub fn from_parts(parts: LinkParts) -> Result<Link, String> {
        let LinkParts {
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
        } = parts;
        if acknowledged > sent {
            return Err(format!("the peer acknowledged {acknowledged} of {sent} bytes sent"));
        }
        if acked > received || held > received {
            return Err(format!("{acked} bytes acknowledged and {held} held of {received} received"));
        }
        let replay = match replay {
            None => None,
            Some(ReplayParts { start, capacity, bytes }) => {
                let end = start.checked_add(bytes.len() as u64);
                if end != Some(sent) || bytes.len() > capacity {
                    return Err(format!(
                        "a replay buffer of {} bytes from {start} (capacity {capacity}) for {sent} bytes sent",
                        bytes.len()
                    ));
                }
                Some(Replay::restored(start, capacity, bytes))
            }
        };
        Ok(Link {
            inbound: Inbound::new(received),
            outbound: Outbound::restored(sent, acknowledged),
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
            failed: None,
        })
    }
}
