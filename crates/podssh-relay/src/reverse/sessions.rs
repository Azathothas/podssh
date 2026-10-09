//! The state of each session of a node socket, and the frames that it
//! forbids. The relay answers a frame that it does not expect by closing the
//! whole node socket, which ends each session on it: data before `ready` is
//! `1003 data before ready`, and data or a `ready` for an id that was never
//! opened, or was closed, is `1003 unknown session id` (`docs/reverse.md`,
//! "Node"). So the writer of the node refuses those frames before the wire.

use std::collections::BTreeMap;

use super::framing::SessionId;

/// Where one session is. A closed session is forgotten: the relay answers a
/// stale id and an invented one alike, and a node that runs for days must not
/// keep each id that it saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The relay sent `open {id}`; the node has not sent `ready` yet.
    Opened,
    /// The node sent `ready {id}`: data may flow.
    Readied,
}

/// A frame refused before the wire, named by the close that the relay would
/// answer it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub code: u16,
    pub reason: &'static str,
}

pub const DATA_BEFORE_READY: Refusal = Refusal { code: 1003, reason: "data before ready" };
pub const UNKNOWN_SESSION_ID: Refusal = Refusal { code: 1003, reason: "unknown session id" };

/// The sessions of a node socket, by id.
#[derive(Debug, Default)]
pub struct Sessions {
    by_id: BTreeMap<SessionId, SessionState>,
}

impl Sessions {
    pub const fn new() -> Self {
        Self { by_id: BTreeMap::new() }
    }

    /// The state of a session; `None` when it was never opened or is closed.
    pub fn state(&self, id: &SessionId) -> Option<SessionState> {
        self.by_id.get(id).copied()
    }

    /// The live sessions, in the order of their ids.
    pub fn live(&self) -> impl Iterator<Item = (&SessionId, SessionState)> {
        self.by_id.iter().map(|(id, state)| (id, *state))
    }

    /// Whether data for `id` may go out now.
    pub fn may_send_data(&self, id: &SessionId) -> Result<(), Refusal> {
        match self.state(id) {
            Some(SessionState::Readied) => Ok(()),
            Some(SessionState::Opened) => Err(DATA_BEFORE_READY),
            None => Err(UNKNOWN_SESSION_ID),
        }
    }

    /// Whether `ready {id}` may go out now: only for a session that is open.
    pub fn may_send_ready(&self, id: &SessionId) -> Result<(), Refusal> {
        match self.state(id) {
            Some(_) => Ok(()),
            None => Err(UNKNOWN_SESSION_ID),
        }
    }

    /// The relay sent `open {id}`.
    pub fn opened(&mut self, id: SessionId) {
        self.by_id.insert(id, SessionState::Opened);
    }

    /// The node's `ready {id}` went out.
    pub fn readied(&mut self, id: SessionId) {
        self.by_id.insert(id, SessionState::Readied);
    }

    /// The relay sent `close {id}`, or the node's `close` or `reject` went out.
    pub fn closed(&mut self, id: &SessionId) {
        self.by_id.remove(id);
    }
}
