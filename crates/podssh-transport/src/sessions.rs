//! The state of each reverse session on a leg, and the frames that state
//! forbids.
//!
//! The relay answers a frame it does not expect by closing the whole node
//! socket, which ends every session on it: data before `ready` is
//! `1003 data before ready`, and data or a `ready` for an id that was never
//! opened, or was closed, is `1003 unknown session id` (spec lines 172 and
//! 177; `docs/reverse.md`, "Node", 2). The operator's data before `ready` is
//! `1008 wait for ready` (spec line 180). So a leg refuses those frames before
//! the wire, and the runner of the node reads the same state; it keeps no
//! second copy.

use std::collections::BTreeMap;

use crate::framing::SessionId;

/// Where one session is on the node leg. A closed session is forgotten: the
/// relay answers a stale id and an invented one the same way, and a node that
/// runs for days must not keep each id it ever saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The relay sent `open {id}`; the node has not sent `ready` yet.
    Opened,
    /// The node sent `ready {id}`: data may flow.
    Readied,
}

/// Where the one session of an operator leg is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorState {
    /// Connected; the node has not readied the session yet.
    Waiting,
    /// The relay forwarded the node's `ready`: data may flow.
    Readied,
    /// The relay forwarded a `reject` or a `close`: the session is over.
    Closed,
}

/// A frame refused before the wire, named by the close that the relay would
/// answer it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub code: u16,
    pub reason: &'static str,
}

/// Spec line 177.
pub const DATA_BEFORE_READY: Refusal = Refusal { code: 1003, reason: "data before ready" };
/// Spec line 172: "Node frame named a stale or invented id".
pub const UNKNOWN_SESSION_ID: Refusal = Refusal { code: 1003, reason: "unknown session id" };
/// Spec line 173.
pub const INVALID_CONTROL_JSON: Refusal = Refusal { code: 1003, reason: "invalid control JSON" };
/// Spec line 174.
pub const INVALID_SESSION_ID: Refusal = Refusal { code: 1003, reason: "invalid session id" };
/// Spec line 175.
pub const UNKNOWN_CONTROL_TYPE: Refusal = Refusal { code: 1003, reason: "unknown control type" };
/// Spec line 180.
pub const WAIT_FOR_READY: Refusal = Refusal { code: 1008, reason: "wait for ready" };
/// Spec line 182: a node frame with no id is under 32 bytes, or its payload
/// is read as an id.
pub const BAD_MULTIPLEX_FRAME: Refusal = Refusal { code: 1009, reason: "bad multiplex frame" };
/// Spec line 178: the operator leg is binary-only.
pub const BINARY_FRAMES_REQUIRED: Refusal = Refusal { code: 1003, reason: "binary frames required" };

/// A control frame that the node may send, with its session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    Ready(SessionId),
    Reject(SessionId),
    Close(SessionId),
}

/// Check a node's control frame as the relay checks it: JSON, then a type
/// the relay knows, then an id of 32 lowercase hex (spec lines 173-175).
pub fn check_outbound(frame: &[u8]) -> Result<Outbound, Refusal> {
    let value: serde_json::Value = serde_json::from_slice(frame).map_err(|_| INVALID_CONTROL_JSON)?;
    let kind: fn(SessionId) -> Outbound = match value.get("type").and_then(|t| t.as_str()) {
        Some("ready") => Outbound::Ready,
        Some("reject") => Outbound::Reject,
        Some("close") => Outbound::Close,
        _ => return Err(UNKNOWN_CONTROL_TYPE),
    };
    let id = value
        .get("id")
        .and_then(|id| id.as_str())
        .and_then(|id| SessionId::parse(id.as_bytes()).ok())
        .ok_or(INVALID_SESSION_ID)?;
    Ok(kind(id))
}

/// The sessions of a node leg, by id.
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
    pub(crate) fn opened(&mut self, id: SessionId) {
        self.by_id.insert(id, SessionState::Opened);
    }

    /// The node's `ready {id}` went out.
    pub(crate) fn readied(&mut self, id: SessionId) {
        self.by_id.insert(id, SessionState::Readied);
    }

    /// The relay sent `close {id}`, or the node's `close` or `reject` went out.
    pub(crate) fn closed(&mut self, id: &SessionId) {
        self.by_id.remove(id);
    }
}
