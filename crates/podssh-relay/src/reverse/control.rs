//! The control channel of the node: JSON text frames, under the 4 KiB cap.
//! The node receives `hello`, `open {id}` and `close {id}`, and sends
//! `ready {id}`, `reject {id, reason}` or `close {id}`. The operator receives
//! `ready`, `reject` and `close` as text, and never sends a text frame: the
//! relay closes it with `1003` (`docs/reverse.md`). `hello` may never come, so
//! the limits have a floor of their own.

use serde::{Deserialize, Serialize};

use super::framing::{
    CodecError, SessionId, CLOSE_REASON_MAX_BYTES, CLOSE_REASON_MAX_CHARS, CONTROL_FRAME_MAX, NODE_PAYLOAD_MAX,
};

/// The control cap, for a caller to check against what makes the frame.
pub const CONTROL_MAX: usize = CONTROL_FRAME_MAX;

/// What the node reads. An unknown field is kept, not refused: the relay
/// closes for an unknown `type` only, and a field that a new relay adds must
/// not close the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NodeInbound {
    #[serde(rename = "hello")]
    Hello(Hello),
    #[serde(rename = "open")]
    Open { id: String },
    #[serde(rename = "close")]
    Close {
        id: String,
        #[serde(default)]
        reason: Option<String>,
    },
    /// Any other type, read rather than dropped: a message that vanished would
    /// look like a relay that stopped talking.
    #[serde(other)]
    Unknown,
}

/// What the node sends, and what the operator reads: three types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NodeOutbound {
    #[serde(rename = "ready")]
    Ready { id: String },
    #[serde(rename = "reject")]
    Reject { id: String, reason: String },
    #[serde(rename = "close")]
    Close {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// The limits of `hello`, when one comes. Measured on 2026-10-09:
/// `{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}`; no
/// published document gives these fields, so each is optional. The relay's
/// own client reads `maxFrameBytes` as the payload of a node frame, and a
/// larger value is clamped to the published cap.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    // The relay's spelling: a renamed field would parse into nothing.
    #[serde(rename = "maxSessions", default, skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<u32>,
    #[serde(rename = "maxFrameBytes", default, skip_serializing_if = "Option::is_none")]
    pub max_frame_bytes: Option<u64>,
    /// Each field that podssh does not model, kept: a client that fails on an
    /// added field breaks on a new version.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The working limits of a node; never a compiled value of the relay's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeLimits {
    pub max_sessions: u32,
    pub max_frame_bytes: u64,
}

impl NodeLimits {
    /// The floor before a `hello`, or with none: the published payload cap,
    /// and 16 sessions, a small number that cannot exhaust a relay.
    pub const fn conservative() -> Self {
        Self { max_sessions: 16, max_frame_bytes: 65536 }
    }

    /// Take what `hello` says, clamped: the published cap is the contract, and
    /// `hello` a hint. A zero is ignored, not read as "send nothing".
    pub fn apply(&mut self, hello: &Hello) {
        if let Some(sessions) = hello.max_sessions {
            if sessions > 0 {
                self.max_sessions = sessions;
            }
        }
        if let Some(frame) = hello.max_frame_bytes {
            if frame > 0 {
                self.max_frame_bytes = frame.min(NODE_PAYLOAD_MAX as u64);
            }
        }
    }
}

impl Default for NodeLimits {
    fn default() -> Self {
        Self::conservative()
    }
}

/// A `ready`. Only after the local side has accepted: a `ready` sent early
/// passes the relay's gate of 15 s and hands the operator a dead session,
/// which shows as an SSH handshake that dies after the banner.
pub fn ready(id: &SessionId) -> Result<Vec<u8>, ControlError> {
    encode(&NodeOutbound::Ready { id: id.as_str().to_string() })
}

/// A `reject`, with the node's whole reason. The relay cuts the reason of its
/// own Close, but the `reject` text frame keeps the full reason, and that is
/// what the operator reads; so the reason is cut only to fit the control cap.
pub fn reject(id: &SessionId, reason: &str) -> Result<Vec<u8>, ControlError> {
    fitted(|reason| NodeOutbound::Reject { id: id.as_str().to_string(), reason }, reason)
}

/// A `close` of one session. Never a Close of the WebSocket: the socket
/// carries each other session too.
pub fn close(id: &SessionId, reason: Option<&str>) -> Result<Vec<u8>, ControlError> {
    match reason {
        None => encode(&NodeOutbound::Close { id: id.as_str().to_string(), reason: None }),
        Some(reason) => fitted(|reason| NodeOutbound::Close { id: id.as_str().to_string(), reason: Some(reason) }, reason),
    }
}

/// The frame of `make(reason)`, with the reason halved, on a character
/// boundary, until the frame fits the control cap. Only a reason of kilobytes
/// is cut; the relay itself cuts the reason of its Close.
fn fitted(make: impl Fn(String) -> NodeOutbound, reason: &str) -> Result<Vec<u8>, ControlError> {
    let mut reason = reason.to_string();
    loop {
        match encode(&make(reason.clone())) {
            Err(ControlError::Codec(CodecError::ControlFrameTooLong { .. })) if !reason.is_empty() => {
                let mut end = reason.len() / 2;
                while !reason.is_char_boundary(end) {
                    end -= 1;
                }
                reason.truncate(end);
            }
            built => return built,
        }
    }
}

/// The JSON of a frame, checked against the 4 KiB control cap; a bound apart
/// from the cut of a Close's reason.
pub fn encode(frame: &NodeOutbound) -> Result<Vec<u8>, ControlError> {
    let bytes = serde_json::to_vec(frame).map_err(|e| ControlError::Serialise(e.to_string()))?;
    if bytes.len() > CONTROL_FRAME_MAX {
        return Err(ControlError::Codec(CodecError::ControlFrameTooLong { got: bytes.len(), max: CONTROL_FRAME_MAX }));
    }
    Ok(bytes)
}

/// A control frame that the node received.
pub fn parse_inbound(text: &[u8]) -> Result<NodeInbound, ControlError> {
    serde_json::from_slice(text).map_err(|e| ControlError::Malformed { detail: e.to_string() })
}

/// A control frame that the operator received: `ready`, `reject` or `close`.
/// The operator holds one session, so it has nothing to open.
pub fn parse_operator_control(text: &[u8]) -> Result<NodeOutbound, ControlError> {
    serde_json::from_slice(text).map_err(|e| ControlError::Malformed { detail: e.to_string() })
}

/// A reason cut as the relay cuts its own: 100 characters and 123 bytes, and
/// a character that would cross the byte bound is left out whole. For
/// display; `reject` and `close` send the whole reason.
pub fn truncate_reason(reason: &str) -> String {
    if reason.chars().count() <= CLOSE_REASON_MAX_CHARS && reason.len() <= CLOSE_REASON_MAX_BYTES {
        return reason.to_string();
    }
    let mut out = String::new();
    for ch in reason.chars().take(CLOSE_REASON_MAX_CHARS) {
        if out.len() + ch.len_utf8() > CLOSE_REASON_MAX_BYTES {
            break;
        }
        out.push(ch);
    }
    out
}

#[derive(Debug)]
pub enum ControlError {
    Codec(CodecError),
    Serialise(String),
    Malformed { detail: String },
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::Codec(e) => write!(f, "{e}"),
            ControlError::Serialise(d) => write!(f, "control frame would not serialise: {d}"),
            ControlError::Malformed { detail } => write!(f, "control frame is not JSON podssh understands: {detail}"),
        }
    }
}

impl std::error::Error for ControlError {}

impl From<CodecError> for ControlError {
    fn from(e: CodecError) -> Self {
        ControlError::Codec(e)
    }
}
