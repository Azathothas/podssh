//! The node control channel: JSON **text** frames, and the cap they answer with.
//!
//! ⛔ **Control travels on the node leg only.** Spec line 105-106: the node
//! *receives* `hello`, `open {id}` and `close {id}`; spec lines 139-140: it
//! *replies* `ready {id}` or `reject {id,reason}`. The operator leg receives
//! `ready`/`reject`/`close` as text and ⛔ **never sends one** — spec lines
//! 144-145: *"the operator receives text control frames and sends binary data
//! frames only — an operator text frame closes the socket `1003`."*
//!
//! ⛔ **`hello` may never arrive.** Spec line 106 lists it among what the node
//! receives, while `dropssh` `src/relay.c:895` has the relay *emit* it, and
//! `reverse-node.md:115-124` records the contradiction. So `NodeLimits::apply`
//! takes whatever is told and `NodeLimits::default()` is the fallback, and
//! ⛔ **neither path hardcodes the numbers the sibling read off the wire.**

use serde::{Deserialize, Serialize};

use crate::framing::{
    CodecError, SessionId, CLOSE_REASON_MAX_BYTES, CLOSE_REASON_MAX_CHARS, NODE_PAYLOAD_MAX,
};
use crate::framing::CONTROL_FRAME_MAX;

/// ⛔ **The 4 KiB control cap, re-exported** so a caller checks the bound against
/// the thing that produces the frame rather than against a number it copied.
pub const CONTROL_MAX: usize = CONTROL_FRAME_MAX;

/// ⛔ **What the node reads.** `serde`'s default is to reject an unknown field
/// with `deny_unknown_fields`, and ⛔ **that is wrong here**: spec line 175 names
/// `1003 unknown control type` for an unknown `type`, not for an extra field, and
/// a node that refuses a message carrying a field a future relay added would turn
/// a harmless version bump into a closed socket. Extra fields are kept in
/// `extra` so nothing is silently dropped either.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NodeInbound {
    #[serde(rename = "hello")]
    Hello(Hello),
    #[serde(rename = "open")]
    Open { id: String },
    #[serde(rename = "close")]
    Close { id: String, #[serde(default)] reason: Option<String> },
    /// ⛔ Anything else. Spec line 175 answers it `1003 unknown control type`,
    /// so it is parsed rather than dropped — an unrecognised control message
    /// that vanished silently would look like a relay that stopped talking.
    #[serde(other)]
    Unknown,
}

/// ⛔ **What the node sends.** Exactly three types, per spec lines 139-140.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NodeOutbound {
    #[serde(rename = "ready")]
    Ready { id: String },
    #[serde(rename = "reject")]
    Reject { id: String, reason: String },
    #[serde(rename = "close")]
    Close { id: String, #[serde(default, skip_serializing_if = "Option::is_none")] reason: Option<String> },
}

/// ⛔ **`hello`'s limits, when one arrives.**
///
/// ⚠ **`maxSessions` and `maxFrameBytes` appear in no published document.**
/// `01-relay-protocol.md:399-403` records `maxSessions: 64` as read off the wire
/// and the sibling's own `hello` as
/// `{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}`
/// (`dropssh` `src/relay.c:894-895`, **READ**). ⛔ **They are `Option` here, and
/// `01-relay-protocol.md:399-403` says why**: read `hello`, never hard-code.
///
/// ⛔ **`maxFrameBytes` carries its own unit and it is `INFERRED` from the code
/// path, not `READ` from a document.** ⛔ **The sibling's `hello` says `65536`
/// and this crate's node cap is 65568 *on the wire*, id included** — so if the
/// field is a wire size the sibling was already wrong by 32, and if it is a
/// payload size it agrees with spec line 140's *"up to 64 KiB of bytes"*. In the
/// relay's own client `REVERSE_MAX_FRAME_BYTES = 64 * 1024` sits on the **payload**
/// side of `encodeNodeFrame`, so ⛔ **payload is the reading this crate takes and
/// it is flagged `UNKNOWN` rather than asserted**, because no published document
/// says which. ⛔ **What is not `UNKNOWN` is the clamp below**: whatever the field
/// means, a value above the published payload cap is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    // ⛔ **The relay's own spelling, kept verbatim.** Renaming a wire field to
    // Rust convention would work until the relay spelled it differently, and the
    // silent failure is a `hello` that parses into an empty struct.
    #[serde(rename = "maxSessions", default, skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<u32>,
    #[serde(rename = "maxFrameBytes", default, skip_serializing_if = "Option::is_none")]
    pub max_frame_bytes: Option<u64>,
    /// ⛔ Every field the relay sent that podssh does not model, kept rather than
    /// dropped. `01-relay-protocol.md:501-506` records that the relay deletes
    /// prose between versions, and a client that errors on an added field is a
    /// client that breaks on a rewording.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// ⛔ **The node's working limits. ⛔ Never a compiled constant.**
///
/// ⛔ **The defaults are conservative on purpose and are labelled as such.** They
/// are *not* measurements of the relay and they are *not* the sibling's numbers:
/// they are the smallest values that cannot violate anything the published
/// document states, so a node that never sees a `hello` cannot overrun a cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeLimits {
    pub max_sessions: u32,
    pub max_frame_bytes: u64,
}

impl NodeLimits {
    /// ⛔ **The conservative floor**, used when `hello` does not arrive or is
    /// silent. `max_frame_bytes` is **65536**, which is the *payload* a node
    /// frame may carry beside a full id (spec line 140) and therefore the wire
    /// size is 65568 and the published maximum exactly. `max_sessions` is **16**:
    /// ⚠ **not** the sibling's 64, which is in no published document; it is
    /// chosen here as a small number that cannot exhaust a relay.
    pub const fn conservative() -> Self {
        Self { max_sessions: 16, max_frame_bytes: 65536 }
    }

    /// ⛔ **Apply whatever the relay told, and clamp.** A `hello` claiming a frame
    /// cap larger than the published wire maximum is clamped down, because the
    /// relay's table is the contract and a `hello` is a hint read off the wire.
    /// A cap of zero is refused outright rather than accepted as "send nothing".
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
    /// ⛔ **Named, not inlined**, so a reader can see which of the two defaults
    /// they are getting.
    fn default() -> Self {
        Self::conservative()
    }
}

/// ⛔ **Build a `ready`, and refuse to build one that breaks a cap.**
///
/// ⛔ **`ready` gates a session, not the socket** (`reverse-node.md:171-173`),
/// and ⛔ **it must never be sent optimistically**: an optimistic `ready` passes
/// the relay's 15 s gate (spec line 190) and then hands the operator a dead
/// socket, which surfaces as an SSH handshake that dies after the banner rather
/// than as a `1013` the operator can read.
pub fn ready(id: &SessionId) -> Result<Vec<u8>, ControlError> {
    let frame = NodeOutbound::Ready { id: id.as_str().to_string() };
    encode(&frame)
}

/// ⛔ **Build a `reject`, whose reason is capped at **123 UTF-8 bytes**.
///
/// ⛔ **Spec line 157 caps the reason at 100 chars *and* 123 UTF-8 bytes,
/// without splitting a code point.** Truncating at a byte index that lands
/// mid-character produces invalid UTF-8, which is the one thing the relay's own
/// wording is careful about. `truncate_reason` therefore walks back to a
/// character boundary.
pub fn reject(id: &SessionId, reason: &str) -> Result<Vec<u8>, ControlError> {
    let frame = NodeOutbound::Reject {
        id: id.as_str().to_string(),
        reason: truncate_reason(reason),
    };
    encode(&frame)
}

/// ⛔ **Build a `close`.** ⛔ **Never closes the WebSocket** — the node's socket is
/// shared and a Close frame there kills every other session
/// (`reverse-node.md:155-156`).
pub fn close(id: &SessionId, reason: Option<&str>) -> Result<Vec<u8>, ControlError> {
    let frame = NodeOutbound::Close {
        id: id.as_str().to_string(),
        reason: reason.map(truncate_reason),
    };
    encode(&frame)
}

/// ⛔ **Serialise and check the 4 KiB control cap** — **READ**, spec line 181.
///
/// ⛔ **This is a different bound from the 123-byte reason cap**, and the two
/// being confused is a recorded correction (`reverse-node.md:53-57`).
pub fn encode(frame: &NodeOutbound) -> Result<Vec<u8>, ControlError> {
    let bytes = serde_json::to_vec(frame)
        .map_err(|e| ControlError::Serialise(e.to_string()))?;
    if bytes.len() > CONTROL_FRAME_MAX {
        return Err(ControlError::Codec(CodecError::ControlFrameTooLong {
            got: bytes.len(),
            max: CONTROL_FRAME_MAX,
        }));
    }
    Ok(bytes)
}

/// ⛔ **Parse a control frame the node was sent.**
pub fn parse_inbound(text: &[u8]) -> Result<NodeInbound, ControlError> {
    let parsed: NodeInbound = serde_json::from_slice(text)
        .map_err(|e| ControlError::Malformed { detail: e.to_string() })?;
    Ok(parsed)
}

/// ⛔ **Parse a control frame the operator was sent**, which is `ready`,
/// `reject` or `close` and never `open` or `hello` — ⛔ the operator is spliced
/// to one session, so it has no id to open.
pub fn parse_operator_control(text: &[u8]) -> Result<NodeOutbound, ControlError> {
    let parsed: NodeOutbound = serde_json::from_slice(text)
        .map_err(|e| ControlError::Malformed { detail: e.to_string() })?;
    Ok(parsed)
}

/// ⛔ **The reason cap, applied without splitting a code point.**
///
/// **READ**, spec line 192: *"limited to 100 chars and 123 UTF-8 bytes without
/// splitting a code point"*. Both bounds apply, so a 100-character string of
/// 4-byte characters is cut on the byte bound and a 200-character string of
/// ASCII is cut on the character bound.
pub fn truncate_reason(reason: &str) -> String {
    if reason.chars().count() <= CLOSE_REASON_MAX_CHARS && reason.len() <= CLOSE_REASON_MAX_BYTES {
        return reason.to_string();
    }
    let mut out = String::new();
    for ch in reason.chars().take(CLOSE_REASON_MAX_CHARS) {
        // ⛔ `len()` is bytes, so this is the byte bound, and a multi-byte
        // character that would cross it is dropped whole rather than split.
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
            ControlError::Malformed { detail } => {
                write!(f, "control frame is not JSON podssh understands: {detail}")
            }
        }
    }
}

impl std::error::Error for ControlError {}

impl From<CodecError> for ControlError {
    fn from(e: CodecError) -> Self {
        ControlError::Codec(e)
    }
}