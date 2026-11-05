//! The control channel of the node: JSON text frames, under the 4 KiB cap.
//! The node receives `hello`, `open {id}` and `close {id}`, and sends
//! `ready {id}`, `reject {id, reason}` or `close {id}`; with podssh's relay
//! role, it sends `token` and receives `spent` too, beside the contract
//! (T-615, `crate::e2e::legs`). The operator receives
//! `ready`, `reject` and `close` as text, and never sends a text frame: the
//! relay closes it with `1003` (`docs/reverse.md`). `hello` may never come, so
//! the limits have a floor of their own. Its `version` is the relay's
//! dialect, and one that this node does not read ends the node with one
//! sentence, as a new socket would meet the same (T-643, [`accept`]).

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
    /// podssh's relay role took a token of one leg that this node registered
    /// for an operator's upgrade, by its digest (T-615); it comes before the
    /// session's `open`, and only to a node that registered one.
    #[serde(rename = "spent")]
    Spent { digest: String },
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
/// larger value is clamped to the published cap. `version` is the relay's
/// dialect ([`accept`], T-643).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    // Any JSON, so that a version of another type is said, not a `hello`
    // that fails to parse and is dropped with its limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<serde_json::Value>,
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
    /// `hello` a hint (`crate::answer::hint`). A zero is ignored, not read as
    /// "send nothing".
    pub fn apply(&mut self, hello: &Hello) {
        self.max_sessions = crate::answer::hint(hello.max_sessions, self.max_sessions);
        self.max_frame_bytes =
            crate::answer::hint(hello.max_frame_bytes, self.max_frame_bytes).min(NODE_PAYLOAD_MAX as u64);
    }
}

impl Default for NodeLimits {
    fn default() -> Self {
        Self::conservative()
    }
}

/// The dialect of the reverse road that this podssh speaks: the `version`
/// of the role's `hello`, and the `X-Podssh-Proto` that the dialer writes on
/// each node's and operator's upgrade (T-643).
pub const PROTO: i64 = podssh_ws::handshake::REVERSE_PROTO;
/// The oldest dialect that this podssh reads: [`PROTO`] until the dialect
/// changes, so that the check refuses nothing before that change.
pub const PROTO_MIN: i64 = 1;
/// The dialect of a peer that states none: the contract's, which the default
/// relay and each podssh of before speak. Never zero, which none speaks.
pub const UNSTATED: i64 = 1;
/// The header of an upgrade's dialect.
pub const PROTO_HEADER: &str = podssh_ws::handshake::PROTO_HEADER;

/// A peer's dialect that this end does not read: what the peer stated, as a
/// line shows it, and whether it is past this end's range (`Some(true)`),
/// short of it (`Some(false)`), or no number at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skew {
    pub stated: String,
    pub newer: Option<bool>,
}

impl Skew {
    /// One sentence for the user: the dialect that `peer` states, what
    /// `reader` reads, and which of the two to update. A new connection
    /// would meet the same, so no caller retries on it.
    pub fn sentence(&self, reader: &str, peer: &str) -> String {
        let range = match PROTO_MIN == PROTO {
            true => format!("dialect {PROTO} alone"),
            false => format!("dialects {PROTO_MIN} to {PROTO}"),
        };
        let update = match self.newer {
            Some(true) => reader.to_string(),
            Some(false) => peer.to_string(),
            None => format!("{reader} or {peer}"),
        };
        format!("{peer} speaks the reverse road's dialect {}, and {reader} reads {range}: update {update}", self.stated)
    }
}

/// Whether this end reads the dialect that `version` states, by the rule of
/// a dialect (`crate::answer::dialect`): none, or null, is [`UNSTATED`].
pub fn accept(version: Option<&serde_json::Value>) -> Result<i64, Skew> {
    match crate::answer::dialect(version, UNSTATED) {
        Ok(number) if (PROTO_MIN..=PROTO).contains(&number) => Ok(number),
        Ok(number) => Err(Skew { stated: number.to_string(), newer: Some(number > PROTO) }),
        Err(raw) => Err(Skew { stated: shown(&raw), newer: None }),
    }
}

/// [`accept`] of an upgrade's `X-Podssh-Proto`, at podssh's relay role: no
/// header is [`UNSTATED`], and a value that is no whole number no dialect.
pub fn accept_header(value: Option<&str>) -> Result<i64, Skew> {
    let stated = value.map(|text| match text.trim().parse::<i64>() {
        Ok(number) => serde_json::Value::from(number),
        Err(_) => serde_json::Value::String(text.to_string()),
    });
    accept(stated.as_ref())
}

/// A peer's value as a line says it: one line, 40 characters at most, as
/// it reaches a terminal and a refusal's reason.
fn shown(raw: &str) -> String {
    podssh_ws::text::one_line(raw).chars().take(40).collect()
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
        Some(reason) => {
            fitted(|reason| NodeOutbound::Close { id: id.as_str().to_string(), reason: Some(reason) }, reason)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hello(text: &str) -> Hello {
        match parse_inbound(text.as_bytes()) {
            Ok(NodeInbound::Hello(hello)) => hello,
            other => panic!("not a hello: {other:?}"),
        }
    }

    /// T-643: the relay of the contract states 1, and a relay of before may
    /// state nothing; both are read, as is an upgrade with no header.
    #[test]
    fn a_hello_with_no_version_is_the_oldest_dialect() {
        assert_eq!(accept(hello(r#"{"type":"hello","maxSessions":64}"#).version.as_ref()), Ok(UNSTATED));
        assert_eq!(accept(hello(r#"{"type":"hello","version":null}"#).version.as_ref()), Ok(UNSTATED));
        let measured = hello(r#"{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}"#);
        assert_eq!(accept(measured.version.as_ref()), Ok(PROTO));
        assert_eq!(accept_header(None), Ok(UNSTATED));
        assert_eq!(accept_header(Some(" 1 ")), Ok(PROTO));
    }

    /// T-643: a dialect that this node does not read is one sentence that
    /// names what the peer states, what this end reads, and whom to update.
    #[test]
    fn a_hello_of_a_dialect_this_node_cannot_read_names_both_sides() {
        let newer = accept(hello(r#"{"type":"hello","version":2}"#).version.as_ref()).unwrap_err();
        assert_eq!(newer, Skew { stated: "2".into(), newer: Some(true) });
        let words = newer.sentence("this node", "the relay");
        assert!(words.contains("dialect 2") && words.contains(&format!("dialect {PROTO}")), "{words}");
        assert!(words.ends_with(": update this node"), "{words}");
        // Zero is a dialect that no podssh speaks, never an absence.
        let older = accept(Some(&json!(0))).unwrap_err();
        assert!(older.sentence("this node", "the relay").ends_with(": update the relay"));
        // No number: quoted as the peer wrote it, and either side may be old.
        for odd in [json!("2"), json!(1.5), json!({"major": 2}), json!(true)] {
            let skew = accept(Some(&odd)).unwrap_err();
            assert_eq!(skew.newer, None, "{odd}");
            assert!(skew.sentence("this node", "the relay").ends_with(": update this node or the relay"), "{odd}");
        }
        // The role's reading of an upgrade's header.
        assert_eq!(accept_header(Some("2")).unwrap_err().newer, Some(true));
        let words = accept_header(Some("two")).unwrap_err().sentence("the relay", "the node");
        assert!(words.starts_with("the node speaks the reverse road's dialect \"two\""), "{words}");
    }

    /// A version of another type keeps the rest of the `hello`: its limits
    /// are taken, and the version is said, not dropped with the frame.
    #[test]
    fn a_hello_whose_version_is_no_number_keeps_its_limits() {
        let odd = hello(r#"{"type":"hello","version":"1.0","maxSessions":8,"maxFrameBytes":4096}"#);
        let mut limits = NodeLimits::conservative();
        limits.apply(&odd);
        assert_eq!(limits, NodeLimits { max_sessions: 8, max_frame_bytes: 4096 });
        assert!(accept(odd.version.as_ref()).is_err());
    }

    /// A peer's text reaches a terminal and a refusal's reason: one line,
    /// cut, with no control character.
    #[test]
    fn a_stated_value_is_shown_on_one_line_and_cut() {
        let long = format!("{}\u{1b}[31m\nsecond line", "x".repeat(200));
        let skew = accept_header(Some(&long)).unwrap_err();
        assert!(skew.stated.chars().count() <= 40, "{}", skew.stated);
        assert!(!skew.stated.chars().any(char::is_control), "{:?}", skew.stated);
    }
}
