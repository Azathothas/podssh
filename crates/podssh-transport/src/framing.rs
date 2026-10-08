//! The relay's framing rules, as one codec per leg, testable with no network.
//!
//! ⛔ **This is the layer E02 exists to get right, and it is separated from the
//! socket for exactly that reason.** Every function here is pure: bytes in,
//! frames out, and no transport, no clock and no socket. The relay accepts no
//! inbound TCP and the live legs cannot be exercised from a machine with no
//! minted token, so a codec that could only be exercised through a socket would
//! be a codec with no test.
//!
//! ⛔ **THE THREE LEGS ARE NOT VARIANTS OF ONE FRAMER. They are three shapes
//! with three different rules, and the two errors this repository names as its
//! highest-risk misreadings are both *merging* them by accident.**
//!
//! | | forward | reverse node | reverse operator |
//! | --- | --- | --- | --- |
//! | id prefix | ⛔ **none** | **32 lowercase hex** | ⛔ **none** |
//! | text frames | ⛔ closes `1003` | **is the control channel** | ⛔ closes `1003` |
//! | max wire frame | **262144** | **65568** | **65536** |
//!
//! The forward cap is **MEASURED** 2026-10-02 from `/relays.json`
//! `limits.max_frame_bytes`, this machine, Git Bash on Windows:
//! `curl -sSL 'https://tcp.ssh.relay.ajam.dev/relays.json?host=github.com&port=22'`
//! → `262144`. The other two are **READ** from spec lines 182 and 184.
//!
//! ⛔ **The forward cap is a runtime value, not a constant.** There is no `hello`
//! frame on the forward path, so nothing on the wire tells a client what the cap
//! is. `Limits::forward` therefore *requires* the operator to supply the number
//! the relay published, and `Limits::conservative` is named for what it is — a
//! floor used only before `/relays.json` has been read.

/// ⛔ **The 32-byte session id, and the regex that decides what one is.**
///
/// **READ**, spec line 140: *"Each node binary frame starts with the 32 ASCII hex
/// characters of the session id"*; spec lines 174 and 176 pin *lowercase*.
/// **MEASURED** 2026-10-02, this machine, from the relay's own client bundle
/// `https://tcp.ssh.relay.ajam.dev/client/relay.mjs` line 112:
/// `SESSION_ID_RE = /^[0-9a-f]{32}$/`, sha256 `bfbfff50…ff56ea` matching
/// `/client/index.json`. podssh emits lowercase and accepts nothing else.
pub const SESSION_ID_LEN: usize = 32;

/// **READ**, spec line 182: *"Node binary frame under 32 bytes or over 65568
/// (32-byte id plus 65536 payload)"*. The id is part of the frame, not a
/// separate frame — **READ**, `dropssh` `src/serve.c:387-391`.
pub const NODE_FRAME_MAX_WIRE: usize = 65568;

/// **READ**, spec line 140: *"followed by up to 64 KiB of bytes"*.
pub const NODE_PAYLOAD_MAX: usize = 65536;

/// **READ**, spec line 184: *"One operator frame exceeded 65536 payload bytes"*.
///
/// ⛔ **A different limit from `NODE_PAYLOAD_MAX`, and equal to it.** The two are
/// the same number for different reasons, and this crate keeps them as two
/// constants for that reason: a merge of the two legs is the defect this module
/// exists to prevent, and two names for one number is the seam where the merge
/// would happen.
pub const OPERATOR_PAYLOAD_MAX: usize = 65536;

/// **READ**, spec line 181: *"Node JSON control exceeded 4 KiB"*.
///
/// ⛔ **Not the 123-byte close-reason cap at spec line 192.** Two different
/// bounds, and `reverse-node.md:53-57` records the conflation as a correction.
pub const CONTROL_FRAME_MAX: usize = 4096;

/// **READ**, spec line 192: close reasons are *"limited to 100 chars and 123
/// UTF-8 bytes without splitting a code point"*.
pub const CLOSE_REASON_MAX_CHARS: usize = 100;
pub const CLOSE_REASON_MAX_BYTES: usize = 123;

/// ⛔ **A validated session id.** A bare `String` has no field that could stop a
/// caller writing `"0".repeat(32)`, so the prefix can only be written from a value
/// that has already been through `SessionId::parse` or `SessionId::mint`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    /// ⛔ **The only constructor from bytes.** Refuses anything that is not 32
    /// lowercase hex — uppercase is rejected too, because spec lines 174 and
    /// 176 pin the case and a client that emits `A` gets `1003 invalid
    /// session id`.
    pub fn parse(raw: &[u8]) -> Result<Self, CodecError> {
        if raw.len() != SESSION_ID_LEN {
            return Err(CodecError::SessionIdLength { got: raw.len() });
        }
        for (index, byte) in raw.iter().enumerate() {
            if !matches!(byte, b'0'..=b'9' | b'a'..=b'f') {
                return Err(CodecError::SessionIdNotLowercaseHex { index, byte: *byte });
            }
        }
        let mut bytes = [0u8; SESSION_ID_LEN];
        bytes.copy_from_slice(raw);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        // ⛔ Every byte was checked to be ASCII hex in `parse`.
        std::str::from_utf8(&self.0).expect("a session id is 32 checked ASCII bytes")
    }
}

impl std::fmt::Debug for SessionId {
    /// ⛔ **Redacted by default.** A session id is not a credential, but a full
    /// `Debug` in a log line is 32 bytes of a live multiplex address nobody asked
    /// to print, and `Debug` is what `unwrap()` prints.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionId(..)")
    }
}

/// ⛔ **The four ways a frame can be wrong**, kept as a closed set so a caller
/// can match on it instead of parsing an error string.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CodecError {
    /// Spec line 182: a node binary frame under 32 bytes. `1009 bad multiplex frame`.
    FrameTooShort { got: usize },
    /// Spec line 182: over 65568 on the wire. `1009 bad multiplex frame`.
    FrameTooLong { got: usize, max: usize },
    /// Spec line 174: control `id` is not 32 lowercase hex. `1003 invalid session id`.
    SessionIdLength { got: usize },
    /// Spec line 176: the 32-byte binary prefix is not hex. `1003 bad multiplex id`.
    SessionIdNotLowercaseHex { index: usize, byte: u8 },
    /// Spec line 184: an operator frame over 65536 payload bytes. `1009 frame byte cap`.
    OperatorPayloadTooLong { got: usize, max: usize },
    /// Spec line 181: node JSON control over 4 KiB. `1009 control frame byte cap`.
    ControlFrameTooLong { got: usize, max: usize },
}

impl CodecError {
    /// ⛔ **The close code the relay answers this with**, so a caller can branch
    /// on the protocol and not on a string.
    ///
    /// Every mapping is **READ** from the row named beside it in the close table,
    /// spec lines 170-193. The two that are *not* in the table are named: a frame this
    /// client built itself and got wrong cannot be answered by the relay at all,
    /// because it never left, and saying `1009` for it would be inventing a
    /// close code — the one thing `AGENTS.md` forbids above every other.
    pub fn relay_close_code(&self) -> Option<u16> {
        match self {
            CodecError::FrameTooShort { .. } | CodecError::FrameTooLong { .. } => Some(1009),
            CodecError::SessionIdNotLowercaseHex { .. } => Some(1003),
            CodecError::SessionIdLength { .. } => Some(1003),
            CodecError::OperatorPayloadTooLong { .. } => Some(1009),
            CodecError::ControlFrameTooLong { .. } => Some(1009),
        }
    }

    /// ⛔ **The spec row this maps to**, for a message a user can act on.
    pub fn spec_row(&self) -> &'static str {
        match self {
            CodecError::FrameTooShort { .. } | CodecError::FrameTooLong { .. } => {
                "spec line 182 | 1009 | bad multiplex frame | node"
            }
            CodecError::SessionIdNotLowercaseHex { .. } => {
                "spec line 176 | 1003 | bad multiplex id | node"
            }
            CodecError::SessionIdLength { .. } => "spec line 174 | 1003 | invalid session id | node",
            CodecError::OperatorPayloadTooLong { .. } => {
                "spec line 184 | 1009 | frame byte cap | operator"
            }
            CodecError::ControlFrameTooLong { .. } => {
                "spec line 181 | 1009 | control frame byte cap | node"
            }
        }
    }
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::FrameTooShort { got } => write!(
                f,
                "node frame is {got} bytes, under the 32-byte id the relay strips; \
                 the id and the payload must be ONE frame (spec line 182)"
            ),
            CodecError::FrameTooLong { got, max } => write!(
                f,
                "node frame is {got} bytes on the wire, over the {max} maximum \
                 (spec line 184)"
            ),
            CodecError::SessionIdLength { got } => write!(
                f,
                "session id is {got} bytes, not {SESSION_ID_LEN} (spec line 174)"
            ),
            CodecError::SessionIdNotLowercaseHex { index, byte } => write!(
                f,
                "session id byte {index} is 0x{byte:02x}, not lowercase hex \
                 (spec line 176)"
            ),
            CodecError::OperatorPayloadTooLong { got, max } => write!(
                f,
                "operator payload is {got} bytes, over the {max} cap \
                 (spec line 184)"
            ),
            CodecError::ControlFrameTooLong { got, max } => write!(
                f,
                "node control frame is {got} bytes, over the {max} cap (spec line 181)"
            ),
        }
    }
}

impl std::error::Error for CodecError {}

/// ⛔ **The three leg codecs, in their own module.** ⛔ They are split out rather
/// than written here because a module that holds the caps *and* the encoders is
/// a module where a reader comparing `NODE_PAYLOAD_MAX` against
/// `OPERATOR_PAYLOAD_MAX` has the two numbers on one screen — ⛔ and comparing
/// them is the point, because they are equal for different reasons.
pub mod legs;