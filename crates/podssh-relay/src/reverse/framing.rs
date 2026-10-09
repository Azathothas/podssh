//! The framing of the reverse legs, with no I/O: the session id, the caps of
//! each leg, and the faults of a frame. The node leg puts the 32-character id
//! before each payload; the operator leg has no framing at all; text frames
//! are control on the node leg only. Each cap is the relay contract's own
//! number (`docs/relay.md`, "The reverse path").

/// The length of a session id: 32 lowercase hex characters, as the relay's
/// own client checks them (`/^[0-9a-f]{32}$/`).
pub const SESSION_ID_LEN: usize = 32;

/// The largest node frame on the wire: the id and 65536 bytes of payload.
pub const NODE_FRAME_MAX_WIRE: usize = 65568;

/// The largest payload of a node frame.
pub const NODE_PAYLOAD_MAX: usize = 65536;

/// The largest payload of an operator frame. Equal to the node's, but a cap
/// of another leg for another reason: two names keep the legs apart.
pub const OPERATOR_PAYLOAD_MAX: usize = 65536;

/// The largest control frame of the node. Not the reason cap of a Close.
pub const CONTROL_FRAME_MAX: usize = 4096;

/// The relay cuts the reason of its own Close to 100 characters and 123
/// bytes, without splitting a character.
pub const CLOSE_REASON_MAX_CHARS: usize = 100;
pub const CLOSE_REASON_MAX_BYTES: usize = 123;

/// A checked session id. A frame's prefix is written from this type only, so
/// no prefix is made of unchecked bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    /// The one constructor: 32 lowercase hex characters. An upper-case id is
    /// refused too, as the relay closes it with `1003 invalid session id`.
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
        // `parse` checked each byte to be ASCII hex.
        std::str::from_utf8(&self.0).expect("a session id is 32 checked ASCII bytes")
    }
}

impl std::fmt::Debug for SessionId {
    /// Redacted: an id is no credential, but it is the live address of a
    /// session, and `Debug` is what a panic prints.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionId(..)")
    }
}

/// How a frame can be wrong; a closed set, so a caller matches on it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CodecError {
    /// A node frame under 32 bytes: `1009 bad multiplex frame`.
    FrameTooShort { got: usize },
    /// A node frame over 65568 bytes: `1009 bad multiplex frame`.
    FrameTooLong { got: usize, max: usize },
    /// An id that is not 32 characters: `1003 invalid session id`.
    SessionIdLength { got: usize },
    /// A prefix that is not lowercase hex: `1003 bad multiplex id`.
    SessionIdNotLowercaseHex { index: usize, byte: u8 },
    /// An operator payload over 65536 bytes: `1009 frame byte cap`.
    OperatorPayloadTooLong { got: usize, max: usize },
    /// A node control frame over 4 KiB: `1009 control frame byte cap`.
    ControlFrameTooLong { got: usize, max: usize },
    /// A text frame carries UTF-8 only (RFC 6455, section 8.1). Refused
    /// before the wire, so the relay never answers it.
    ControlNotUtf8 { valid_up_to: usize },
}

impl CodecError {
    /// The close that the relay answers this with; `None` for a frame that
    /// never leaves this side, which no close of the relay can name.
    pub fn relay_close_code(&self) -> Option<u16> {
        match self {
            CodecError::FrameTooShort { .. } | CodecError::FrameTooLong { .. } => Some(1009),
            CodecError::SessionIdNotLowercaseHex { .. } => Some(1003),
            CodecError::SessionIdLength { .. } => Some(1003),
            CodecError::OperatorPayloadTooLong { .. } => Some(1009),
            CodecError::ControlFrameTooLong { .. } => Some(1009),
            CodecError::ControlNotUtf8 { .. } => None,
        }
    }

    /// The row of the contract's close table, for a message a user can act on.
    pub fn spec_row(&self) -> &'static str {
        match self {
            CodecError::FrameTooShort { .. } | CodecError::FrameTooLong { .. } => {
                "spec line 182 | 1009 | bad multiplex frame | node"
            }
            CodecError::SessionIdNotLowercaseHex { .. } => "spec line 176 | 1003 | bad multiplex id | node",
            CodecError::SessionIdLength { .. } => "spec line 174 | 1003 | invalid session id | node",
            CodecError::OperatorPayloadTooLong { .. } => "spec line 184 | 1009 | frame byte cap | operator",
            CodecError::ControlFrameTooLong { .. } => "spec line 181 | 1009 | control frame byte cap | node",
            CodecError::ControlNotUtf8 { .. } => {
                "RFC 6455 section 8.1 | none: refused before the wire | text is UTF-8 | node"
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
            CodecError::FrameTooLong { got, max } => {
                write!(f, "node frame is {got} bytes on the wire, over the {max} maximum (spec line 184)")
            }
            CodecError::SessionIdLength { got } => {
                write!(f, "session id is {got} bytes, not {SESSION_ID_LEN} (spec line 174)")
            }
            CodecError::SessionIdNotLowercaseHex { index, byte } => {
                write!(f, "session id byte {index} is 0x{byte:02x}, not lowercase hex (spec line 176)")
            }
            CodecError::OperatorPayloadTooLong { got, max } => {
                write!(f, "operator payload is {got} bytes, over the {max} cap (spec line 184)")
            }
            CodecError::ControlFrameTooLong { got, max } => {
                write!(f, "node control frame is {got} bytes, over the {max} cap (spec line 181)")
            }
            CodecError::ControlNotUtf8 { valid_up_to } => write!(
                f,
                "node control frame is not UTF-8 after byte {valid_up_to}; a text frame \
                 carries UTF-8 only (RFC 6455 section 8.1)"
            ),
        }
    }
}

impl std::error::Error for CodecError {}

/// The codec of each leg; apart from the caps, so that the two equal payload
/// caps of two legs are read side by side.
pub mod legs;
