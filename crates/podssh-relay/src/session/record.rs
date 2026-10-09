//! The records of the layer, and how they go on the wire.
//!
//! A record is a type byte, a 32-bit length and a body of at most
//! [`MAX_BODY`] bytes. Numbers are big-endian; offsets and values have 64
//! bits. The table, also in `docs/design.md` (section 5):
//!
//! | Type | Record   | Sent by | Body |
//! | ---- | -------- | ------- | ---- |
//! | 0x01 | GREETING | far end | magic, version, role, nonce, features |
//! | 0x02 | OPEN     | client  | magic, version, role, nonce, then 0x00 and a public key (new) or 0x01 and a session id (resume), then features |
//! | 0x03 | ACCEPT   | far end | 0x00, a session id and a public key (new); or 0x01, an offset and a proof (resume) |
//! | 0x04 | PROOF    | client  | an offset and a proof |
//! | 0x05 | REFUSE   | either  | a code byte and a reason |
//! | 0x06 | DATA     | either  | the offset of its first byte, then the bytes |
//! | 0x07 | ACK      | either  | an offset |
//! | 0x08 | PING     | either  | a value |
//! | 0x09 | PONG     | either  | the value of the PING, then an offset |
//! | 0x0a | CLOSE    | either  | a reason |
//!
//! The magic is the 14 bytes `podssh-session`. A nonce, a public key and a
//! proof have 32 bytes, a session id 16. Features are a count byte (16 at
//! most), then each name as a length byte and the name: 1 to 32 bytes of
//! `a-z`, `0-9`, `.`, `-` and `_`. A reason is UTF-8, 1024 bytes at most.
//! No type byte is a printable character, and an SSH server's first line is
//! text, so a client tells a far end with the layer from one with none by
//! the first byte.

use std::fmt;

use super::secret::{Nonce, Proof, SessionId, KEY_LEN};

/// The type byte and the length.
pub const HEADER: usize = 5;
/// The largest body.
pub const MAX_BODY: usize = 64 * 1024;
/// The most bytes that one `DATA` record carries.
pub const MAX_DATA: usize = MAX_BODY - 8;
/// The first bytes of a `GREETING` and an `OPEN` body.
pub const MAGIC: &[u8; 14] = b"podssh-session";
/// The highest version of the layer that this side speaks.
pub const VERSION: u8 = 1;
/// The longest reason of a `REFUSE` or a `CLOSE`, in bytes.
pub const MAX_REASON: usize = 1024;
/// The most feature names in a `GREETING` or an `OPEN`.
pub const MAX_FEATURES: usize = 16;
/// The longest feature name.
pub const MAX_FEATURE_NAME: usize = 32;

/// The type bytes.
pub mod kind {
    pub const GREETING: u8 = 0x01;
    pub const OPEN: u8 = 0x02;
    pub const ACCEPT: u8 = 0x03;
    pub const PROOF: u8 = 0x04;
    pub const REFUSE: u8 = 0x05;
    pub const DATA: u8 = 0x06;
    pub const ACK: u8 = 0x07;
    pub const PING: u8 = 0x08;
    pub const PONG: u8 = 0x09;
    pub const CLOSE: u8 = 0x0a;
}

/// What a side is. A byte, so that a role of a later version still decodes
/// and the handshake decides.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Role(pub u8);

impl Role {
    /// `podssh ssh`, `podssh cp` and the other commands that reach a far end.
    pub const CLIENT: Role = Role(1);
    /// `podssh node`.
    pub const NODE: Role = Role(2);
    /// `podssh serve`.
    pub const SERVE: Role = Role(3);

    /// Whether a far end can have this role: any but the client's, so that
    /// a far end of a later role still speaks to this client.
    pub fn is_far(self) -> bool {
        self.0 != 0 && self != Role::CLIENT
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Role::CLIENT => f.write_str("a podssh client"),
            Role::NODE => f.write_str("a podssh node"),
            Role::SERVE => f.write_str("podssh serve"),
            Role(other) => write!(f, "a podssh of role {other}"),
        }
    }
}

impl fmt::Debug for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Role({})", self.0)
    }
}

/// Why a side refused. A byte, so that a code of a later version still
/// decodes; its reason says the rest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefuseCode(pub u8);

impl RefuseCode {
    pub const OTHER: RefuseCode = RefuseCode(0);
    /// `OPEN` names a session that the far end does not keep.
    pub const UNKNOWN_SESSION: RefuseCode = RefuseCode(1);
    /// A proof that the secret, the nonces or the offset do not give.
    pub const BAD_PROOF: RefuseCode = RefuseCode(2);
    /// A resume from an offset that the sender no longer keeps (T-152).
    pub const NOT_KEPT: RefuseCode = RefuseCode(3);
    /// A version that the far end does not speak.
    pub const VERSION: RefuseCode = RefuseCode(4);
    /// A role that cannot be at that end.
    pub const ROLE: RefuseCode = RefuseCode(5);
    /// The far end keeps as many sessions as it can.
    pub const BUSY: RefuseCode = RefuseCode(6);
    /// A record that the handshake did not expect there.
    pub const PROTOCOL: RefuseCode = RefuseCode(7);
}

impl fmt::Display for RefuseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            RefuseCode::UNKNOWN_SESSION => "unknown session",
            RefuseCode::BAD_PROOF => "wrong proof",
            RefuseCode::NOT_KEPT => "offset no longer kept",
            RefuseCode::VERSION => "version",
            RefuseCode::ROLE => "role",
            RefuseCode::BUSY => "busy",
            RefuseCode::PROTOCOL => "protocol",
            RefuseCode::OTHER => "other",
            RefuseCode(other) => return write!(f, "code {other}"),
        };
        f.write_str(name)
    }
}

impl fmt::Debug for RefuseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RefuseCode({})", self.0)
    }
}

/// The first record of each side on a link, but for what follows the nonce
/// in `OPEN`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// The highest version that the side speaks.
    pub version: u8,
    pub role: Role,
    pub nonce: Nonce,
    /// The features that the side offers; a side ignores a name that it does
    /// not know.
    pub features: Vec<String>,
}

/// What an `OPEN` asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opening {
    /// A new session, with the client's public key.
    New { public: [u8; KEY_LEN] },
    /// The resume of the session with this id; its `PROOF` follows.
    Resume { id: SessionId },
}

/// What an `ACCEPT` gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Acceptance {
    /// A new session: its id, and the far end's public key.
    New { id: SessionId, public: [u8; KEY_LEN] },
    /// A resume: the far end's received offset, and its proof.
    Resume { offset: u64, proof: Proof },
}

#[derive(Clone, PartialEq, Eq)]
pub enum Record {
    Greeting(Hello),
    Open {
        hello: Hello,
        opening: Opening,
    },
    Accept(Acceptance),
    /// The client's received offset, and its proof.
    Proof {
        offset: u64,
        proof: Proof,
    },
    Refuse {
        code: RefuseCode,
        reason: String,
    },
    /// Bytes of the session, `offset` being that of the first.
    Data {
        offset: u64,
        bytes: Vec<u8>,
    },
    /// The sender has received each byte below `offset`.
    Ack {
        offset: u64,
    },
    Ping {
        value: u64,
    },
    /// The answer to the `PING` of `value`, with the sender's received offset.
    Pong {
        value: u64,
        offset: u64,
    },
    /// The end of the session, not of one link.
    Close {
        reason: String,
    },
}

impl Record {
    /// The record's name in the table, for messages.
    pub fn name(&self) -> &'static str {
        name_of(self.kind())
    }

    pub fn kind(&self) -> u8 {
        match self {
            Record::Greeting(_) => kind::GREETING,
            Record::Open { .. } => kind::OPEN,
            Record::Accept(_) => kind::ACCEPT,
            Record::Proof { .. } => kind::PROOF,
            Record::Refuse { .. } => kind::REFUSE,
            Record::Data { .. } => kind::DATA,
            Record::Ack { .. } => kind::ACK,
            Record::Ping { .. } => kind::PING,
            Record::Pong { .. } => kind::PONG,
            Record::Close { .. } => kind::CLOSE,
        }
    }

    /// Append the record to `out`. A record that the table cannot carry
    /// (too many bytes, a feature name out of its alphabet) is refused, and
    /// `out` is left as it was.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let start = out.len();
        out.push(self.kind());
        out.extend_from_slice(&[0; 4]);
        let written = self.body(out);
        let len = out.len() - start - HEADER;
        match written {
            Ok(()) if len <= MAX_BODY => {
                out[start + 1..start + HEADER].copy_from_slice(&(len as u32).to_be_bytes());
                Ok(())
            }
            Ok(()) => {
                out.truncate(start);
                Err(EncodeError("a body over 64 KiB"))
            }
            Err(e) => {
                out.truncate(start);
                Err(e)
            }
        }
    }

    /// The record alone, as bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    fn body(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Record::Greeting(hello) => {
                hello_head(out, hello);
                features(out, &hello.features)
            }
            Record::Open { hello, opening } => {
                hello_head(out, hello);
                match opening {
                    Opening::New { public } => {
                        out.push(0);
                        out.extend_from_slice(public);
                    }
                    Opening::Resume { id } => {
                        out.push(1);
                        out.extend_from_slice(&id.0);
                    }
                }
                features(out, &hello.features)
            }
            Record::Accept(Acceptance::New { id, public }) => {
                out.push(0);
                out.extend_from_slice(&id.0);
                out.extend_from_slice(public);
                Ok(())
            }
            Record::Accept(Acceptance::Resume { offset, proof }) => {
                out.push(1);
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(&proof.0);
                Ok(())
            }
            Record::Proof { offset, proof } => {
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(&proof.0);
                Ok(())
            }
            Record::Refuse { code, reason } => {
                out.push(code.0);
                text(out, reason)
            }
            Record::Data { offset, bytes } => {
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(bytes);
                Ok(())
            }
            Record::Ack { offset } => {
                out.extend_from_slice(&offset.to_be_bytes());
                Ok(())
            }
            Record::Ping { value } => {
                out.extend_from_slice(&value.to_be_bytes());
                Ok(())
            }
            Record::Pong { value, offset } => {
                out.extend_from_slice(&value.to_be_bytes());
                out.extend_from_slice(&offset.to_be_bytes());
                Ok(())
            }
            Record::Close { reason } => text(out, reason),
        }
    }
}

/// The name of a type byte in the table.
pub fn name_of(kind: u8) -> &'static str {
    match kind {
        kind::GREETING => "GREETING",
        kind::OPEN => "OPEN",
        kind::ACCEPT => "ACCEPT",
        kind::PROOF => "PROOF",
        kind::REFUSE => "REFUSE",
        kind::DATA => "DATA",
        kind::ACK => "ACK",
        kind::PING => "PING",
        kind::PONG => "PONG",
        kind::CLOSE => "CLOSE",
        _ => "an unknown record",
    }
}

fn hello_head(out: &mut Vec<u8>, hello: &Hello) {
    out.extend_from_slice(MAGIC);
    out.push(hello.version);
    out.push(hello.role.0);
    out.extend_from_slice(&hello.nonce.0);
}

fn features(out: &mut Vec<u8>, names: &[String]) -> Result<(), EncodeError> {
    if names.len() > MAX_FEATURES {
        return Err(EncodeError("more than 16 feature names"));
    }
    out.push(names.len() as u8);
    for name in names {
        if !is_feature_name(name.as_bytes()) {
            return Err(EncodeError("a feature name out of its alphabet or length"));
        }
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
    }
    Ok(())
}

fn text(out: &mut Vec<u8>, reason: &str) -> Result<(), EncodeError> {
    if reason.len() > MAX_REASON {
        return Err(EncodeError("a reason over 1024 bytes"));
    }
    out.extend_from_slice(reason.as_bytes());
    Ok(())
}

/// 1 to 32 bytes of `a-z`, `0-9`, `.`, `-` and `_`.
pub fn is_feature_name(name: &[u8]) -> bool {
    (1..=MAX_FEATURE_NAME).contains(&name.len())
        && name.iter().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
}

/// `reason` cut to [`MAX_REASON`] bytes at a character boundary, so that a
/// long reason still goes out.
pub fn cut_reason(reason: &str) -> String {
    if reason.len() <= MAX_REASON {
        return reason.to_string();
    }
    let mut end = MAX_REASON;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_string()
}

/// A record that the table cannot carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeError(pub &'static str);

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a record that the layer cannot carry: {}", self.0)
    }
}

impl std::error::Error for EncodeError {}

/// The bytes of `DATA` are SSH's ciphertext and can be many: a message names
/// their count. A proof prints as `Proof(..)`.
impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Record::Greeting(hello) => f.debug_tuple("Greeting").field(hello).finish(),
            Record::Open { hello, opening } => {
                f.debug_struct("Open").field("hello", hello).field("opening", opening).finish()
            }
            Record::Accept(acceptance) => f.debug_tuple("Accept").field(acceptance).finish(),
            Record::Proof { offset, proof } => {
                f.debug_struct("Proof").field("offset", offset).field("proof", proof).finish()
            }
            Record::Refuse { code, reason } => {
                f.debug_struct("Refuse").field("code", code).field("reason", reason).finish()
            }
            Record::Data { offset, bytes } => {
                f.debug_struct("Data").field("offset", offset).field("len", &bytes.len()).finish()
            }
            Record::Ack { offset } => f.debug_struct("Ack").field("offset", offset).finish(),
            Record::Ping { value } => f.debug_struct("Ping").field("value", value).finish(),
            Record::Pong { value, offset } => {
                f.debug_struct("Pong").field("value", value).field("offset", offset).finish()
            }
            Record::Close { reason } => f.debug_struct("Close").field("reason", reason).finish(),
        }
    }
}
