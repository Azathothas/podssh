//! The records of chat (T-099): a type byte, a 32-bit length (big-endian)
//! and a body. Numbers are big-endian; text is UTF-8. A length past the
//! limit of its type is refused before its body is read, so a peer cannot
//! make the receiver hold more than one chunk.

/// The version of the protocol, in each side's greeting.
pub const VERSION: u8 = 1;
/// The most bytes of one message's text.
pub const MAX_TEXT: usize = 16 * 1024;
/// The most bytes of a nick.
pub const MAX_NICK: usize = 64;
/// The most bytes of a file's offered name.
pub const MAX_NAME: usize = 255;
/// The most bytes of a file in one chunk.
pub const MAX_CHUNK: usize = 64 * 1024;

const HELLO: u8 = 1;
const TEXT: u8 = 2;
const ACK: u8 = 3;
const OFFER: u8 = 4;
const ACCEPT: u8 = 5;
const DECLINE: u8 = 6;
const CHUNK: u8 = 7;
const DONE: u8 = 8;
const BUSY: u8 = 9;

/// One record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// Each side's first record: the version, and the nick to show.
    Hello {
        version: u8,
        nick: String,
    },
    /// A message, with this side's id for it.
    Text {
        id: u64,
        text: String,
    },
    /// The receiver has the message of this id.
    Ack {
        id: u64,
    },
    /// A file: its size, its SHA-256 and its name; nothing of it moves
    /// before the receiver's accept.
    Offer {
        id: u64,
        size: u64,
        sha256: [u8; 32],
        name: String,
    },
    Accept {
        id: u64,
    },
    Decline {
        id: u64,
    },
    /// Bytes of an accepted file, at their offset.
    Chunk {
        id: u64,
        offset: u64,
        data: Vec<u8>,
    },
    /// The receiver's word on a file: whether its SHA-256 matched.
    Done {
        id: u64,
        whole: bool,
    },
    /// The side that waits has a peer already.
    Busy,
}

/// Why bytes are not a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A length past the limit of the record's type.
    TooLong {
        kind: u8,
        len: usize,
    },
    UnknownKind(u8),
    /// A body that does not hold its type's fields.
    Malformed(&'static str),
    /// Text that is not UTF-8.
    NotUtf8,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooLong { kind, len } => write!(f, "a record of type {kind} of {len} bytes, past its limit"),
            DecodeError::UnknownKind(kind) => write!(f, "a record of unknown type {kind}"),
            DecodeError::Malformed(why) => write!(f, "a malformed record: {why}"),
            DecodeError::NotUtf8 => f.write_str("text that is not UTF-8"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Record {
    /// The record's bytes: its type, its length, its body.
    pub fn encode(&self) -> Vec<u8> {
        let (kind, body) = match self {
            Record::Hello { version, nick } => (HELLO, [&[*version][..], nick.as_bytes()].concat()),
            Record::Text { id, text } => (TEXT, [&id.to_be_bytes()[..], text.as_bytes()].concat()),
            Record::Ack { id } => (ACK, id.to_be_bytes().to_vec()),
            Record::Offer { id, size, sha256, name } => {
                (OFFER, [&id.to_be_bytes()[..], &size.to_be_bytes(), sha256, name.as_bytes()].concat())
            }
            Record::Accept { id } => (ACCEPT, id.to_be_bytes().to_vec()),
            Record::Decline { id } => (DECLINE, id.to_be_bytes().to_vec()),
            Record::Chunk { id, offset, data } => {
                (CHUNK, [&id.to_be_bytes()[..], &offset.to_be_bytes(), data].concat())
            }
            Record::Done { id, whole } => (DONE, [&id.to_be_bytes()[..], &[u8::from(*whole)]].concat()),
            Record::Busy => (BUSY, Vec::new()),
        };
        let mut out = Vec::with_capacity(5 + body.len());
        out.push(kind);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }
}

/// The most bytes of a body of `kind`; `None` for a type that this side
/// does not know.
fn limit(kind: u8) -> Option<usize> {
    Some(match kind {
        HELLO => 1 + MAX_NICK,
        TEXT => 8 + MAX_TEXT,
        ACK | ACCEPT | DECLINE => 8,
        OFFER => 8 + 8 + 32 + MAX_NAME,
        CHUNK => 8 + 8 + MAX_CHUNK,
        DONE => 9,
        BUSY => 0,
        _ => return None,
    })
}

/// Records out of a byte stream, as its bytes come.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Bytes as they came.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole record; `None` until its bytes are all there.
    pub fn next_record(&mut self) -> Result<Option<Record>, DecodeError> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let kind = self.buf[0];
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        let max = limit(kind).ok_or(DecodeError::UnknownKind(kind))?;
        if len > max {
            return Err(DecodeError::TooLong { kind, len });
        }
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        let body: Vec<u8> = self.buf.drain(..5 + len).skip(5).collect();
        parse(kind, &body).map(Some)
    }
}

fn parse(kind: u8, body: &[u8]) -> Result<Record, DecodeError> {
    let u64_at = |at: usize| -> Result<u64, DecodeError> {
        let bytes = body.get(at..at + 8).ok_or(DecodeError::Malformed("a short number"))?;
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| DecodeError::Malformed("a short number"))?))
    };
    let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::NotUtf8);
    let exactly =
        |n: usize| (body.len() == n).then_some(()).ok_or(DecodeError::Malformed("a body of the wrong length"));
    Ok(match kind {
        HELLO => {
            let (&version, nick) = body.split_first().ok_or(DecodeError::Malformed("a greeting with no version"))?;
            Record::Hello { version, nick: text(nick)? }
        }
        TEXT => Record::Text { id: u64_at(0)?, text: text(body.get(8..).unwrap_or_default())? },
        ACK => {
            exactly(8)?;
            Record::Ack { id: u64_at(0)? }
        }
        OFFER => {
            if body.len() < 48 {
                return Err(DecodeError::Malformed("an offer with no digest"));
            }
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&body[16..48]);
            Record::Offer { id: u64_at(0)?, size: u64_at(8)?, sha256, name: text(&body[48..])? }
        }
        ACCEPT => {
            exactly(8)?;
            Record::Accept { id: u64_at(0)? }
        }
        DECLINE => {
            exactly(8)?;
            Record::Decline { id: u64_at(0)? }
        }
        CHUNK => {
            if body.len() < 16 {
                return Err(DecodeError::Malformed("a chunk with no offset"));
            }
            Record::Chunk { id: u64_at(0)?, offset: u64_at(8)?, data: body[16..].to_vec() }
        }
        DONE => {
            exactly(9)?;
            Record::Done { id: u64_at(0)?, whole: body[8] == 1 }
        }
        BUSY => {
            exactly(0)?;
            Record::Busy
        }
        other => return Err(DecodeError::UnknownKind(other)),
    })
}
