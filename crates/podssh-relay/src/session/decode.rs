//! Records out of a byte stream. The link's frames mean nothing (the relay
//! can split or join them), so the decoder takes bytes as they come and
//! gives each whole record once its last byte is there.
//!
//! Each error means that the link is no longer usable: the relay or the peer
//! sent bytes that are not the layer. The caller drops the link, and a
//! resume (T-153) carries the session on a new one.

use std::fmt;

use super::record::{
    is_feature_name, kind, Acceptance, Hello, Opening, Record, RefuseCode, Role, HEADER, MAGIC, MAX_BODY, MAX_FEATURES,
    MAX_REASON,
};
use super::secret::{Nonce, Proof, SessionId, ID_LEN, KEY_LEN};

/// Why bytes are not a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A type byte that the table does not have.
    UnknownType(u8),
    /// A length over [`MAX_BODY`].
    TooLong(u32),
    /// A body that is not the body of its record.
    Malformed { record: &'static str, why: &'static str },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnknownType(t) => write!(f, "a record of unknown type {t:#04x}"),
            DecodeError::TooLong(n) => write!(f, "a record of {n} bytes, over the limit of 65536"),
            DecodeError::Malformed { record, why } => write!(f, "a malformed {record}: {why}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Whole records out of the bytes of one link.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    failed: Option<DecodeError>,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Bytes read from the link, in order.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The bytes held that are not a whole record yet.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The next whole record, or `None` until more bytes come. After an
    /// error, each call gives that error again: nothing after it is read.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Record>, DecodeError> {
        if let Some(failed) = &self.failed {
            return Err(failed.clone());
        }
        match self.take() {
            Err(e) => {
                self.buf.clear();
                self.failed = Some(e.clone());
                Err(e)
            }
            ok => ok,
        }
    }

    fn take(&mut self) -> Result<Option<Record>, DecodeError> {
        let Some(&first) = self.buf.first() else { return Ok(None) };
        // A wrong type is known at its first byte; waiting for a body that a
        // peer with no layer will never send would only hang.
        if !(kind::GREETING..=kind::RETIRE).contains(&first) {
            return Err(DecodeError::UnknownType(first));
        }
        if self.buf.len() < HEADER {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]);
        if len as usize > MAX_BODY {
            return Err(DecodeError::TooLong(len));
        }
        let end = HEADER + len as usize;
        if self.buf.len() < end {
            return Ok(None);
        }
        let record = decode_body(first, &self.buf[HEADER..end])?;
        self.buf.drain(..end);
        Ok(Some(record))
    }
}

/// The record of type `kind` with this body.
pub fn decode_body(kind: u8, body: &[u8]) -> Result<Record, DecodeError> {
    let name = super::record::name_of(kind);
    let mut b = Body { rest: body, record: name };
    let record = match kind {
        kind::GREETING => {
            let (version, role, nonce) = b.hello_head()?;
            let features = b.features()?;
            Record::Greeting(Hello { version, role, nonce, features })
        }
        kind::OPEN => {
            let (version, role, nonce) = b.hello_head()?;
            let opening = match b.byte()? {
                0 => Opening::New { public: b.array::<KEY_LEN>()? },
                1 => Opening::Resume { id: SessionId(b.array::<ID_LEN>()?) },
                _ => return Err(b.malformed("neither a new session (0) nor a resume (1)")),
            };
            let features = b.features()?;
            Record::Open { hello: Hello { version, role, nonce, features }, opening }
        }
        kind::ACCEPT => match b.byte()? {
            0 => {
                let id = SessionId(b.array::<ID_LEN>()?);
                Record::Accept(Acceptance::New { id, public: b.array::<KEY_LEN>()? })
            }
            1 => {
                let offset = b.u64()?;
                Record::Accept(Acceptance::Resume { offset, proof: Proof(b.array::<KEY_LEN>()?) })
            }
            _ => return Err(b.malformed("neither a new session (0) nor a resume (1)")),
        },
        kind::PROOF => {
            let offset = b.u64()?;
            Record::Proof { offset, proof: Proof(b.array::<KEY_LEN>()?) }
        }
        kind::REFUSE => {
            let code = RefuseCode(b.byte()?);
            Record::Refuse { code, reason: b.reason()? }
        }
        kind::DATA => {
            let offset = b.u64()?;
            let bytes = b.rest.to_vec();
            b.rest = &[];
            Record::Data { offset, bytes }
        }
        kind::ACK => Record::Ack { offset: b.u64()? },
        kind::PING => Record::Ping { value: b.u64()? },
        kind::PONG => {
            let value = b.u64()?;
            Record::Pong { value, offset: b.u64()? }
        }
        kind::CLOSE => Record::Close { reason: b.reason()? },
        kind::RETIRE => Record::Retire,
        other => return Err(DecodeError::UnknownType(other)),
    };
    b.end()?;
    Ok(record)
}

/// A cursor over one body.
struct Body<'a> {
    rest: &'a [u8],
    record: &'static str,
}

impl<'a> Body<'a> {
    fn malformed(&self, why: &'static str) -> DecodeError {
        DecodeError::Malformed { record: self.record, why }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.rest.len() < n {
            return Err(self.malformed("the body ends early"));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn hello_head(&mut self) -> Result<(u8, Role, Nonce), DecodeError> {
        if self.take(MAGIC.len())? != MAGIC {
            return Err(self.malformed("no podssh-session magic"));
        }
        let version = self.byte()?;
        let role = Role(self.byte()?);
        Ok((version, role, Nonce(self.array::<KEY_LEN>()?)))
    }

    fn features(&mut self) -> Result<Vec<String>, DecodeError> {
        let count = self.byte()? as usize;
        if count > MAX_FEATURES {
            return Err(self.malformed("more than 16 feature names"));
        }
        let mut names = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.byte()? as usize;
            let name = self.take(len)?;
            if !is_feature_name(name) {
                return Err(self.malformed("a feature name out of its alphabet or length"));
            }
            // The alphabet is ASCII, so this cannot fail.
            names.push(String::from_utf8_lossy(name).into_owned());
        }
        Ok(names)
    }

    fn reason(&mut self) -> Result<String, DecodeError> {
        if self.rest.len() > MAX_REASON {
            return Err(self.malformed("a reason over 1024 bytes"));
        }
        let text = std::str::from_utf8(self.rest).map_err(|_| self.malformed("a reason that is not UTF-8"))?;
        self.rest = &[];
        Ok(text.to_string())
    }

    fn end(self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(self.malformed("bytes after the end of the body"))
        }
    }
}
