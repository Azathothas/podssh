//! The bytes of a handover (T-668): numbers big-endian, and each run of
//! bytes after its 32-bit length, so that a reader refuses what it cannot
//! read whole and never reads past it. The bytes hold secrets, so the writer
//! keeps them in memory that is wiped when it goes.

use std::fmt;

use zeroize::Zeroizing;

/// Why bytes of a handover were not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable(pub String);

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unreadable {}

/// A writer of a handover's bytes.
pub struct Put(Zeroizing<Vec<u8>>);

impl Default for Put {
    fn default() -> Self {
        Put::new()
    }
}

impl Put {
    pub fn new() -> Put {
        Put(Zeroizing::new(Vec::with_capacity(4096)))
    }

    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub fn bool(&mut self, value: bool) {
        self.0.push(u8::from(value));
    }

    pub fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    /// Bytes of a length that the reader knows: an id, a key.
    pub fn fixed(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    /// Bytes after their length. More than 4 GiB is no state of a session.
    pub fn bytes(&mut self, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.u32(len);
        self.0.extend_from_slice(&bytes[..len as usize]);
    }

    pub fn text(&mut self, text: &str) {
        self.bytes(text.as_bytes());
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// A reader of a handover's bytes; each read names what it reads, for the
/// refusal.
pub struct Get<'a> {
    rest: &'a [u8],
}

impl<'a> Get<'a> {
    pub fn new(bytes: &'a [u8]) -> Get<'a> {
        Get { rest: bytes }
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], Unreadable> {
        if self.rest.len() < n {
            return Err(Unreadable(format!("the handover ends inside {what}")));
        }
        let (taken, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(taken)
    }

    pub fn u8(&mut self, what: &str) -> Result<u8, Unreadable> {
        Ok(self.take(1, what)?[0])
    }

    /// A flag: 0 or 1, and nothing else.
    pub fn bool(&mut self, what: &str) -> Result<bool, Unreadable> {
        match self.u8(what)? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(Unreadable(format!("{what} is {other}, not a flag"))),
        }
    }

    pub fn u32(&mut self, what: &str) -> Result<u32, Unreadable> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn u64(&mut self, what: &str) -> Result<u64, Unreadable> {
        let mut out = [0u8; 8];
        out.copy_from_slice(self.take(8, what)?);
        Ok(u64::from_be_bytes(out))
    }

    pub fn fixed<const N: usize>(&mut self, what: &str) -> Result<[u8; N], Unreadable> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N, what)?);
        Ok(out)
    }

    /// Bytes after their length, `max` at most.
    pub fn bytes(&mut self, what: &str, max: usize) -> Result<&'a [u8], Unreadable> {
        let len = self.u32(what)? as usize;
        if len > max {
            return Err(Unreadable(format!("{what} of {len} bytes, past its bound of {max}")));
        }
        self.take(len, what)
    }

    pub fn text(&mut self, what: &str, max: usize) -> Result<String, Unreadable> {
        let bytes = self.bytes(what, max)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Unreadable(format!("{what} is not UTF-8")))
    }

    /// The bytes not read yet.
    pub fn left(&self) -> usize {
        self.rest.len()
    }

    /// Nothing may follow what was read.
    pub fn end(&self, what: &str) -> Result<(), Unreadable> {
        match self.rest.len() {
            0 => Ok(()),
            n => Err(Unreadable(format!("{n} bytes follow {what}"))),
        }
    }
}
