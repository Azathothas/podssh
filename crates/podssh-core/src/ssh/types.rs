//! SSH wire types (RFC 4251 §5): byte, boolean, uint32, string, mpint,
//! name-list. One writer, one cursor reader — every KEXINIT field and every
//! kex input goes through these, so a malformed field is one error, not five.

/// Why bytes are not a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeError {
    /// The cursor ran out mid-value: more bytes, not a verdict.
    Truncated,
    /// A name-list entry is empty or the list has a trailing comma.
    BadNameList { list: String },
    /// An mpint whose top bit is set without its zero pad (RFC 4251 §5 —
    /// a positive value MUST carry the pad; without it the value is
    /// malformed, not negative, and not "more bytes needed").
    BadMpint,
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "value runs past the end of the buffer"),
            Self::BadNameList { list } => write!(f, "malformed name-list {list:?}"),
            Self::BadMpint => write!(f, "mpint top bit set without its zero pad"),
        }
    }
}

impl std::error::Error for TypeError {}

/// Append a `string`: uint32 length + bytes.
pub fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// Append an `mpint`: uint32 length + two's-complement big-endian, with a
/// leading zero iff the high bit is set (RFC 4251 §5: "a zero is stored as a
/// string with zero bytes of data", and a positive value whose top bit is set
/// gains one zero octet — without it the value reads as negative).
pub fn put_mpint(out: &mut Vec<u8>, value: &[u8]) {
    let stripped: &[u8] = {
        let mut i = 0;
        while i < value.len() && value[i] == 0 {
            i += 1;
        }
        &value[i..]
    };
    if stripped.is_empty() {
        put_u32(out, 0);
        return;
    }
    let pad = u8::from(stripped[0] & 0x80 != 0);
    put_u32(out, stripped.len() as u32 + u32::from(pad));
    if pad == 1 {
        out.push(0);
    }
    out.extend_from_slice(stripped);
}

/// Append a `name-list`: comma-joined names as one `string`.
pub fn put_namelist(out: &mut Vec<u8>, names: &[&str]) {
    put_string(out, names.join(",").as_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// A cursor over a payload being decoded. `Truncated` is never a verdict —
/// the caller feeds more bytes or fails the stream, it never guesses.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TypeError> {
        let end = self.pos.checked_add(n).ok_or(TypeError::Truncated)?;
        if end > self.buf.len() {
            return Err(TypeError::Truncated);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, TypeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, TypeError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn boolean(&mut self) -> Result<bool, TypeError> {
        Ok(self.u8()? != 0)
    }

    /// Exactly `n` raw bytes (the KEXINIT cookie).
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], TypeError> {
        self.take(n)
    }

    /// A `string`, returned borrowed — the caller copies what it keeps.
    pub fn string(&mut self) -> Result<&'a [u8], TypeError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// An `mpint`, normalized: leading zeroes stripped, empty meaning zero.
    /// The sign bit is checked, not honoured — SSH never sends a negative
    /// mpint on this path, and a leading 0x80+ byte without its zero pad is
    /// a malformed value, not a negative number to propagate.
    pub fn mpint(&mut self) -> Result<&'a [u8], TypeError> {
        let raw = self.string()?;
        if raw.is_empty() {
            return Ok(&[]);
        }
        if raw[0] & 0x80 != 0 {
            return Err(TypeError::BadMpint);
        }
        let mut i = 0;
        while i + 1 < raw.len() && raw[i] == 0 {
            i += 1;
        }
        Ok(&raw[i..])
    }

    /// A `name-list`, split and validated. Empty entries are refused: a
    /// trailing comma is a peer smuggling an empty algorithm name.
    pub fn namelist(&mut self) -> Result<Vec<String>, TypeError> {
        let raw = self.string()?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        let text = std::str::from_utf8(raw)
            .map_err(|_| TypeError::BadNameList { list: format!("{raw:?}") })?;
        if text.split(',').any(str::is_empty) {
            return Err(TypeError::BadNameList { list: text.to_string() });
        }
        Ok(text.split(',').map(str::to_string).collect())
    }

    /// Bytes not yet consumed. A KEXINIT with trailing bytes is malformed —
    /// strict, because trailing bytes after a handshake message are where a
    /// downgrade hides.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}
