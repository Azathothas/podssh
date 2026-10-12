//! The framing of UDP in a stream (T-168): each datagram is its length in
//! two bytes, big-endian, then its bytes. 65,507 bytes is the most that one
//! UDP datagram over IPv4 holds, so no podssh writes a longer length: a
//! datagram that is too long is counted and dropped where it would be
//! framed, and a length over the limit is refused where it is read, as the
//! stream is then not this framing.

use std::fmt;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// The most bytes of one datagram: a UDP datagram over IPv4.
pub const MAX_DATAGRAM: usize = 65_507;
/// The bytes of a datagram's length.
pub const LENGTH: usize = 2;
/// The size of each read of [`Frames`].
const READ: usize = 64 * 1024;

/// A stream that is not this framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// A length over [`MAX_DATAGRAM`].
    TooLong(usize),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLong(n) => write!(
                f,
                "a datagram's length is {n}, over the {MAX_DATAGRAM} bytes of one UDP datagram: the stream is not \
                 each datagram after its 16-bit length"
            ),
        }
    }
}

impl std::error::Error for FrameError {}

/// `datagram` after its length; `None` when it is too long to be one UDP
/// datagram, and the caller counts it.
pub fn framed(datagram: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(LENGTH + datagram.len());
    if !encode(datagram, &mut out) {
        return None;
    }
    Some(out)
}

/// Append `datagram`, after its length, to `out`; `false`, with nothing
/// appended, when it is too long.
pub fn encode(datagram: &[u8], out: &mut Vec<u8>) -> bool {
    if datagram.len() > MAX_DATAGRAM {
        return false;
    }
    out.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
    out.extend_from_slice(datagram);
    true
}

/// The datagrams of a stream whose bytes come in pieces of any size: each
/// datagram whole, and none joined to the next.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// The next bytes of the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole datagram, or `None` until each of its bytes came. A
    /// length over the limit is refused as soon as its two bytes came.
    pub fn next_datagram(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if self.buf.len() < LENGTH {
            return Ok(None);
        }
        let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
        if len > MAX_DATAGRAM {
            return Err(FrameError::TooLong(len));
        }
        if self.buf.len() < LENGTH + len {
            return Ok(None);
        }
        let datagram = self.buf[LENGTH..LENGTH + len].to_vec();
        self.buf.drain(..LENGTH + len);
        Ok(Some(datagram))
    }

    /// The bytes that wait for the rest of their datagram.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// The datagrams of a byte stream, as they are read from it.
pub struct Frames<R> {
    stream: R,
    decoder: Decoder,
    buf: Box<[u8]>,
}

impl<R: AsyncRead + Unpin> Frames<R> {
    pub fn new(stream: R) -> Frames<R> {
        Frames { stream, decoder: Decoder::new(), buf: vec![0u8; READ].into_boxed_slice() }
    }

    /// The next datagram, or `None` at the end of the stream between two
    /// datagrams. A stream that ends inside a datagram, or that is not the
    /// framing (`InvalidData`), is an error. Safe to cancel, as in a
    /// `select!`: each byte that a read gave waits in the decoder.
    pub async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            match self.decoder.next_datagram() {
                Ok(Some(datagram)) => return Ok(Some(datagram)),
                Ok(None) => {}
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
            let n = self.stream.read(&mut self.buf).await?;
            if n == 0 {
                return match self.decoder.pending() {
                    0 => Ok(None),
                    left => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("the stream ended {left} bytes into a datagram"),
                    )),
                };
            }
            self.decoder.push(&self.buf[..n]);
        }
    }
}
