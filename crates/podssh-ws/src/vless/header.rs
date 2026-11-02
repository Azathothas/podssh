//! VLESS's request and its answer (Xray-core,
//! `proxy/vless/encoding/encoding.go`). The request is the version 0, the
//! user's 16 bytes, the length of its add-ons (0: no flow), the command (1:
//! TCP), then the port and the address, port first (`PortThenAddress`), the
//! address a type byte (1 IPv4, 2 a name, 3 IPv6; `common/protocol/payload.go`)
//! and its bytes. The answer is the version again and the length of its
//! add-ons, then the target's bytes. The server writes its answer with the
//! target's first bytes (`proxy/vless/inbound/inbound.go`, a buffered writer
//! flushed with the first write), and ends the session without one when it
//! refuses the ID or cannot reach the target.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::link::Id;

/// VLESS's version, the only one that Xray-core speaks.
pub const VERSION: u8 = 0;
const COMMAND_TCP: u8 = 1;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_NAME: u8 = 2;
const ADDRESS_IPV6: u8 = 3;

/// The request for `host:port`. A name is of the characters that the server
/// reads (`common/protocol/address.go`, `isValidDomain`), 255 bytes at most.
pub fn request(id: &Id, host: &str, port: u16) -> Result<Vec<u8>, String> {
    if port == 0 {
        return Err("port 0 is no port".into());
    }
    let mut out = Vec::with_capacity(24 + host.len());
    out.push(VERSION);
    out.extend_from_slice(id.bytes());
    out.push(0);
    out.push(COMMAND_TCP);
    out.extend_from_slice(&port.to_be_bytes());
    match host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(ADDRESS_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(ADDRESS_IPV6);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let readable = host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
            if host.is_empty() || host.len() > 255 || !readable {
                return Err(format!("{host:?} is no name that a VLESS server reads"));
            }
            out.push(ADDRESS_NAME);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    Ok(out)
}

/// Why no answer came.
#[derive(Debug)]
pub enum AnswerError {
    /// The server ended the stream before its answer.
    Ended,
    /// The first byte is not VLESS's version.
    NotVless(u8),
    Io(io::Error),
}

/// The words of a stream that ended before VLESS's answer.
pub const ENDED: &str = "the server ended the session before VLESS's answer: it refused the ID, or it could not \
                         reach the target";

impl AnswerError {
    fn into_io(self) -> io::Error {
        match self {
            AnswerError::Ended => io::Error::new(io::ErrorKind::ConnectionAborted, ENDED),
            AnswerError::NotVless(v) => io::Error::new(io::ErrorKind::InvalidData, not_vless(v)),
            AnswerError::Io(e) => e,
        }
    }
}

/// The words of an answer that is not VLESS's: a server's fallback for an
/// ID that it refused sends another protocol's bytes, as a web server's.
pub fn not_vless(version: u8) -> String {
    format!(
        "its answer is not VLESS's (its first byte is {version}, not {VERSION}): another protocol, or the fallback \
         of a server that refused the ID"
    )
}

/// The stream of a session, which reads VLESS's answer before the target's
/// bytes and passes writes through.
pub struct Answered<S> {
    inner: S,
    /// The answer's bytes so far, until it is whole.
    waiting: Option<Vec<u8>>,
    /// The target's bytes that came with the answer, from `at`.
    ahead: Vec<u8>,
    at: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Answered<S> {
    pub fn new(inner: S) -> Answered<S> {
        Answered { inner, waiting: Some(Vec::new()), ahead: Vec::new(), at: 0 }
    }

    /// Read until VLESS's answer is whole.
    pub async fn answer(&mut self) -> Result<(), AnswerError> {
        std::future::poll_fn(|cx| self.poll_answer(cx)).await
    }

    fn poll_answer(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), AnswerError>> {
        loop {
            let Some(waiting) = self.waiting.as_mut() else { return Poll::Ready(Ok(())) };
            if let Some(len) = whole(waiting)? {
                self.ahead = waiting.split_off(len);
                self.at = 0;
                self.waiting = None;
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; 4096];
            let mut read = ReadBuf::new(&mut chunk);
            std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read)).map_err(AnswerError::Io)?;
            if read.filled().is_empty() {
                return Poll::Ready(Err(AnswerError::Ended));
            }
            waiting.extend_from_slice(read.filled());
        }
    }
}

/// The length of a whole answer at the start of `bytes`, or none yet.
fn whole(bytes: &[u8]) -> Result<Option<usize>, AnswerError> {
    match bytes {
        [] | [VERSION] => Ok(None),
        [v, ..] if *v != VERSION => Err(AnswerError::NotVless(*v)),
        [_, addons, ..] => {
            let len = 2 + usize::from(*addons);
            Ok((bytes.len() >= len).then_some(len))
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Answered<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        std::task::ready!(this.poll_answer(cx)).map_err(AnswerError::into_io)?;
        if this.at < this.ahead.len() {
            let n = (this.ahead.len() - this.at).min(buf.remaining());
            buf.put_slice(&this.ahead[this.at..this.at + n]);
            this.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Answered<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn id() -> Id {
        Id::parse("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    /// The bytes of Xray-core's `EncodeRequestHeader` for each kind of
    /// address: version, ID, no add-ons, TCP, the port, then the address.
    #[test]
    fn the_request_is_xray_s_bytes_for_a_name_and_each_family() {
        let mut head = vec![0u8];
        head.extend_from_slice(&[0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16]);
        head.extend_from_slice(&[0x44, 0x66, 0x55, 0x44, 0x00, 0x00, 0x00, 0x01]);
        let name = request(&id(), "github.com", 22).unwrap();
        assert_eq!(&name[..19], &head[..]);
        assert_eq!(&name[19..], b"\x00\x16\x02\x0agithub.com");
        assert_eq!(&request(&id(), "192.0.2.7", 443).unwrap()[19..], &[0x01, 0xbb, 1, 192, 0, 2, 7]);
        let v6 = request(&id(), "[2001:db8::1]", 22).unwrap();
        assert_eq!((v6[21], v6.len()), (ADDRESS_IPV6, 22 + 16));
        assert!(request(&id(), "a b", 22).is_err() && request(&id(), &"a".repeat(256), 22).is_err());
        assert!(request(&id(), "h", 0).is_err());
    }

    /// The answer is read before the target's bytes, whether it comes alone,
    /// in pieces, with add-ons, or with the target's first bytes.
    #[tokio::test]
    async fn the_answer_is_taken_and_the_target_s_bytes_follow() {
        for wire in [&b"\x00\x00SSH-2.0-x\r\n"[..], b"\x00\x03abcSSH-2.0-x\r\n"] {
            let (ours, mut theirs) = tokio::io::duplex(64);
            let mut stream = Answered::new(ours);
            for byte in wire {
                theirs.write_all(&[*byte]).await.unwrap();
            }
            stream.answer().await.unwrap();
            let mut banner = [0u8; 11];
            stream.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"SSH-2.0-x\r\n");
        }
    }

    /// An end before the answer, and bytes of another protocol, are said.
    #[tokio::test]
    async fn an_end_before_the_answer_and_another_protocol_are_said() {
        let (ours, theirs) = tokio::io::duplex(64);
        drop(theirs);
        let mut stream = Answered::new(ours);
        assert!(matches!(stream.answer().await, Err(AnswerError::Ended)));
        let (ours, mut theirs) = tokio::io::duplex(64);
        theirs.write_all(b"HTTP/1.1 400 Bad Request\r\n").await.unwrap();
        let mut stream = Answered::new(ours);
        let mut byte = [0u8; 1];
        let e = stream.read(&mut byte).await.unwrap_err();
        assert!(e.to_string().contains("first byte is 72"), "{e}");
        assert!(ENDED.contains("refused the ID"));
    }
}
