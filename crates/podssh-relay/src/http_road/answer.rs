//! An answer of HTTP/1.1 as the client of the road reads it: its head, then
//! a body of its length, in chunks, or to the end of its connection, read as
//! it comes, so that the bytes down go on at once. The bytes read past an
//! answer stay with its connection, for the next answer's head.

use tokio::io::{AsyncRead, AsyncReadExt};

/// The longest head of an answer, and the longest line of a chunk's size.
pub const HEAD_LIMIT: usize = 16 * 1024;
/// The bytes asked of the stream in each read.
const READ: usize = 32 * 1024;

/// How an answer's body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Length(u64),
    Chunked,
    UntilClose,
}

/// An answer's head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub reason: String,
    /// Names in lower case, values trimmed, in arrival order.
    pub headers: Vec<(String, String)>,
    pub framing: Framing,
    /// Whether its connection may carry another request after it.
    pub keep: bool,
}

impl Head {
    /// The first value of a header, by its name in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_str())
    }

    /// A header's value as a number.
    pub fn number(&self, name: &str) -> Option<u64> {
        self.header(name)?.trim().parse().ok()
    }
}

/// Read an answer's head from `io`, after the bytes in `buf`; the bytes after
/// the head stay in `buf`. A `100 Continue` is passed over.
pub async fn read_head<R: AsyncRead + Unpin>(io: &mut R, buf: &mut Vec<u8>) -> Result<Head, String> {
    loop {
        let end = loop {
            if let Some(end) = find(&buf[..], b"\r\n\r\n") {
                break end + 4;
            }
            if buf.len() > HEAD_LIMIT {
                return Err("no end of the answer's head within 16 KiB".into());
            }
            if !fill(io, buf).await? {
                return Err("the connection closed before the answer's head".into());
            }
        };
        let text = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end);
        let (status, reason, headers) = podssh_ws::http::parse_head(&text)?;
        if (100..200).contains(&status) {
            continue;
        }
        let header = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.to_ascii_lowercase());
        let framing = if status == 204 || status == 304 {
            Framing::Length(0)
        } else if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
            Framing::Chunked
        } else if let Some(length) = header("content-length").and_then(|v| v.trim().parse::<u64>().ok()) {
            Framing::Length(length)
        } else {
            Framing::UntilClose
        };
        let close = header("connection").is_some_and(|v| v.contains("close")) || text.starts_with("HTTP/1.0");
        let keep = !close && framing != Framing::UntilClose;
        return Ok(Head { status, reason, headers, framing, keep });
    }
}

/// Where a body's reader is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// This many bytes left of a body of a length.
    Left(u64),
    /// Before a chunk's size.
    Size,
    /// This many bytes left of a chunk.
    Data(u64),
    /// The CRLF after a chunk.
    DataEnd,
    /// The trailers after the last chunk, to an empty line.
    Trailers,
    UntilClose,
    Done,
}

/// A body, read as it comes off `io`, whose first bytes are in `buf`.
pub struct Body<'a, R> {
    io: &'a mut R,
    buf: &'a mut Vec<u8>,
    state: State,
}

impl<'a, R: AsyncRead + Unpin> Body<'a, R> {
    pub fn new(io: &'a mut R, buf: &'a mut Vec<u8>, framing: Framing) -> Body<'a, R> {
        let state = match framing {
            Framing::Length(n) => State::Left(n),
            Framing::Chunked => State::Size,
            Framing::UntilClose => State::UntilClose,
        };
        Body { io, buf, state }
    }

    /// The next bytes of the body; `None` at its end. A body that its framing
    /// says was cut short is an error.
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        loop {
            match self.state {
                State::Done | State::Left(0) => {
                    self.state = State::Done;
                    return Ok(None);
                }
                State::Left(left) | State::Data(left) => {
                    if self.buf.is_empty() && !fill(&mut *self.io, &mut *self.buf).await? {
                        return Err("the connection closed in the middle of the body".into());
                    }
                    let n = (self.buf.len() as u64).min(left);
                    let out: Vec<u8> = self.buf.drain(..n as usize).collect();
                    self.state = match self.state {
                        State::Left(_) => State::Left(left - n),
                        _ if left == n => State::DataEnd,
                        _ => State::Data(left - n),
                    };
                    return Ok(Some(out));
                }
                State::UntilClose => {
                    if self.buf.is_empty() && !fill(&mut *self.io, &mut *self.buf).await? {
                        self.state = State::Done;
                        return Ok(None);
                    }
                    return Ok(Some(std::mem::take(&mut *self.buf)));
                }
                State::Size | State::Trailers => {
                    let Some(end) = find(&self.buf[..], b"\r\n") else {
                        if self.buf.len() > HEAD_LIMIT {
                            return Err("a chunk's line longer than 16 KiB".into());
                        }
                        if !fill(&mut *self.io, &mut *self.buf).await? {
                            return Err("the connection closed in the middle of the body".into());
                        }
                        continue;
                    };
                    let line: Vec<u8> = self.buf.drain(..end + 2).take(end).collect();
                    self.state = match self.state {
                        State::Trailers if line.is_empty() => State::Done,
                        State::Trailers => State::Trailers,
                        _ => match size(&line)? {
                            0 => State::Trailers,
                            n => State::Data(n),
                        },
                    };
                }
                State::DataEnd => {
                    if self.buf.len() < 2 {
                        if !fill(&mut *self.io, &mut *self.buf).await? {
                            return Err("the connection closed in the middle of the body".into());
                        }
                        continue;
                    }
                    if &self.buf[..2] != b"\r\n" {
                        return Err("a chunk is not followed by CRLF".into());
                    }
                    self.buf.drain(..2);
                    self.state = State::Size;
                }
            }
        }
    }

    /// The whole body, `cap` bytes at most.
    pub async fn all(&mut self, cap: usize) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        while let Some(bytes) = self.next().await? {
            if out.len() + bytes.len() > cap {
                return Err(format!("an answer's body of more than {cap} bytes"));
            }
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    /// Whether the body ended as its framing says.
    pub fn finished(&self) -> bool {
        self.state == State::Done
    }
}

/// A chunk's size, in hex, before any extension.
fn size(line: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(line).map_err(|_| "a chunk's size that is not text".to_string())?;
    let digits = text.split(';').next().unwrap_or_default().trim();
    u64::from_str_radix(digits, 16).map_err(|_| format!("a chunk's size {:?}", podssh_ws::text::one_line(digits)))
}

/// Read once more into `buf`; `false` at the end of the stream.
async fn fill<R: AsyncRead + Unpin>(io: &mut R, buf: &mut Vec<u8>) -> Result<bool, String> {
    let mut chunk = vec![0u8; READ];
    let n = io.read(&mut chunk).await.map_err(|e| e.to_string())?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n > 0)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Answers as nginx 1.24 writes them, chunked and of a length, and one
    /// to the end of its connection; each body is read whole, and a kept
    /// connection keeps the next answer's head.
    #[tokio::test]
    async fn chunked_and_framed_answers_are_read_and_the_next_head_stays() {
        let (mut ours, mut theirs) = tokio::io::duplex(64 * 1024);
        let sent = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\
            Transfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Offset: 0\r\n\r\n5\r\nhello\r\n\
            6;ext=1\r\n world\r\n0\r\n\r\nHTTP/1.1 204 No Content\r\nX-Ack: 3\r\n\r\n";
        theirs.write_all(sent).await.unwrap();
        let mut buf = Vec::new();
        let head = read_head(&mut ours, &mut buf).await.unwrap();
        assert_eq!((head.status, head.framing, head.keep), (200, Framing::Chunked, true));
        assert_eq!(head.number("x-offset"), Some(0));
        let mut body = Body::new(&mut ours, &mut buf, head.framing);
        assert_eq!(body.all(64).await.unwrap(), b"hello world");
        assert!(body.finished());
        let next = read_head(&mut ours, &mut buf).await.unwrap();
        assert_eq!((next.status, next.framing, next.number("X-Ack")), (204, Framing::Length(0), Some(3)));
        theirs.write_all(b"HTTP/1.0 200 OK\r\n\r\nto the end").await.unwrap();
        drop(theirs);
        let last = read_head(&mut ours, &mut buf).await.unwrap();
        assert_eq!((last.framing, last.keep), (Framing::UntilClose, false));
        assert_eq!(Body::new(&mut ours, &mut buf, last.framing).all(64).await.unwrap(), b"to the end");
    }

    #[tokio::test]
    async fn a_body_cut_short_or_too_long_is_an_error() {
        let (mut ours, mut theirs) = tokio::io::duplex(1024);
        theirs.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort").await.unwrap();
        drop(theirs);
        let mut buf = Vec::new();
        let head = read_head(&mut ours, &mut buf).await.unwrap();
        let mut body = Body::new(&mut ours, &mut buf, head.framing);
        assert_eq!(body.next().await.unwrap(), Some(b"short".to_vec()));
        assert!(body.next().await.is_err());
        let (mut ours, mut theirs) = tokio::io::duplex(1024);
        theirs.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789").await.unwrap();
        let mut buf = Vec::new();
        let head = read_head(&mut ours, &mut buf).await.unwrap();
        assert!(Body::new(&mut ours, &mut buf, head.framing).all(4).await.is_err());
    }
}
