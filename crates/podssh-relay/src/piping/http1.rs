//! HTTP/1.1 as the road needs it: a request's head, a body in chunks or
//! with its length, and an answer's head and body read as they come. A
//! Piping Server answers a sender at once and streams a receiver's body as
//! the sender's comes (nwtgck/piping-server:src/piping.ts), so a body is
//! read piece by piece, never whole, and each piece goes on at once.

use tokio::io::{AsyncRead, AsyncReadExt};

/// The longest head of an answer, and the longest line of a chunk's size.
pub const HEAD_LIMIT: usize = 16 * 1024;
/// The bytes asked of the stream in each read.
const READ: usize = 16 * 1024;

/// How a request's body goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Length {
    /// No body: a GET.
    None,
    /// In chunks, as they come: a streamed POST.
    Chunked,
    /// This many bytes: a whole POST.
    Fixed(usize),
}

/// A request's head. `authority` and `path` are the road's own words, which
/// hold no space and no line break ([`super::server::Server::parse`]).
pub fn request(method: &str, authority: &str, path: &str, length: Length) -> Vec<u8> {
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n", super::USER_AGENT);
    match length {
        Length::None => {}
        Length::Chunked => head.push_str("Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n"),
        Length::Fixed(n) => {
            head.push_str(&format!("Content-Type: application/octet-stream\r\nContent-Length: {n}\r\n"));
        }
    }
    head.push_str("\r\n");
    head.into_bytes()
}

/// One chunk of a body that goes in chunks: never empty, as an empty one
/// ends the body.
pub fn chunk(bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", bytes.len()).into_bytes();
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
    out
}

/// The end of a body that goes in chunks.
pub const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// How an answer's body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Length(u64),
    Chunked,
    UntilClose,
}

/// An answer's head: its status, how its body ends, and whether its
/// connection may carry another request after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub framing: Framing,
    pub keep: bool,
}

/// Read an answer's head from `io`, after the bytes in `buf`; the bytes after
/// the head stay in `buf`. A `100 Continue` is passed over.
pub async fn read_head<R: AsyncRead + Unpin>(io: &mut R, buf: &mut Vec<u8>) -> Result<Answer, String> {
    loop {
        let end = loop {
            if let Some(end) = find(buf, b"\r\n\r\n") {
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
        let (status, _, headers) = podssh_ws::http::parse_head(&text)?;
        if (100..200).contains(&status) {
            continue;
        }
        let header = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.to_ascii_lowercase());
        let length = header("content-length").and_then(|v| v.trim().parse::<u64>().ok());
        let framing = if status == 204 || status == 304 {
            Framing::Length(0)
        } else if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
            Framing::Chunked
        } else if let Some(length) = length {
            Framing::Length(length)
        } else {
            Framing::UntilClose
        };
        let close = header("connection").is_some_and(|v| v.contains("close")) || text.starts_with("HTTP/1.0");
        return Ok(Answer { status, framing, keep: !close && framing != Framing::UntilClose });
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

/// A body, read as it comes off `io`.
pub struct Reader<R> {
    io: R,
    buf: Vec<u8>,
    state: State,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    /// The body that follows a head of `framing`, whose first bytes are in
    /// `buf`.
    pub fn new(io: R, buf: Vec<u8>, framing: Framing) -> Reader<R> {
        let state = match framing {
            Framing::Length(n) => State::Left(n),
            Framing::Chunked => State::Size,
            Framing::UntilClose => State::UntilClose,
        };
        Reader { io, buf, state }
    }

    /// The next bytes of the body; `None` at its end. A body that its framing
    /// says is cut short is an error.
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        loop {
            match self.state {
                State::Done | State::Left(0) => {
                    self.state = State::Done;
                    return Ok(None);
                }
                State::Left(left) | State::Data(left) => {
                    if self.buf.is_empty() && !fill(&mut self.io, &mut self.buf).await? {
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
                    if self.buf.is_empty() && !fill(&mut self.io, &mut self.buf).await? {
                        self.state = State::Done;
                        return Ok(None);
                    }
                    return Ok(Some(std::mem::take(&mut self.buf)));
                }
                State::Size | State::Trailers => {
                    let Some(end) = find(&self.buf, b"\r\n") else {
                        if self.buf.len() > HEAD_LIMIT {
                            return Err("a chunk's line longer than 16 KiB".into());
                        }
                        if !fill(&mut self.io, &mut self.buf).await? {
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
                        if !fill(&mut self.io, &mut self.buf).await? {
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

    /// The whole body, at most `cap` bytes.
    pub async fn all(&mut self, cap: usize) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        while let Some(bytes) = self.next().await? {
            if out.len() + bytes.len() > cap {
                return Err(format!("a body of more than {cap} bytes"));
            }
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    /// Whether the body ended as its framing says, so that its connection
    /// may carry another request.
    pub fn finished(&self) -> bool {
        self.state == State::Done && self.buf.is_empty()
    }

    /// The stream, and the bytes read past the body.
    pub fn into_parts(self) -> (R, Vec<u8>) {
        (self.io, self.buf)
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
    let mut chunk = [0u8; READ];
    let n = io.read(&mut chunk).await.map_err(|e| e.to_string())?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n > 0)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
