//! HTTP/1.1 for XHTTP (Q67): the connection to the server, a request's head
//! as `super::xhttp::request` makes it for HTTP/2 (the padding of `Referer`,
//! `User-Agent`, the link's headers, gRPC's type on a streamed upload), and a
//! response read as a stream: its head, then its body by its length, in
//! chunks decoded as they come, or to the connection's end. podssh writes
//! and reads the heads alone; each body passes as bytes.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use super::link::Server;
use super::VlessError;
use crate::dial::ProxyChoice;
use crate::tls::Trust;
use crate::via::Duplex;

/// The longest response head read: a server's head is a few hundred bytes.
const HEAD_MAX: usize = 64 * 1024;
/// The longest line of a chunk's size, with its extensions.
const LINE_MAX: usize = 4096;

/// A connection of HTTP/1.1, read through a buffer.
pub(super) type Conn = BufReader<Box<dyn Duplex>>;

/// What a dial of a connection to the server needs, owned, so that the task
/// of the uploads dials again when the server closed its connection.
#[derive(Clone)]
pub(super) struct Again {
    pub server: Server,
    pub trust: Trust,
    pub proxy: ProxyChoice,
    pub timeout: Duration,
}

impl Again {
    /// What `dial` holds for `server`, owned.
    pub fn of(server: &Server, dial: &super::Dial<'_>) -> Again {
        Again { server: server.clone(), trust: dial.trust.clone(), proxy: dial.proxy.clone(), timeout: dial.timeout }
    }

    /// A connection to the same server, dialed as the first: TCP through
    /// the host's proxy, and TLS that offers `http/1.1` alone, as the server
    /// refused HTTP/2 already.
    pub async fn connect(&self) -> Result<Conn, VlessError> {
        let Again { server, trust, proxy, timeout } = self;
        let tcp = crate::dial::dial(&server.host, server.port, proxy, *timeout).await.map_err(VlessError::Dial)?;
        if !server.tls {
            return Ok(BufReader::new(Box::new(tcp)));
        }
        let tls = super::xhttp::tls(server, trust, *timeout, vec![b"http/1.1".to_vec()], tcp).await?;
        Ok(BufReader::new(Box::new(tls)))
    }
}

/// How a body is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Framing {
    /// No body: a GET.
    None,
    Length(u64),
    Chunked,
    /// To the end of the connection: a response with neither of the others.
    ToEnd,
}

/// A request's head: its line, `Host`, the headers of XHTTP's request, and
/// the body's framing.
pub(super) fn head(server: &Server, method: http::Method, path: &str, body: Framing) -> Result<Vec<u8>, VlessError> {
    let streamed = body == Framing::Chunked;
    let request = super::xhttp::request(server, method.clone(), path, streamed)?;
    let target = request.uri().path_and_query().map_or("/", |p| p.as_str());
    let mut text = format!("{method} {target} HTTP/1.1\r\nHost: {}\r\n", server.authority);
    for (name, value) in request.headers() {
        // The link's own Host would be a second one: the authority is it.
        if *name == http::header::HOST {
            continue;
        }
        if let Ok(value) = value.to_str() {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    match body {
        Framing::Length(n) => text.push_str(&format!("Content-Length: {n}\r\n")),
        Framing::Chunked => text.push_str("Transfer-Encoding: chunked\r\n"),
        Framing::None | Framing::ToEnd => {}
    }
    text.push_str("\r\n");
    Ok(text.into_bytes())
}

/// What a response's head said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Answer {
    pub status: u16,
    pub body: Framing,
    /// The server closes the connection after this response.
    pub close: bool,
}

/// The head of the answer to `what`, which must be a 200, within `limit`;
/// a `100 Continue` before it is passed over. The words of a refusal are
/// those of HTTP/2's road (`super::xhttp::answer`).
pub(super) async fn answer(conn: &mut Conn, limit: Duration, what: &str) -> Result<Answer, VlessError> {
    let read = async {
        loop {
            let answer = read_head(conn).await?;
            if answer.status != 100 {
                return Ok::<_, io::Error>(answer);
            }
        }
    };
    let answer = tokio::time::timeout(limit, read)
        .await
        .map_err(|_| VlessError::Carry(format!("no answer to {what} within {} s", limit.as_secs())))?
        .map_err(|e| VlessError::Carry(format!("{what}: HTTP/1.1: {e}")))?;
    if answer.status == 200 {
        return Ok(answer);
    }
    let why = match answer.status {
        404 => format!("{what}: no XHTTP at the link's path, or for its host"),
        400 => format!("{what}: its padding, its session or its mode"),
        _ => what.to_string(),
    };
    Err(VlessError::Refused { status: answer.status, why })
}

/// A line, without its CRLF, of at most `max` bytes.
async fn line<R: AsyncRead + Unpin>(conn: &mut BufReader<R>, max: usize) -> io::Result<String> {
    let mut bytes = Vec::new();
    let n = (&mut *conn).take(max as u64 + 2).read_until(b'\n', &mut bytes).await?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the server ended the connection"));
    }
    if !bytes.ends_with(b"\n") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "a line longer than the bound"));
    }
    while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a line that is not text"))
}

async fn read_head<R: AsyncRead + Unpin>(conn: &mut BufReader<R>) -> io::Result<Answer> {
    let bad = |why: String| io::Error::new(io::ErrorKind::InvalidData, why);
    let first = line(conn, HEAD_MAX).await?;
    let mut words = first.split(' ');
    let (version, code) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
    if !version.starts_with("HTTP/1.") {
        return Err(bad(format!("an answer that is not HTTP/1.1: {first:?}")));
    }
    let status = code.parse::<u16>().map_err(|_| bad(format!("no status in {first:?}")))?;
    let (mut length, mut chunked, mut close, mut read) = (None, false, version == "HTTP/1.0", first.len());
    loop {
        let field = line(conn, HEAD_MAX).await?;
        read += field.len() + 2;
        if read > HEAD_MAX {
            return Err(bad(format!("a head longer than {HEAD_MAX} bytes")));
        }
        if field.is_empty() {
            break;
        }
        let Some((name, value)) = field.split_once(':') else { continue };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_ascii_lowercase());
        match name.as_str() {
            "content-length" => {
                length = Some(value.parse::<u64>().map_err(|_| bad(format!("Content-Length {value}")))?);
            }
            "transfer-encoding" => chunked = value.split(',').any(|v| v.trim() == "chunked"),
            "connection" => close = value.split(',').any(|v| v.trim() == "close"),
            _ => {}
        }
    }
    // A chunked body wins over a length, as RFC 9112 (6.3) says.
    let body = match (chunked, length) {
        (true, _) => Framing::Chunked,
        (false, Some(n)) => Framing::Length(n),
        (false, None) if status == 204 || status == 304 || (100..200).contains(&status) => Framing::Length(0),
        (false, None) => Framing::ToEnd,
    };
    Ok(Answer { status, body, close: close || body == Framing::ToEnd })
}

/// The body of a response framed as `framing`, to `out` as it comes, each
/// chunk flushed: the download of a session streams in it.
pub(super) async fn body<R, W>(conn: &mut BufReader<R>, framing: Framing, out: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match framing {
        Framing::None => Ok(()),
        Framing::Length(n) => exactly(conn, n, out).await,
        Framing::ToEnd => {
            tokio::io::copy(conn, out).await?;
            out.flush().await
        }
        Framing::Chunked => loop {
            let size = line(conn, LINE_MAX).await?;
            let hex = size.split(';').next().unwrap_or_default().trim();
            let n = u64::from_str_radix(hex, 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("a chunk's size {hex:?}")))?;
            if n == 0 {
                // The trailer, to its empty line, so that the next answer
                // on a kept connection starts at its own head.
                while !line(conn, HEAD_MAX).await?.is_empty() {}
                return Ok(());
            }
            exactly(conn, n, out).await?;
            if !line(conn, LINE_MAX).await?.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "no CRLF after a chunk"));
            }
        },
    }
}

/// `n` bytes of `conn` to `out`, flushed; fewer is an early end.
async fn exactly<R, W>(conn: &mut BufReader<R>, n: u64, out: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut (&mut *conn).take(n), out).await?;
    out.flush().await?;
    if copied < n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the server ended the connection in a body"));
    }
    Ok(())
}

/// One chunk of a streamed request's body, flushed; an empty `data` is the
/// last chunk, which ends the body.
pub(super) async fn chunk<W: AsyncWrite + Unpin>(io: &mut W, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        io.write_all(b"0\r\n\r\n").await?;
    } else {
        io.write_all(format!("{:x}\r\n", data.len()).as_bytes()).await?;
        io.write_all(data).await?;
        io.write_all(b"\r\n").await?;
    }
    io.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn decoded(wire: &[u8]) -> (Answer, Vec<u8>, Vec<u8>) {
        let mut conn = BufReader::new(wire);
        let answer = read_head(&mut conn).await.unwrap();
        let mut out = Vec::new();
        body(&mut conn, answer.body, &mut out).await.unwrap();
        let mut rest = Vec::new();
        conn.read_to_end(&mut rest).await.unwrap();
        (answer, out, rest)
    }

    #[tokio::test]
    async fn a_chunked_body_is_decoded_and_the_next_answer_starts_after_its_trailer() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 99\r\n\r\n\
                     5;x=y\r\nhello\r\n1\r\n!\r\n0\r\nX-T: 1\r\n\r\nHTTP/1.1 200";
        let (answer, out, rest) = decoded(wire).await;
        assert_eq!((answer.status, answer.body, answer.close), (200, Framing::Chunked, false));
        assert_eq!(out, b"hello!");
        assert_eq!(rest, b"HTTP/1.1 200");
    }

    #[tokio::test]
    async fn a_length_a_close_and_a_body_to_the_end_are_read() {
        let (answer, out, rest) = decoded(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef").await;
        assert_eq!((answer.body, out.as_slice(), rest.as_slice()), (Framing::Length(3), &b"abc"[..], &b"def"[..]));
        let (answer, out, _) = decoded(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nall of it").await;
        assert_eq!((answer.body, answer.close, out.as_slice()), (Framing::ToEnd, true, &b"all of it"[..]));
        let mut short = BufReader::new(&b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nab"[..]);
        let answer = read_head(&mut short).await.unwrap();
        assert!(body(&mut short, answer.body, &mut Vec::<u8>::new()).await.is_err(), "an early end is said");
        let mut not_http = BufReader::new(&b"SSH-2.0-x\r\n\r\n"[..]);
        assert!(read_head(&mut not_http).await.is_err());
    }

    #[tokio::test]
    async fn a_streamed_body_is_written_in_chunks_and_ends_with_the_last() {
        let mut out = Vec::new();
        chunk(&mut out, b"hello world!").await.unwrap();
        chunk(&mut out, b"").await.unwrap();
        assert_eq!(out, b"c\r\nhello world!\r\n0\r\n\r\n");
    }
}
