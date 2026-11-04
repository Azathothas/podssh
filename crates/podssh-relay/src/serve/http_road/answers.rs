//! The answers of the HTTP road's sessions (`crate::http_road`, the wire):
//! a batch up, stored once by its number; the bytes down from an offset,
//! in an answer that streams them and ends a moment after nothing more came;
//! both in one whole answer for the serial form; the end. Each answer says
//! the batches that the target took (`X-Ack`), and a refusal's words start
//! with the road's word, as each error of the relay starts with its path's.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request::Request;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::sessions::{Ready, Session, Stored};
use crate::http_road::{close_value, Query, ACK, CLOSE, DOWN_MAX, OFFSET, WAIT_MAX};

/// How long a body's next bytes may take.
const BODY_WAIT: Duration = Duration::from_secs(30);
/// The bytes of one chunk of an answer down.
const CHUNK: usize = 32 * 1024;
/// How long an answer down waits for more bytes, once it sent each that
/// was there, before it ends.
const LINGER: Duration = Duration::from_millis(20);

/// The reason phrase of each status that the road answers with.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Content Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// A whole answer of `status`, with `headers` and `body` of the type
/// `kind`; with `keep`, its connection goes on after it.
pub fn whole(status: u16, headers: &[(&str, String)], body: &[u8], kind: &str, keep: bool) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {}\r\nCache-Control: no-store\r\n", reason(status));
    for (name, value) in headers {
        out.push_str(&format!("{name}: {}\r\n", podssh_ws::text::one_line(value)));
    }
    // A 204 has no body, and says no length (RFC 9110, section 8.6).
    if status != 204 {
        if !body.is_empty() {
            out.push_str(&format!("Content-Type: {kind}\r\n"));
        }
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    if !keep {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A refusal of `status` with `words`, as text.
pub fn refuse(status: u16, words: &str, headers: &[(&str, String)], keep: bool) -> Vec<u8> {
    let body = format!("{}\n", podssh_ws::text::one_line(words));
    whole(status, headers, body.as_bytes(), "text/plain; charset=utf-8", keep)
}

/// `410` for a session that ended, with its code and reason in `X-Close`.
fn gone(session: &Session, at: Option<u64>, keep: bool) -> Vec<u8> {
    let (code, why) = session.ended().unwrap_or((1000, String::new()));
    let mut headers = vec![(CLOSE, close_value(code, &why)), (ACK, session.acked().to_string())];
    headers.extend(at.map(|at| (OFFSET, at.to_string())));
    refuse(410, &format!("http: the session ended: {code} {why}"), &headers, keep)
}

/// `204`: nothing down yet.
fn nothing(session: &Session, at: u64, keep: bool) -> Vec<u8> {
    whole(204, &[(OFFSET, at.to_string()), (ACK, session.acked().to_string())], &[], "", keep)
}

/// Write `reply`: `Some(keep)` once it went, `None` when the client is gone.
pub async fn write<S: AsyncWrite + Unpin>(stream: &mut S, reply: Vec<u8>, keep: bool) -> Option<bool> {
    if stream.write_all(&reply).await.is_err() || stream.flush().await.is_err() {
        return None;
    }
    Some(keep)
}

/// The body of `head`, `max` bytes at most, its first bytes in `pending`:
/// the body, and the bytes after it, which are the next request's. `Err`
/// holds the refusal, or `None` for a client that went away.
pub async fn body<S: AsyncRead + Unpin>(
    stream: &mut S,
    head: &Request,
    mut pending: Vec<u8>,
    max: usize,
) -> Result<(Vec<u8>, Vec<u8>), Option<(u16, String)>> {
    if head.has("transfer-encoding") {
        return Err(Some((411, "http: a batch goes with its Content-Length".into())));
    }
    let length = match head.header("content-length") {
        None => 0,
        Some(value) => match value.parse::<usize>() {
            Ok(length) => length,
            Err(_) => return Err(Some((400, "http: a length that is no number".into()))),
        },
    };
    if length > max {
        return Err(Some((413, format!("http: a body of {max} bytes at most"))));
    }
    let mut chunk = vec![0u8; 16 * 1024];
    while pending.len() < length {
        match tokio::time::timeout(BODY_WAIT, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => pending.extend_from_slice(&chunk[..n]),
            _ => return Err(None),
        }
    }
    let rest = pending.split_off(length);
    Ok((pending, rest))
}

/// The answer to a batch that was not stored, or `None` once it was.
fn not_stored(session: &Session, stored: Stored, seq: u64, keep: bool) -> Option<Vec<u8>> {
    let acked = || (ACK, session.acked().to_string());
    match stored {
        Stored::Taken => None,
        Stored::Full => {
            let why = "http: the target has not taken the batches before it";
            Some(refuse(503, why, &[acked(), ("Retry-After", "1".to_string())], keep))
        }
        Stored::Conflict(next) => {
            let why = format!("http: the batch {seq} came, where the next is {next}");
            Some(refuse(409, &why, &[acked()], keep))
        }
        Stored::Ended => Some(gone(session, None, keep)),
    }
}

/// `POST .../up?seq=N[&fin=1]`: one batch, stored once.
pub async fn up<S>(stream: &mut S, session: &Arc<Session>, q: Query, batch: Vec<u8>, keep: bool) -> Option<bool>
where
    S: AsyncWrite + Unpin,
{
    let Some(seq) = q.seq else {
        return write(stream, refuse(400, "http: a batch takes seq=N", &[], keep), keep).await;
    };
    let stored = session.store(seq, batch, q.fin).await;
    let reply = not_stored(session, stored, seq, keep)
        .unwrap_or_else(|| whole(204, &[(ACK, session.acked().to_string())], &[], "", keep));
    write(stream, reply, keep).await
}

/// `GET .../down?at=OFFSET&wait=MS`: the target's bytes from OFFSET, which
/// says that each byte before it came. With bytes there, a `200` that
/// streams them, in chunks on a kept connection and to its end on another,
/// until nothing more came for a moment or `DOWN_MAX` went; else, after the
/// wait, a whole `204`.
pub async fn down<S>(stream: &mut S, session: &Arc<Session>, q: Query, keep: bool) -> Option<bool>
where
    S: AsyncWrite + Unpin,
{
    let generation = session.newest();
    let Some(at) = q.at else {
        return write(stream, refuse(400, "http: the bytes down take at=OFFSET", &[], keep), keep).await;
    };
    if let Err(why) = session.ack(at) {
        return write(stream, refuse(409, &why, &[], keep), keep).await;
    }
    let wait = Duration::from_millis(q.wait_ms.unwrap_or(0)).min(WAIT_MAX);
    match session.ready(at, wait, Some(generation)).await {
        Ready::Bytes => {}
        Ready::Nothing => return write(stream, nothing(session, at, keep), keep).await,
        Ready::Done => {
            session.end(1000, "target closed");
            return write(stream, gone(session, Some(at), keep), keep).await;
        }
        Ready::Ended => return write(stream, gone(session, Some(at), keep), keep).await,
    }
    let framing = if keep { "Transfer-Encoding: chunked\r\n" } else { "Connection: close\r\n" };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\n{OFFSET}: {at}\r\n\
         {framing}\r\n"
    );
    if stream.write_all(head.as_bytes()).await.is_err() {
        return None;
    }
    let (mut pos, mut sent) = (at, 0usize);
    while sent < DOWN_MAX {
        let bytes = session.take_from(pos, CHUNK.min(DOWN_MAX - sent));
        if bytes.is_empty() {
            // A moment for more, then the end: a hop that holds an answer to
            // its end holds a short one.
            match session.ready(pos, LINGER, Some(generation)).await {
                Ready::Bytes => continue,
                _ => break,
            }
        }
        let framed = if keep { chunk(&bytes) } else { bytes.clone() };
        if stream.write_all(&framed).await.is_err() || stream.flush().await.is_err() {
            return None;
        }
        session.progress();
        pos += bytes.len() as u64;
        sent += bytes.len();
    }
    if keep && (stream.write_all(b"0\r\n\r\n").await.is_err() || stream.flush().await.is_err()) {
        return None;
    }
    Some(keep)
}

/// One chunk of a body in chunks: its size in hex, its bytes, CRLF.
fn chunk(bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", bytes.len()).into_bytes();
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
    out
}

/// `POST .../x?[seq=N&]at=OFFSET&wait=MS[&fin=1]`, the serial form: the
/// batch, when one came, then the bytes down from OFFSET in a whole answer.
/// An exchange that carried a batch does not wait for bytes down, so that
/// the next batch goes at once.
pub async fn exchange<S>(stream: &mut S, session: &Arc<Session>, q: Query, batch: Vec<u8>, keep: bool) -> Option<bool>
where
    S: AsyncWrite + Unpin,
{
    match q.seq {
        Some(seq) => {
            let stored = session.store(seq, batch, q.fin).await;
            if let Some(reply) = not_stored(session, stored, seq, keep) {
                return write(stream, reply, keep).await;
            }
        }
        None if !batch.is_empty() => {
            return write(stream, refuse(400, "http: a batch takes seq=N", &[], keep), keep).await;
        }
        None => {}
    }
    let Some(at) = q.at else {
        return write(stream, refuse(400, "http: an exchange takes at=OFFSET", &[], keep), keep).await;
    };
    if let Err(why) = session.ack(at) {
        return write(stream, refuse(409, &why, &[], keep), keep).await;
    }
    let asked = Duration::from_millis(q.wait_ms.unwrap_or(0)).min(WAIT_MAX);
    let wait = if q.seq.is_some() { Duration::ZERO } else { asked };
    let reply = match session.ready(at, wait, None).await {
        Ready::Bytes => {
            let bytes = session.take_from(at, DOWN_MAX);
            session.progress();
            let headers = [(OFFSET, at.to_string()), (ACK, session.acked().to_string())];
            whole(200, &headers, &bytes, "application/octet-stream", keep)
        }
        Ready::Nothing => nothing(session, at, keep),
        Ready::Done => {
            session.end(1000, "target closed");
            gone(session, Some(at), keep)
        }
        Ready::Ended => gone(session, Some(at), keep),
    };
    write(stream, reply, keep).await
}

/// `POST .../close`: the session ends at once.
pub async fn close<S: AsyncWrite + Unpin>(stream: &mut S, session: &Arc<Session>, keep: bool) -> Option<bool> {
    session.end(1000, "client closed");
    write(stream, whole(204, &[], &[], "", keep), keep).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_204_says_no_length_and_a_refusal_its_words_and_its_end() {
        let none = String::from_utf8(whole(204, &[(ACK, "3".to_string())], &[], "", true)).unwrap();
        assert_eq!(none, "HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\nX-Ack: 3\r\n\r\n");
        let refused = String::from_utf8(refuse(404, "http: no such session", &[], false)).unwrap();
        assert!(refused.starts_with("HTTP/1.1 404 Not Found\r\n"), "{refused}");
        assert!(
            refused.contains("Content-Length: 22\r\nConnection: close\r\n\r\nhttp: no such session\n"),
            "{refused}"
        );
        assert_eq!(chunk(b"hello"), b"5\r\nhello\r\n");
    }
}
