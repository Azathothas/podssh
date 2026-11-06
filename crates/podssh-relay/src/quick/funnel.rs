//! `podssh funnel TARGET` (T-180): a local HTTP service at the public name
//! of a quick tunnel, as Tailscale's funnel publishes one. The node's origin
//! is TARGET itself, for each path: each request of a visitor goes to a new
//! connection of TARGET as HTTP/1.1 with `Connection: close`, so that its end
//! is the answer's end; the answer's head goes to the edge, and its body as
//! it comes, a chunked one decoded as a stream ([`super::chunks`]), as the
//! edge takes a body's bytes alone. A WebSocket's upgrade passes to TARGET,
//! and after its 101 the frames pass both ways untouched. podssh reads the
//! heads, never a body: TLS ends at Cloudflare's edge, which can read each
//! byte, and the node says so.
//!
//! TARGET is dialed by the caller's [`Dial`]: TCP, a Unix socket or a
//! program's stdin and stdout (`podssh pipe`'s addresses), so that a node in
//! a cage where loopback is refused still serves a socket or a program.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use super::chunks::Chunks;
use super::origin::{Origin, PIPE};

/// The line that each funnel says: who can read its traffic.
pub const TLS_LINE: &str = "TLS ends at Cloudflare's edge; Cloudflare can read this traffic.";
/// The longest head of a request or of TARGET's answer.
const MAX_HEAD: usize = 64 * 1024;

/// A connection to TARGET: any stream that reads and writes.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// A new connection to TARGET, or why none came.
pub type Dialed = Pin<Box<dyn Future<Output = Result<Box<dyn Stream>, String>> + Send>>;
/// How a funnel dials TARGET, once for each request.
pub type Dial = Arc<dyn Fn() -> Dialed + Send + Sync>;
/// Where a funnel says each request that TARGET did not take.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The origin of a funnel: TARGET, for each path.
pub struct Funnel {
    dial: Dial,
    say: Say,
}

impl Funnel {
    pub fn new(dial: Dial, say: Say) -> Funnel {
        Funnel { dial, say }
    }
}

impl Origin for Funnel {
    fn serves(&self, _: &str) -> bool {
        true
    }

    fn connect(&self, _: Option<std::net::IpAddr>) -> DuplexStream {
        let (theirs, ours) = tokio::io::duplex(PIPE);
        let (dial, say) = (self.dial.clone(), self.say.clone());
        tokio::spawn(async move {
            if let Err(why) = carry(ours, dial).await {
                say(why);
            }
        });
        theirs
    }

    fn streams(&self) -> bool {
        true
    }
}

/// One request from `edge`, the node's side of the origin's pipe, to a new
/// connection of TARGET, and its answer back.
async fn carry(mut edge: DuplexStream, dial: Dial) -> Result<(), String> {
    let (head, rest) = read_head(&mut edge).await?;
    let websocket = upgrades(&head);
    let head = if websocket { head } else { closing(&head) };
    let target = match dial().await {
        Ok(target) => target,
        Err(why) => {
            let body = format!("podssh funnel: TARGET did not answer: {why}\n");
            let answer = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = edge.write_all(answer.as_bytes()).await;
            let _ = edge.shutdown().await;
            return Err(format!("a request found no TARGET: {why}"));
        }
    };
    let (mut from_target, mut to_target) = tokio::io::split(target);
    let (mut from_edge, mut to_edge) = tokio::io::split(edge);
    // The request's body, or the visitor's frames, as they come; TARGET's
    // input ends with the visitor's side, as an end of a WebSocket does.
    let up = async move {
        if to_target.write_all(&head).await.is_err() || to_target.write_all(&rest).await.is_err() {
            return;
        }
        let _ = tokio::io::copy(&mut from_edge, &mut to_target).await;
        let _ = to_target.shutdown().await;
    };
    let down = async move {
        let (head, rest) = match answer_head(&mut from_target).await {
            Ok(answered) => answered,
            Err(why) => {
                let _ = to_edge.shutdown().await;
                return Err(why);
            }
        };
        let switched = status_of(&head) == Some(101);
        if switched || !chunked(&head) {
            // A length, an end at the close, or a WebSocket's frames: as they are.
            to_edge.write_all(&head).await.map_err(|e| e.to_string())?;
            to_edge.write_all(&rest).await.map_err(|e| e.to_string())?;
            let _ = tokio::io::copy(&mut from_target, &mut to_edge).await;
        } else {
            to_edge.write_all(&unchunked(&head)).await.map_err(|e| e.to_string())?;
            decode(rest, &mut from_target, &mut to_edge).await?;
        }
        let _ = to_edge.shutdown().await;
        Ok::<(), String>(())
    };
    let (_, down) = tokio::join!(up, down);
    down
}

/// A head that ends with CRLF CRLF from `from`, and the bytes read past it.
async fn read_head<R: AsyncRead + Unpin>(from: &mut R) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (mut got, mut chunk) = (Vec::new(), [0u8; 4096]);
    loop {
        if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = got.split_off(at + 4);
            return Ok((got, rest));
        }
        if got.len() > MAX_HEAD {
            return Err(format!("no end of a head within {} KiB", MAX_HEAD / 1024));
        }
        let n = from.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("the connection closed before a whole head".into());
        }
        got.extend_from_slice(&chunk[..n]);
    }
}

/// TARGET's answer's head: an interim answer (`100 Continue`, `103 Early
/// Hints`) is dropped, as the edge has one answer for a request; a 101 is
/// the answer.
async fn answer_head<R: AsyncRead + Unpin>(from: &mut R) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut carried = Vec::new();
    loop {
        let (head, rest) = match carried.windows(4).position(|w: &[u8]| w == b"\r\n\r\n") {
            Some(at) => {
                let rest = carried.split_off(at + 4);
                (std::mem::take(&mut carried), rest)
            }
            None => {
                let mut joined = Chained { first: std::mem::take(&mut carried), from: &mut *from };
                read_head(&mut joined).await.map_err(|e| format!("TARGET's answer: {e}"))?
            }
        };
        match status_of(&head) {
            Some(s) if (100..200).contains(&s) && s != 101 => carried = rest,
            Some(_) => return Ok((head, rest)),
            None => return Err("TARGET's answer is not HTTP/1.1".into()),
        }
    }
}

/// Bytes already read, then a reader.
struct Chained<'a, R> {
    first: Vec<u8>,
    from: &'a mut R,
}

impl<R: AsyncRead + Unpin> AsyncRead for Chained<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.first.is_empty() {
            let n = self.first.len().min(buf.remaining());
            buf.put_slice(&self.first[..n]);
            self.first.drain(..n);
            return std::task::Poll::Ready(Ok(()));
        }
        Pin::new(&mut *self.from).poll_read(cx, buf)
    }
}

/// The lines of a head, the first one aside.
fn fields(head: &[u8]) -> impl Iterator<Item = (String, String)> + '_ {
    let text = std::str::from_utf8(head).unwrap_or_default();
    text.split("\r\n").skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
    })
}

/// Whether a request's head asks for a WebSocket.
fn upgrades(head: &[u8]) -> bool {
    fields(head).any(|(name, value)| name == "upgrade" && value.eq_ignore_ascii_case("websocket"))
}

/// The status of an answer's head.
fn status_of(head: &[u8]) -> Option<u16> {
    let line = head.split(|b| *b == b'\r').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut words = line.split(' ');
    if !words.next()?.starts_with("HTTP/1.") {
        return None;
    }
    words.next()?.parse().ok()
}

/// Whether an answer's body is chunked.
fn chunked(head: &[u8]) -> bool {
    fields(head).any(|(name, value)| name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked"))
}

/// `head` with each of `drop`'s fields taken out, and `add` before its end.
fn rewritten(head: &[u8], drop: &[&str], add: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.trim_end_matches("\r\n").split("\r\n");
    let mut out = format!("{}\r\n", lines.next().unwrap_or_default());
    for line in lines {
        let name = line.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        if !drop.contains(&name.as_str()) {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out.push_str(add);
    out.push_str("\r\n");
    out.into_bytes()
}

/// A request's head with `Connection: close`: TARGET's close ends its answer.
fn closing(head: &[u8]) -> Vec<u8> {
    rewritten(head, &["connection", "keep-alive"], "Connection: close\r\n")
}

/// An answer's head with no `Transfer-Encoding`: its body goes decoded, and
/// ends at the close.
fn unchunked(head: &[u8]) -> Vec<u8> {
    rewritten(head, &["transfer-encoding", "content-length"], "")
}

/// A chunked body from `rest` and `from`, its data to `to` as it comes,
/// until its last chunk.
async fn decode<R, W>(rest: Vec<u8>, from: &mut R, to: &mut W) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut chunks, mut out, mut buf) = (Chunks::default(), Vec::new(), vec![0u8; PIPE]);
    let mut input = rest;
    loop {
        chunks.feed(&input, &mut out).map_err(|e| format!("TARGET's chunked body: {e}"))?;
        if !out.is_empty() {
            to.write_all(&out).await.map_err(|e| e.to_string())?;
            out.clear();
        }
        if chunks.done() {
            return Ok(());
        }
        let n = from.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("TARGET closed within its chunked body".into());
        }
        input = buf[..n].to_vec();
    }
}

#[cfg(test)]
#[path = "funnel_tests.rs"]
mod tests;
