//! The relay role's endpoints for what a path does to a stream (T-325), which
//! `podssh doctor --stream` asks: `GET /v1/probe/drip`, a response whose bytes
//! go out at timed moments, and `POST /v1/probe/anything`, a body read as it
//! comes, answered with when each part of it came. Their paths and queries
//! are go-httpbin's `/drip` and `/anything` under `/v1/probe`, so that doctor
//! asks either server alike (`go-httpbin -prefix /v1/probe`). Their limits
//! are in `/relays.json` ([`limits`]), so that a client tells a cut of the
//! path from the server's own; behind a quick tunnel's node, the node's own
//! limits on what it passes ([`behind_node`]).
//!
//! They need no token: they dial nothing and keep nothing of a body. At most
//! [`MOST_AT_ONCE`] run together, and each has a bound on its time.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use podssh_ws::http::request::Request;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// The paths, under this prefix.
pub const PREFIX: &str = "/v1/probe";
/// The longest drip: its delay and its bytes' times together.
pub const DRIP_MAX: Duration = Duration::from_secs(600);
/// The most bytes of a drip.
pub const DRIP_MAX_BYTES: u64 = 64 * 1024;
/// The largest body that `/anything` takes; a larger one gets `413`.
pub const BODY_MAX: u64 = 8 << 20;
/// How long the next bytes of a body may take.
pub const BODY_WAIT: Duration = Duration::from_secs(60);
/// The probes that run together; past them, `503`.
pub const MOST_AT_ONCE: usize = 16;
/// A read within this of the one before is the same part of a body.
const SAME_PART: Duration = Duration::from_millis(50);
/// The parts that an answer names, at most; later reads join the last.
const PARTS_SHOWN: usize = 64;
/// How long a refused body is read and dropped: an answer written before
/// the body ended is lost to a reset when the rest of it stays unread.
const DRAIN_WAIT: Duration = Duration::from_secs(5);
/// What a drip sends, as go-httpbin's does.
const DRIP_BYTE: &[u8] = b"*";

/// The probes that run now.
static RUNNING: AtomicUsize = AtomicUsize::new(0);

tokio::task_local! {
    /// Set for a request that a quick tunnel's node gave the role.
    static BEHIND_NODE: bool;
}

/// Whether `path`, with no query, is a probe's.
pub fn serves(path: &str) -> bool {
    matches!(path, "/v1/probe/drip" | "/v1/probe/anything")
}

/// Serve `served`, one request that a quick tunnel's node gave the role
/// (T-428), so that its `/relays.json` names the node's own limits.
pub async fn behind_node<F: Future>(served: F) -> F::Output {
    BEHIND_NODE.scope(true, served).await
}

fn is_behind_node() -> bool {
    BEHIND_NODE.try_with(|behind| *behind).unwrap_or(false)
}

/// The limits of the probes, for `/relays.json`: what the server does
/// itself, so that what a client meets below them is the path's.
pub fn limits() -> Value {
    let drip_ms = DRIP_MAX.as_millis() as u64;
    let mut doc = json!({
        "paths": ["/v1/probe/drip", "/v1/probe/anything"],
        "drip_max_ms": drip_ms,
        "drip_max_bytes": DRIP_MAX_BYTES,
        "body_max_bytes": BODY_MAX,
        // A body is read as it comes, and each part's time is said.
        "body": "streamed",
        "quiet_max_ms": drip_ms,
        "at_once": MOST_AT_ONCE,
    });
    node_limits(&mut doc);
    doc
}

/// Behind a quick tunnel's node, what the node does to a request before the
/// role reads it: it takes a body whole, 32 KiB at most, and ends an answer
/// that goes quiet for 60 s (`crate::quick::origin`).
#[cfg(feature = "quick")]
fn node_limits(doc: &mut Value) {
    if is_behind_node() {
        doc["behind"] = json!("the node of a quick tunnel");
        doc["body"] = json!("whole");
        doc["body_max_bytes"] = json!(crate::quick::origin::BODY_MAX);
        doc["quiet_max_ms"] = json!(crate::quick::origin::ANSWER_WAIT.as_millis() as u64);
    }
}

#[cfg(not(feature = "quick"))]
fn node_limits(_: &mut Value) {
    let _ = is_behind_node();
}

/// One of the probes that run, given back to its count when it ends.
struct Turn(&'static AtomicUsize);

impl Turn {
    /// A turn of `count`, unless `most` run already.
    fn take(count: &'static AtomicUsize, most: usize) -> Option<Turn> {
        let mut now = count.load(Ordering::Relaxed);
        loop {
            if now >= most {
                return None;
            }
            match count.compare_exchange_weak(now, now + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Some(Turn(count)),
                Err(seen) => now = seen,
            }
        }
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serve the probe of `head` on `stream`, then end the connection.
pub async fn request<S>(mut stream: S, head: Request, pending: Vec<u8>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    let Some(_turn) = Turn::take(&RUNNING, MOST_AT_ONCE) else {
        let why = format!("{path}: {MOST_AT_ONCE} probes run already; ask again later");
        let reply = refusal(503, &why, &[("Retry-After", "10")]);
        return refuse(&mut stream, &head, pending.len(), reply).await;
    };
    match (head.method.as_str(), path.as_str()) {
        ("GET", "/v1/probe/drip") => drip(&mut stream, &head).await,
        ("POST" | "PUT", "/v1/probe/anything") => anything(&mut stream, &head, pending).await,
        (method, path) => {
            let allow = if path.ends_with("/drip") { "GET" } else { "POST" };
            let reply = refusal(405, &format!("{path}: not {method}, but {allow}"), &[("Allow", allow)]);
            refuse(&mut stream, &head, pending.len(), reply).await
        }
    }
}

/// What a drip asks: go-httpbin's query of `/drip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drip {
    /// From the first byte to the last.
    pub duration: Duration,
    /// Before the head.
    pub delay: Duration,
    pub bytes: u64,
    pub code: u16,
}

/// The drip of a request's target: `duration` (2 s), `delay` (2 s),
/// `numbytes` (10) and `code` (200), go-httpbin's names and defaults; `Err`
/// says which value is wrong.
pub fn drip_of(target: &str) -> Result<Drip, String> {
    let time = |key: &str, default: Duration| match query(target, key) {
        None => Ok(default),
        Some(text) => parse_duration(text)
            .ok_or_else(|| format!("{key}={text}: a number of seconds, or a time such as 2s or 500ms")),
    };
    let duration = time("duration", Duration::from_secs(2))?;
    let delay = time("delay", Duration::from_secs(2))?;
    let both = duration.checked_add(delay).filter(|both| *both <= DRIP_MAX);
    if both.is_none() {
        return Err(format!("duration and delay take {} s at most together", DRIP_MAX.as_secs()));
    }
    let bytes = match query(target, "numbytes") {
        None => 10,
        Some(text) => text
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=DRIP_MAX_BYTES).contains(n))
            .ok_or_else(|| format!("numbytes={text}: 1 to {DRIP_MAX_BYTES}"))?,
    };
    let code = match query(target, "code") {
        None => 200,
        Some(text) => text
            .parse::<u16>()
            .ok()
            .filter(|c| (200..=599).contains(c))
            .ok_or_else(|| format!("code={text}: a status from 200 to 599"))?,
    };
    Ok(Drip { duration, delay, bytes, code })
}

/// The value of `key` in the query of `target`.
fn query<'a>(target: &'a str, key: &str) -> Option<&'a str> {
    let (_, query) = target.split_once('?')?;
    query.split('&').find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
}

/// A time as go-httpbin reads one: a number of seconds (`2.5`), or Go's
/// form (`1500ms`, `2s`, `1m30s`).
pub fn parse_duration(text: &str) -> Option<Duration> {
    // Past this, a time is no probe's, and `from_secs_f64` would panic.
    const MOST: f64 = 1e9;
    if let Ok(secs) = text.parse::<f64>() {
        return (secs.is_finite() && (0.0..=MOST).contains(&secs)).then(|| Duration::from_secs_f64(secs));
    }
    let (mut rest, mut total) = (text, Duration::ZERO);
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
        let (number, after) = rest.split_at(digits);
        let value: f64 = number.parse().ok()?;
        let unit = after.find(|c: char| c.is_ascii_digit() || c == '.').unwrap_or(after.len());
        let (unit, next) = after.split_at(unit);
        let scale = match unit {
            "ns" => 1e-9,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        let secs = value * scale;
        if !secs.is_finite() || !(0.0..=MOST).contains(&secs) {
            return None;
        }
        total = total.checked_add(Duration::from_secs_f64(secs))?;
        rest = next;
    }
    Some(total)
}

/// The pause after each byte but the last, as go-httpbin's: the duration
/// over the gaps, rounded up, so that the last byte goes at its end.
pub fn pause_of(duration: Duration, bytes: u64) -> Duration {
    if bytes <= 1 {
        return duration;
    }
    let nanos = duration.as_nanos().div_ceil(u128::from(bytes - 1));
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

/// `GET /v1/probe/drip`: after `delay`, the head with the drip's length,
/// then its bytes one at a time, the first at once and the last at
/// `duration`, each written and flushed at its own moment.
async fn drip<S: AsyncWrite + Unpin>(stream: &mut S, head: &Request) {
    let asked = match drip_of(&head.target) {
        Ok(asked) => asked,
        Err(why) => return answer(stream, refusal(400, &format!("/v1/probe/drip: {why}"), &[])).await,
    };
    tokio::time::sleep(asked.delay).await;
    let top = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        asked.code,
        reason(asked.code),
        asked.bytes
    );
    if stream.write_all(top.as_bytes()).await.is_err() {
        return;
    }
    let pause = pause_of(asked.duration, asked.bytes);
    let started = Instant::now();
    for n in 0..asked.bytes {
        // Each byte at its own moment from the start, so that a late write
        // does not move the ones after it.
        let at = pause.checked_mul(n as u32).unwrap_or(asked.duration);
        tokio::time::sleep_until(started + at).await;
        if stream.write_all(DRIP_BYTE).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
    let _ = stream.shutdown().await;
}

/// The parts of a body as they came: reads less than [`SAME_PART`] apart
/// are one part.
#[derive(Debug, Default)]
pub struct Parts(Vec<Part>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Part {
    /// When its first read and its last came, from the request's head.
    pub from: Duration,
    pub to: Duration,
    pub bytes: u64,
}

impl Parts {
    pub fn add(&mut self, at: Duration, bytes: u64) {
        let full = self.0.len() >= PARTS_SHOWN;
        if let Some(last) = self.0.last_mut() {
            if full || at.saturating_sub(last.to) <= SAME_PART {
                last.to = at;
                last.bytes += bytes;
                return;
            }
        }
        self.0.push(Part { from: at, to: at, bytes });
    }

    pub fn parts(&self) -> &[Part] {
        &self.0
    }

    pub fn json(&self) -> Value {
        let ms = |d: Duration| d.as_millis() as u64;
        let parts: Vec<Value> =
            self.0.iter().map(|p| json!({ "from_ms": ms(p.from), "to_ms": ms(p.to), "bytes": p.bytes })).collect();
        Value::Array(parts)
    }
}

/// `POST /v1/probe/anything`: a body of its `Content-Length`, [`BODY_MAX`]
/// at most, read as it comes and dropped, answered with its length and its
/// parts: `{"bytes": N, "parts": [{"from_ms", "to_ms", "bytes"}, ...]}`, the
/// times from the end of the head.
async fn anything<S>(stream: &mut S, head: &Request, pending: Vec<u8>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let came = Instant::now();
    let length = head.header("content-length").and_then(|l| l.trim().parse::<u64>().ok());
    let Some(length) = length.filter(|_| head.header("transfer-encoding").is_none()) else {
        let reply = refusal(411, "/v1/probe/anything: a body with its Content-Length", &[]);
        return refuse(stream, head, pending.len(), reply).await;
    };
    if length > BODY_MAX {
        let reply = refusal(413, &format!("/v1/probe/anything: a body of {BODY_MAX} bytes at most"), &[]);
        return refuse(stream, head, pending.len(), reply).await;
    }
    let mut parts = Parts::default();
    let mut got = (pending.len() as u64).min(length);
    if got > 0 {
        parts.add(Duration::ZERO, got);
    }
    let mut buf = vec![0u8; 64 * 1024];
    while got < length {
        match tokio::time::timeout(BODY_WAIT, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let n = (n as u64).min(length - got);
                got += n;
                parts.add(came.elapsed(), n);
            }
            // The client left: nobody to answer.
            Ok(_) => return,
            Err(_) => {
                let why = format!("/v1/probe/anything: no byte of the body for {} s", BODY_WAIT.as_secs());
                return answer(stream, refusal(408, &why, &[])).await;
            }
        }
    }
    let body = json!({ "bytes": got, "parts": parts.json() });
    answer(stream, super::docs::json(&body)).await;
}

/// The status line's words for each status that the probes send.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        other => podssh_ws::http::request::reason(other),
    }
}

/// A refusal of `status`, its words on one line as its body, and `headers`.
fn refusal(status: u16, words: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let body = format!("{}\n", podssh_ws::text::one_line(words));
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n");
    out.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()));
    out.into_bytes()
}

/// Write `reply` to a request that may have a body, then read and drop what
/// is left of the body for [`DRAIN_WAIT`] at most, so that the client reads
/// the refusal before the end of the connection.
async fn refuse<S>(stream: &mut S, head: &Request, pending: usize, reply: Vec<u8>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if stream.write_all(&reply).await.is_err() || stream.flush().await.is_err() {
        return;
    }
    let length = head.header("content-length").and_then(|l| l.trim().parse::<u64>().ok()).unwrap_or(0);
    let mut left = length.saturating_sub(pending as u64);
    let mut buf = vec![0u8; 64 * 1024];
    let drain = async {
        while left > 0 {
            match stream.read(&mut buf).await {
                Ok(n) if n > 0 => left = left.saturating_sub(n as u64),
                _ => break,
            }
        }
    };
    let _ = tokio::time::timeout(DRAIN_WAIT, drain).await;
    let _ = stream.shutdown().await;
}

/// Write `reply`, then end the connection.
async fn answer<S: AsyncWrite + Unpin>(stream: &mut S, reply: Vec<u8>) {
    let _ = stream.write_all(&reply).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
