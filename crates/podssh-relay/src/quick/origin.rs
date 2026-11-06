//! What a quick tunnel's node serves (T-428): each visitor's WebSocket, as
//! a stream of its messages' bytes, for the node's TARGET; and, for a node
//! that is also its owner's relay, an origin of HTTP/1.1 in this process,
//! the relay role, for the paths that it serves, in place of the 404.
//!
//! The edge's request goes to the origin as cloudflared's proxy sends one to
//! an origin of HTTP (`proxy/proxy.go` at 2026.10.6): the visitor's headers
//! but those of one hop, the three headers of the upgrade for a WebSocket,
//! and a body with its length. The answer goes back as cloudflared's writer
//! sends an origin's ([`Answer::passed`]); after a 101 the WebSocket's frames
//! pass as they are, both ways, as the edge passes them unchanged, so the
//! origin is the WebSocket's server. Nothing listens: each request is a pipe
//! in this process.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, DuplexStream};

/// The buffer of each pipe to the origin, each way.
pub const PIPE: usize = 64 * 1024;
/// The largest body of a request that is no upgrade: the relay's are `{}`
/// or a key's proof, 4 KiB at most. With a head of 16 KiB it fits in the
/// pipe, so the origin's early refusal reaches the edge whole.
pub const BODY_MAX: usize = 32 * 1024;
/// How long the edge has for a request's body.
pub const BODY_WAIT: Duration = Duration::from_secs(30);
/// How long the origin has for its answer's head, and for each read of its
/// body: the role dials a target within 10 s, and `/trace` waits 5 s more
/// for the target's first line.
pub const ANSWER_WAIT: Duration = Duration::from_secs(60);
/// How long the origin's last bytes may take once the visitor's side ended.
pub const END_WAIT: Duration = Duration::from_secs(10);
/// The longest head of the origin's answer, as of each answer podssh reads.
const MAX_HEAD: usize = 16 * 1024;

/// An origin of HTTP/1.1 in this process, which reads one request on each
/// connection and closes it after its answer.
pub trait Origin: Send + Sync {
    /// Whether the request for `path`, with no query, is the origin's.
    fn serves(&self, path: &str) -> bool;
    /// A new connection to the origin, for the visitor whose address the
    /// edge named (`CF-Connecting-IP`), if it named one. It must be called
    /// in a runtime: the origin serves it in a task of its own.
    fn connect(&self, visitor: Option<std::net::IpAddr>) -> DuplexStream;
    /// Whether the origin takes a request's body as it comes, with no
    /// bound: a funnel's TARGET, a web application, may take an upload of
    /// any size (T-180). The relay role's bodies are small, and come whole
    /// first ([`BODY_MAX`]).
    fn streams(&self) -> bool {
        false
    }
}

/// How the head of a request says the length of its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyHead {
    /// `Content-Length`.
    Length(usize),
    /// `Transfer-Encoding: chunked`: a body whose length the visitor did
    /// not name, which goes in chunks as it comes.
    Chunked,
}

/// The visitor's address that the edge names in `CF-Connecting-IP`, one
/// address and nothing else. The edge sets it on each request; it only says
/// whom the relay role's brake counts a request for, never who may mint.
pub fn visitor_of<'a>(mut fields: impl Iterator<Item = (&'a str, &'a str)>) -> Option<std::net::IpAddr> {
    let (_, value) = fields.find(|(name, _)| name.eq_ignore_ascii_case("cf-connecting-ip"))?;
    value.trim().parse().ok()
}

/// What a node gives each visitor's WebSocket, and the origin of the paths
/// that it does not give to them.
pub trait Visit {
    /// The task of one visitor.
    type Task: Future<Output = ()> + Send + 'static;
    /// One visitor's WebSocket, as a stream of its messages' bytes.
    fn visit(&mut self, stream: DuplexStream) -> Self::Task;
    /// The origin, for a node that has one.
    fn origin(&self) -> Option<Arc<dyn Origin>> {
        None
    }
}

/// A closure is a node with no origin: each request but a visitor's
/// WebSocket gets 404, as before T-428.
impl<V, F> Visit for V
where
    V: FnMut(DuplexStream) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    type Task = F;

    fn visit(&mut self, stream: DuplexStream) -> F {
        (*self)(stream)
    }
}

/// The visitors of `visit`, and the paths that `origin` serves in their
/// place.
#[derive(Clone)]
pub struct Visitors<V> {
    pub visit: V,
    pub origin: Option<Arc<dyn Origin>>,
}

impl<V: Visit> Visit for Visitors<V> {
    type Task = V::Task;

    fn visit(&mut self, stream: DuplexStream) -> V::Task {
        self.visit.visit(stream)
    }

    fn origin(&self) -> Option<Arc<dyn Origin>> {
        self.origin.clone()
    }
}

/// `origin` when it serves `path`, the path of a request target.
pub fn taking(origin: &Option<Arc<dyn Origin>>, path: &str) -> Option<Arc<dyn Origin>> {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    origin.as_ref().filter(|origin| origin.serves(path)).cloned()
}

/// The headers of one hop, which the origin's connection does not take from
/// the edge (RFC 9110, section 7.6.1), and those that the head sets itself.
const HOP: &[&str] =
    &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "host"];
/// The headers of a WebSocket's head, set as cloudflared's proxy sets them
/// for an origin, whatever the visitor sent.
const UPGRADE: &[(&str, &str)] =
    &[("Connection", "Upgrade"), ("Upgrade", "websocket"), ("Sec-WebSocket-Version", "13")];

/// The edge's request, as the origin takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub method: String,
    /// The path and the query, as the visitor sent them.
    pub target: String,
    /// The name that the visitor asked for: its Host.
    pub host: String,
    /// The headers as the edge passed them, in their order.
    pub headers: Vec<(String, String)>,
    /// A WebSocket's upgrade, with no body.
    pub websocket: bool,
}

impl Asked {
    /// The head of HTTP/1.1 for the origin, with `length`, the body's, for a
    /// request that is no upgrade. `Err` for a part that would break the
    /// head or be read two ways, which the edge's metadata does not rule out.
    pub fn head(&self, length: usize) -> Result<Vec<u8>, String> {
        self.head_with(BodyHead::Length(length))
    }

    /// [`Asked::head`] with the body's length as `body` says it.
    pub fn head_with(&self, body: BodyHead) -> Result<Vec<u8>, String> {
        if self.method.is_empty() || !self.method.bytes().all(is_tchar) {
            return Err("the method is not a token".into());
        }
        if !self.target.starts_with('/') || !self.target.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("the request's path is not a path of ASCII".into());
        }
        if self.host.is_empty() || !self.host.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("the request names no host".into());
        }
        let mut head = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", self.method, self.target, self.host);
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            // The edge's own, those of one hop, and those that the head sets.
            let set = lower == "content-length" || (self.websocket && lower == "sec-websocket-version");
            if lower.starts_with("cf-cloudflared-") || lower.starts_with(':') || HOP.contains(&lower.as_str()) || set {
                continue;
            }
            if name.is_empty() || !name.bytes().all(is_tchar) {
                return Err("a header's name is not a token".into());
            }
            if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
                return Err(format!("the header {lower} holds a control byte"));
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if self.websocket {
            for (name, value) in UPGRADE {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
        } else {
            match body {
                BodyHead::Length(length) => head.push_str(&format!("Content-Length: {length}\r\n")),
                BodyHead::Chunked => head.push_str("Transfer-Encoding: chunked\r\n"),
            }
        }
        head.push_str("\r\n");
        Ok(head.into_bytes())
    }
}

/// A character of a token (RFC 9110, section 5.6.2).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The headers of one hop in an answer, which the edge does not take.
const HOP_ANSWER: &[&str] =
    &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade"];
/// The headers of a 101 that a visitor's client needs (cloudflared's
/// `IsWebsocketClientHeader`).
const SWITCHED: &[&str] = &["connection", "upgrade", "sec-websocket-accept"];

/// The head of the origin's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    /// Names in lower case, values trimmed, in the origin's order.
    pub headers: Vec<(String, String)>,
}

impl Answer {
    /// Whether the origin took the upgrade: the WebSocket's frames follow.
    pub fn switched(&self) -> bool {
        self.status == 101
    }

    /// The headers that go to the edge, as cloudflared's writer passes an
    /// origin's: each but those of one hop, and for a 101 the three that the
    /// visitor's client needs.
    pub fn passed(&self) -> Vec<(&str, &str)> {
        let kept = |name: &str| (self.switched() && SWITCHED.contains(&name)) || !HOP_ANSWER.contains(&name);
        self.headers.iter().filter(|(name, _)| kept(name)).map(|(n, v)| (n.as_str(), v.as_str())).collect()
    }

    /// The length of its body, as it names it.
    pub fn length(&self) -> Option<&str> {
        self.headers.iter().find(|(name, _)| name == "content-length").map(|(_, value)| value.as_str())
    }
}

/// The head of the origin's answer from `from`, and the bytes read past it.
pub async fn read_answer<R: AsyncRead + Unpin>(from: &mut R) -> Result<(Answer, Vec<u8>), String> {
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if got.len() > MAX_HEAD {
            return Err(format!("no end of the origin's head within {} KiB", MAX_HEAD / 1024));
        }
        let n = from.read(&mut chunk).await.map_err(|e| format!("the origin's answer: {e}"))?;
        if n == 0 {
            return Err("the origin closed before its answer".into());
        }
        got.extend_from_slice(&chunk[..n]);
    };
    let rest = got.split_off(end);
    let (status, _, headers) = podssh_ws::http::parse_head(&String::from_utf8_lossy(&got))?;
    Ok((Answer { status, headers }, rest))
}

#[cfg(test)]
#[path = "origin_tests.rs"]
mod tests;
