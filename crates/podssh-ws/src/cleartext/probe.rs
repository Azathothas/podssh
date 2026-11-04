//! The probe of GitHub #56 (T-326): a host's port through the proxy when
//! one is set (a CONNECT, as each road dials), then `GET /health` with no
//! TLS, no token and no target, and what came back, named: a reset or a
//! close with nothing (a hop that expects TLS cuts cleartext), a record of
//! TLS (the far end speaks TLS alone there), an answer of HTTP (the edge's
//! refusal of cleartext, a refusal by policy, a redirect, or an answer), or
//! a silence. One connection, each wait within its bound.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cut::Cut;
use crate::dial::{self, DialError, ProxyChoice};

/// The path that the probe asks for: a relay's `/health`, which podssh's
/// relay role serves in cleartext too.
pub const PROBE_PATH: &str = "/health";

/// The words of a server that serves TLS alone on the port, in its answer of
/// 400 to a request of plain HTTP there, as nginx says them.
pub const PLAIN_TO_TLS: &str = "plain HTTP request was sent to HTTPS port";

/// The largest body that the probe reads.
const MAX_BODY: usize = 16 * 1024;

/// What a probe heard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Heard {
    /// The dial or the proxy's CONNECT failed: nothing went in cleartext.
    Unreached(DialError),
    /// The connection ended with no answer: reset, or closed with nothing.
    Cut(Cut),
    /// Nothing came within the bound.
    Silent(Duration),
    /// A record of TLS came back: the far end speaks TLS alone on the port.
    Tls,
    /// An answer of HTTP: its status, its reason in one line, the
    /// `Location` of a redirect with no query, and the start of its body.
    Answered { status: u16, reason: String, location: Option<String>, body: Vec<u8> },
    /// Bytes that are neither HTTP nor TLS, in one line.
    Other(String),
}

impl Heard {
    /// Whether the far end said that the port serves TLS alone: a `400` in
    /// the words of [`PLAIN_TO_TLS`].
    pub fn plain_to_tls(&self) -> bool {
        matches!(self, Heard::Answered { status: 400, reason, body, .. }
            if holds(reason.as_bytes(), PLAIN_TO_TLS) || holds(body, PLAIN_TO_TLS))
    }

    /// Whether the path carried cleartext both ways to a server that took
    /// it: an answer of HTTP that is neither the refusal of cleartext of
    /// [`Heard::plain_to_tls`], nor a redirect, nor a refusal by policy.
    pub fn passed(&self) -> bool {
        match self {
            Heard::Answered { status, .. } => !(300..400).contains(status) && *status != 403 && !self.plain_to_tls(),
            _ => false,
        }
    }

    /// What came back, in a few words for a line.
    pub fn words(&self) -> String {
        match self {
            Heard::Unreached(e) => format!("not reached: {e}"),
            Heard::Cut(Cut::Reset) => "reset, with no answer: a hop that expects TLS cuts cleartext".into(),
            Heard::Cut(Cut::Closed) => "closed with no answer: a hop that expects TLS ends cleartext".into(),
            Heard::Cut(cut) => format!("cut with no answer ({})", cut.words()),
            Heard::Silent(after) => format!("no answer within {} s", after.as_secs()),
            Heard::Tls => "a record of TLS came back: the far end speaks TLS alone on this port".into(),
            Heard::Answered { status, .. } if self.plain_to_tls() => {
                format!("the edge's refusal: HTTP {status}, the plain HTTP request was sent to its HTTPS port")
            }
            Heard::Answered { status, location: Some(to), .. } if (300..400).contains(status) => {
                format!("a redirect: HTTP {status} to {to}")
            }
            Heard::Answered { status: 403, reason, .. } => {
                format!("a refusal by policy: {}", status_words(403, reason))
            }
            Heard::Answered { status, reason, .. } if (200..300).contains(status) => {
                format!("an answer: {}", status_words(*status, reason))
            }
            Heard::Answered { status, reason, .. } => format!("a refusal: {}", status_words(*status, reason)),
            Heard::Other(seen) => format!("bytes that are neither HTTP nor TLS: {seen}"),
        }
    }
}

/// `HTTP 403 Forbidden`, or `HTTP 403` with no reason.
fn status_words(status: u16, reason: &str) -> String {
    match reason.is_empty() {
        true => format!("HTTP {status}"),
        false => format!("HTTP {status} {reason}"),
    }
}

/// Whether `bytes` hold `words`, in any case.
fn holds(bytes: &[u8], words: &str) -> bool {
    bytes.windows(words.len()).any(|w| w.eq_ignore_ascii_case(words.as_bytes()))
}

/// Ask `host:port` for [`PROBE_PATH`] in cleartext, through `proxy`, each
/// wait within `wait`: what came back.
pub async fn probe(host: &str, port: u16, proxy: &ProxyChoice, wait: Duration) -> Heard {
    let mut tcp = match dial::dial(host, port, proxy, wait).await {
        Ok(tcp) => tcp,
        Err(e) => return Heard::Unreached(e),
    };
    // No token, no target and no cookie: what each hop may read.
    let request = format!(
        "GET {PROBE_PATH} HTTP/1.1\r\nHost: {}\r\nUser-Agent: podssh/{}\r\nAccept: application/json\r\n\
         Connection: close\r\n\r\n",
        dial::authority(host, port),
        env!("CARGO_PKG_VERSION")
    );
    match tokio::time::timeout(wait, ask(&mut tcp, request.as_bytes())).await {
        Err(_) => Heard::Silent(wait),
        Ok(Err(e)) => Heard::Cut(Cut::of(e.kind())),
        Ok(Ok(first)) if first.is_empty() => Heard::Cut(Cut::Closed),
        Ok(Ok(first)) => read(&mut tcp, first, wait).await,
    }
}

/// Send `request`, and read the first bytes of the answer.
async fn ask(tcp: &mut TcpStream, request: &[u8]) -> std::io::Result<Vec<u8>> {
    tcp.write_all(request).await?;
    tcp.flush().await?;
    let mut first = vec![0u8; 4096];
    let n = tcp.read(&mut first).await?;
    first.truncate(n);
    Ok(first)
}

/// What `first`, never empty, and the bytes after it are.
async fn read(tcp: &mut TcpStream, first: Vec<u8>, wait: Duration) -> Heard {
    // A record of TLS: an alert (21) or a handshake (22), of version 3.x.
    if matches!(first[0], 0x15 | 0x16) && first.get(1) == Some(&3) {
        return Heard::Tls;
    }
    if !first.starts_with(b"HTTP/") {
        let seen = String::from_utf8_lossy(&first[..first.len().min(40)]).into_owned();
        return Heard::Other(crate::text::one_line(&seen));
    }
    let came = first.clone();
    match tokio::time::timeout(wait, crate::http::read_response(tcp, first, MAX_BODY)).await {
        Ok(Ok(response)) => {
            let location = response.header("location").map(str::to_string);
            answered(response.status, &response.reason, location, response.body)
        }
        // A head that came whole before its body broke off, or ran long.
        _ => head_alone(&came),
    }
}

/// The answer of `status`, its `Location` with no query, which a login page
/// may fill, and each word of the peer's in one line.
fn answered(status: u16, reason: &str, location: Option<String>, body: Vec<u8>) -> Heard {
    let location = location.map(|to| crate::text::one_line(to.split(['?', '#']).next().unwrap_or_default()));
    Heard::Answered { status, reason: crate::text::one_line(reason), location, body }
}

/// The answer of the head in `bytes`, when it came whole.
fn head_alone(bytes: &[u8]) -> Heard {
    let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Heard::Other("an answer of HTTP whose head broke off".into());
    };
    let head = String::from_utf8_lossy(&bytes[..end + 4]).into_owned();
    match crate::http::parse_head(&head) {
        Ok((status, reason, headers)) => {
            let location = headers.into_iter().find(|(name, _)| name == "location").map(|(_, to)| to);
            answered(status, &reason, location, bytes[end + 4..].to_vec())
        }
        Err(why) => Heard::Other(crate::text::one_line(&why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, reason: &str, body: &str) -> Heard {
        answered(status, reason, None, body.as_bytes().to_vec())
    }

    /// The refusal of cleartext in nginx's words, a refusal by policy and a
    /// redirect do not pass; another answer of HTTP does, as the path
    /// carried it both ways.
    #[test]
    fn only_an_answer_that_refuses_nothing_passes() {
        let edge = answer(400, "Bad Request", "<center>The plain HTTP request was sent to HTTPS port</center>");
        assert!(edge.plain_to_tls() && !edge.passed(), "{edge:?}");
        assert!(edge.words().starts_with("the edge's refusal: HTTP 400"), "{}", edge.words());
        let policy = answer(403, "Forbidden", "");
        assert_eq!((policy.passed(), policy.words()), (false, "a refusal by policy: HTTP 403 Forbidden".into()));
        let moved = answered(301, "Moved", Some("https://h.example/health?next=SECRET".into()), Vec::new());
        assert!(!moved.passed());
        assert_eq!(moved.words(), "a redirect: HTTP 301 to https://h.example/health", "no query shown");
        let ok = answer(200, "OK", r#"{"service":"tcp-ssh-relay"}"#);
        assert_eq!((ok.passed(), ok.words()), (true, "an answer: HTTP 200 OK".into()));
        assert!(answer(426, "", "").passed(), "an answer of HTTP that is no refusal of cleartext");
        assert!(answer(400, "Bad Request", "no upgrade").passed(), "a 400 in other words");
        let silent = Heard::Silent(Duration::from_secs(1));
        for no in [Heard::Tls, Heard::Cut(Cut::Reset), silent, Heard::Other("x".into())] {
            assert!(!no.passed(), "{no:?}");
        }
        assert!(Heard::Cut(Cut::Reset).words().starts_with("reset, with no answer"));
    }

    /// A head that came whole is read when its body broke off; one that
    /// did not is said so.
    #[test]
    fn a_head_alone_is_read() {
        let head = b"HTTP/1.1 403 Forbidden\r\nLocation: /x?y\r\nContent-Length: 99\r\n\r\npart";
        let Heard::Answered { status, reason, location, body } = head_alone(head) else { panic!("an answer") };
        assert_eq!((status, reason.as_str(), location.as_deref()), (403, "Forbidden", Some("/x")));
        assert_eq!(body, b"part");
        assert!(matches!(head_alone(b"HTTP/1.1 200 OK\r\nCon"), Heard::Other(_)));
    }
}
