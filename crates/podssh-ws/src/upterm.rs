//! A guest's WebSocket to uptermd (T-495), as `upterm proxy wss://ID@HOST`
//! opens it (owenthereal/upterm, `ws/client.go`): an upgrade of `/` with
//! `Authorization: Basic` of `ID:` (the guest names no node) and
//! `Upterm-Client-Version`'s value of a guest, then SSH in binary messages.
//! uptermd checks both headers before the upgrade, and answers `400` with its
//! words when one is missing; a session that it cannot place ends the
//! WebSocket after the upgrade with a Close 1011 and its reason
//! (`server/wsproxy.go`), unless it hands the guest to its SSH proxy, whose
//! banner says why. The SSH inside ends at uptermd, which checks the
//! guest's key and carries its channels to the upterm host: the caller runs
//! SSH over the stream, and the next hop in a `direct-tcpip` channel.

use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::client::{self, ConnectError, UPGRADE_HEAD, WRITE_TIMEOUT};
use crate::dial::{self, ProxyChoice};
use crate::forwarder::carry::{self, First};
use crate::forwarder::{Carried, Form, EARLY_WAIT};
use crate::session::RelaySession;
use crate::tls::Trust;
use crate::url::Stream;
use crate::{handshake, http, text};

/// The header that names the kind of upterm's client.
pub const VERSION_HEADER: &str = "Upterm-Client-Version";
/// Its value for a guest (`upterm/const.go`, `ClientSSHClientVersion`).
pub const GUEST_VERSION: &str = "SSH-2.0-upterm-client-client";
/// The peer in the words of a failure.
pub const PEER: &str = "uptermd";
/// The most bytes of SSH from uptermd that wait for the reader.
const RECEIVE_CAP: usize = 1024 * 1024;

/// An uptermd server and the session that a guest joins on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub host: String,
    pub port: u16,
    /// `wss://`: TLS checked for the host; else `ws://`, which the caller
    /// keeps to this host.
    pub tls: bool,
    /// The session's ID, as `upterm host` shows it: the SSH user too.
    pub session: String,
}

impl Server {
    /// The value of the `Host` header: the port only when it is not the
    /// scheme's, as upterm's client strips it.
    pub fn host_header(&self) -> String {
        let name = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match (self.tls, self.port) {
            (true, 443) | (false, 80) => name,
            (_, port) => format!("{name}:{port}"),
        }
    }
}

/// How the WebSocket to uptermd is opened.
pub struct Dial<'a> {
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// Bound on the dial, TLS and the upgrade.
    pub timeout: Duration,
}

/// Why uptermd carried no SSH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UptermError {
    /// TCP, the host's proxy, or TLS.
    Connect(ConnectError),
    /// uptermd's answer to the upgrade, in its words.
    Refused { status: u16, words: String },
    /// A Close before any byte of SSH: a session that it cannot place.
    Closed { code: Option<u16>, reason: String },
}

impl UptermError {
    /// The line that says it, the server named as `shown` and the session
    /// as `session`.
    pub fn line(&self, shown: &str, session: &str) -> String {
        match self {
            UptermError::Connect(ConnectError::Tls(why)) => format!("TLS with {PEER} {shown} failed: {why}"),
            UptermError::Connect(other) => format!("{PEER} {shown}: {other}"),
            UptermError::Refused { status, words } => {
                format!("{PEER} {shown} refused the WebSocket: {status} {words}")
            }
            UptermError::Closed { code, reason } => {
                let code = code.map_or("no code".to_string(), |c| c.to_string());
                let said = text::one_line(reason);
                format!(
                    "{PEER} {shown} closed the WebSocket ({code}: {said}): it knows no session {session}, which \
                     ended or whose ID is not the one that its host shows"
                )
            }
        }
    }
}

/// The upgrade request of a guest of `server`; it holds the session's ID,
/// which uptermd reads, and no secret of the user's.
pub fn request(server: &Server, key: &str) -> String {
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:", server.session));
    format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Basic {auth}\r\n\
         {VERSION_HEADER}: {GUEST_VERSION}\r\n\r\n",
        server.host_header(),
        crate::url::USER_AGENT
    )
}

/// The WebSocket to `server`: TCP through `dial`'s proxy, TLS for `wss://`
/// checked for the host's name, the upgrade, then SSH in binary frames as a
/// stream; a Close before any byte is uptermd's refusal of the session.
pub async fn open(server: &Server, dial: &Dial<'_>) -> Result<Carried, UptermError> {
    let key = handshake::generate_key().map_err(|e| UptermError::Connect(ConnectError::Config(e.to_string())))?;
    let request = request(server, &key);
    let (h, p, limit) = (server.host.as_str(), server.port, dial.timeout);
    let stream = if server.tls {
        let tls = client::open_tls(h, p, h, dial.trust, dial.proxy, limit).await;
        Stream::Tls(Box::new(tls.map_err(UptermError::Connect)?))
    } else {
        let tcp = dial::dial(h, p, dial.proxy, limit).await;
        Stream::Plain(tcp.map_err(|e| UptermError::Connect(ConnectError::Dial(e)))?)
    };
    let upgraded = tokio::time::timeout(limit, upgrade(stream, request.as_bytes(), &key)).await;
    let late = |_| UptermError::Connect(ConnectError::Timeout { step: "the WebSocket upgrade", after: limit });
    let (stream, pending) = upgraded.map_err(late)??;
    // No idle bound: SSH's keepalives of the user's settings hold a quiet
    // session.
    let session = RelaySession::new(stream, pending, None, WRITE_TIMEOUT).naming(PEER);
    session.set_receive_cap(RECEIVE_CAP);
    let note: crate::forwarder::Note = std::sync::Arc::new(|_: &str| {});
    let (carried, first) = carry::spawn(session, Form::Query, true, note, PEER);
    // uptermd speaks first (its SSH version line), so a Close before it is
    // its word on the session; silence is left to SSH's own limit.
    match tokio::time::timeout(EARLY_WAIT, first).await {
        Ok(Ok(First::Closed { code, reason })) => {
            carried.abort();
            Err(UptermError::Closed { code, reason })
        }
        Ok(Ok(First::Failed(why))) => {
            carried.abort();
            Err(UptermError::Connect(ConnectError::Upgrade(why)))
        }
        _ => Ok(carried),
    }
}

/// Send `request` on `stream` and read the answer: the stream and the bytes
/// after the head on a 101, else uptermd's refusal in its words.
async fn upgrade<S>(mut stream: S, request: &[u8], key: &str) -> Result<(S, Vec<u8>), UptermError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io = |e: std::io::Error| UptermError::Connect(ConnectError::Upgrade(e.to_string()));
    stream.write_all(request).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        if buf.len() > UPGRADE_HEAD {
            let why = "its answer's head did not end within 16 KiB".to_string();
            return Err(UptermError::Connect(ConnectError::Upgrade(why)));
        }
        let n = stream.read(&mut chunk).await.map_err(io)?;
        if n == 0 {
            let why = "it closed the connection before it answered the upgrade".to_string();
            return Err(UptermError::Connect(ConnectError::Upgrade(why)));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let not_http = |why: String| {
        UptermError::Connect(ConnectError::Upgrade(format!("its answer is no HTTP: {}", text::one_line(&why))))
    };
    let (status, reason, _headers) = http::parse_head(&head).map_err(not_http)?;
    if status == 101 {
        let not_ws = |e: crate::error::WsError| {
            UptermError::Connect(ConnectError::Upgrade(format!("its 101 is no WebSocket's: {e}")))
        };
        handshake::check_response(&head, key).map_err(not_ws)?;
        return Ok((stream, buf.split_off(end)));
    }
    // A short, bounded read of the body, which holds uptermd's words.
    let body = tokio::time::timeout(Duration::from_secs(3), http::read_response(&mut stream, buf, 4096))
        .await
        .ok()
        .and_then(Result::ok)
        .map(|r| r.body_text(200))
        .unwrap_or_default();
    let said = text::one_line(if body.trim().is_empty() { &reason } else { &body });
    Err(UptermError::Refused { status, words: said })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(host: &str, port: u16, tls: bool) -> Server {
        Server { host: host.into(), port, tls, session: "abc123".into() }
    }

    #[test]
    fn the_request_names_the_session_and_a_guest_as_upterm_s_client_does() {
        let request = request(&server("uptermd.test", 443, true), "a2V5");
        // base64("abc123:"), the ID with no node, as `upterm proxy` sends it.
        assert!(request.contains("\r\nAuthorization: Basic YWJjMTIzOg==\r\n"), "{request}");
        assert!(request.contains("\r\nUpterm-Client-Version: SSH-2.0-upterm-client-client\r\n"), "{request}");
        assert!(request.starts_with("GET / HTTP/1.1\r\nHost: uptermd.test\r\n"), "{request}");
    }

    #[test]
    fn the_host_header_keeps_a_port_that_is_not_the_scheme_s() {
        assert_eq!(server("u.test", 443, true).host_header(), "u.test");
        assert_eq!(server("u.test", 8443, true).host_header(), "u.test:8443");
        assert_eq!(server("127.0.0.1", 80, false).host_header(), "127.0.0.1");
        assert_eq!(server("::1", 8080, false).host_header(), "[::1]:8080");
    }

    #[test]
    fn a_close_says_that_uptermd_knows_no_such_session() {
        let closed = UptermError::Closed { code: Some(1011), reason: "error resolving SSH user abc".into() };
        let line = closed.line("wss://u.test", "abc123");
        assert!(line.contains("1011: error resolving SSH user abc") && line.contains("knows no session abc123"));
        let refused = UptermError::Refused { status: 400, words: "missing upterm client version".into() };
        assert!(refused.line("wss://u.test", "x").ends_with("400 missing upterm client version"));
    }
}
