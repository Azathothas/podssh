//! wstunnel's protocol (T-441, the operator's ruling Q66): a server of
//! erebe/wstunnel that the user runs (`wstunnel server wss://[::]:443`), one
//! static binary that takes the destination from its client, is the road in
//! place of the relay. Read in wstunnel's source at v11.1.0 (2026-10-19), and
//! at v10.0.1 and v9.7.4 for the versions before it; v11 changed nothing of
//! the wire (its release notes):
//!
//! - the upgrade goes to `/PREFIX/events`, PREFIX the client's
//!   `--http-upgrade-path-prefix` (`v1` unless set), which the server's
//!   `--restrict-http-upgrade-path-prefix`, or a restrictions file's
//!   `!PathPrefix`, holds as its secret
//!   (`erebe/wstunnel:wstunnel/src/tunnel/server/utils.rs`,
//!   `extract_path_prefix`); a restrictions file may match the
//!   `Authorization` header too (`!Authorization`), which the client's
//!   `--http-upgrade-credentials` fills with Basic;
//! - the destination is a JWT ([`token`]) in `Sec-WebSocket-Protocol: v1,
//!   authorization.bearer.JWT`, and the 101 names the subprotocol `v1`
//!   (`wstunnel/src/tunnel/transport/websocket.rs`, `connect`;
//!   `wstunnel/src/tunnel/server/handler_websocket.rs`);
//! - the server dials the target before it answers, so a 101 is a tunnel
//!   that is open; each refusal is a 400 ([`upgrade`]); the bytes go in
//!   binary frames.
//!
//! The same server serves wstunnel's HTTP/2 transport (`https://`) on the
//! same port; podssh speaks the WebSocket one, which each server takes. Its
//! frames are masked with a key of zero
//! ([`crate::RelaySession::with_zero_mask`]): wstunnel's server takes a
//! payload without its mask unless it runs `--websocket-mask-frame`
//! (fastwebsockets 0.10, whose `set_auto_apply_mask(false)` covers reads).

mod token;
pub mod upgrade;

use std::time::Duration;

use zeroize::Zeroizing;

use crate::client::{self, ConnectError, WRITE_TIMEOUT};
use crate::dial::{self, ProxyChoice};
use crate::forwarder::carry;
use crate::forwarder::Form;
use crate::session::RelaySession;
use crate::tls::Trust;
use crate::url::{Stream, WsUrl};

pub use crate::forwarder::{Carried, Ended, Status};
pub use token::{claims, host_claim, sign, uuid_text, KEY, PREFIX};

/// The path prefix of a client that names none, wstunnel's
/// `DEFAULT_CLIENT_UPGRADE_PATH_PREFIX`.
pub const DEFAULT_PREFIX: &str = "v1";

/// The largest frame taken: wstunnel's server sends what a read of the
/// target gave, in a buffer that it holds at 128 KiB.
pub const RECEIVE_CAP: usize = 1024 * 1024;

/// The other end, in the words of a failure.
pub const PEER: &str = "the wstunnel server";

/// A wstunnel server: `wss://HOST[:PORT]` or `ws://HOST[:PORT]`, with no
/// path, as the path prefix is the server's secret and goes in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    url: WsUrl,
}

impl Server {
    /// Parse the server's URL. wstunnel's other transports, `https://`
    /// (HTTP/2) and `wts://` (WebTransport), are refused with the scheme
    /// that the same server takes.
    pub fn parse(text: &str) -> Result<Server, String> {
        let text = text.trim();
        let scheme = text.split_once("://").map(|(s, _)| s.to_ascii_lowercase()).unwrap_or_default();
        let other = match scheme.as_str() {
            "https" | "http" => Some("wstunnel's HTTP/2 transport"),
            "wts" => Some("wstunnel's WebTransport"),
            _ => None,
        };
        if let Some(other) = other {
            return Err(format!(
                "{scheme}:// is {other}, which podssh does not speak: the same server takes the WebSocket, as \
                 wss://HOST[:PORT] (ws:// with no TLS)"
            ));
        }
        let url = WsUrl::parse(text).map_err(|why| why.replace("a WebSocket's URL", "a wstunnel server's URL"))?;
        if url.target != "/" {
            return Err("a wstunnel server is named by its host and port alone: its path prefix is its secret, \
                        which goes in a file (path-prefix PREFIX), and the URL takes no query"
                .into());
        }
        Ok(Server { url })
    }

    /// `wss://HOST[:PORT]`, the port only when it is not the scheme's own.
    pub fn shown(&self) -> String {
        format!("{}://{}", if self.url.tls { "wss" } else { "ws" }, self.url.host_header())
    }

    pub fn tls(&self) -> bool {
        self.url.tls
    }

    pub fn host(&self) -> &str {
        &self.url.host
    }

    pub fn port(&self) -> u16 {
        self.url.port
    }

    /// Whether the server is this host: `localhost`, or a loopback address.
    pub fn is_loopback(&self) -> bool {
        let host = self.url.host.as_str();
        host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }
}

/// What the server checks of a client: the path prefix, and the
/// `Authorization` that a restrictions file may match. Never shown.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    prefix: Zeroizing<String>,
    authorization: Option<Zeroizing<String>>,
}

impl Default for Secret {
    /// The client that names nothing: the prefix `v1`, no `Authorization`.
    fn default() -> Secret {
        Secret { prefix: Zeroizing::new(DEFAULT_PREFIX.to_string()), authorization: None }
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("prefix", &"<redacted>")
            .field("authorization", &self.authorization.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The characters of a path prefix: those that a path segment holds as
/// they are (RFC 3986's pchar but `%`), as the server compares the raw
/// segment with its own; no `/`, which would end the segment.
fn prefix_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~!$&'()*+,;=:@".contains(c)
}

impl Secret {
    /// The secret of a file's text: lines `path-prefix PREFIX`, `credentials
    /// USER[:PASSWORD]` (Basic, as wstunnel's `--http-upgrade-credentials`
    /// encodes it) and `authorization VALUE` (the header as it is), each
    /// once; or one line, the prefix alone, as `wstunnel server -r PREFIX`
    /// takes it. `#` starts a comment line. A refusal names a line by its
    /// number, never its text.
    pub fn parse(text: &str) -> Result<Secret, String> {
        let mut secret = Secret::default();
        let (mut prefix, mut auth) = (false, false);
        let lines: Vec<(usize, &str)> = text
            .lines()
            .enumerate()
            .map(|(n, l)| (n + 1, l.trim()))
            .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
            .collect();
        if lines.is_empty() {
            return Err("it has no line: give path-prefix PREFIX, or the prefix alone".into());
        }
        for &(n, line) in &lines {
            let (word, value) = line.split_once(char::is_whitespace).map_or((line, ""), |(w, v)| (w, v.trim()));
            let keyword = matches!(word, "path-prefix" | "credentials" | "authorization");
            let bare = lines.len() == 1 && value.is_empty() && !keyword;
            let word = if bare { "path-prefix" } else { word };
            let value = if bare { line } else { value };
            if value.is_empty() {
                return Err(format!("line {n}: {word} has no value"));
            }
            if value.chars().any(char::is_control) {
                return Err(format!("line {n}: it holds a control character"));
            }
            match word {
                "path-prefix" if prefix => return Err(format!("line {n}: a second path-prefix")),
                "path-prefix" => {
                    if value.len() > 256 || !value.chars().all(prefix_char) {
                        return Err(format!(
                            "line {n}: a path prefix holds at most 256 of the letters, digits and -._~!$&'()*+,;=:@ \
                             (no / and no %), as the server compares it as it comes"
                        ));
                    }
                    secret.prefix = Zeroizing::new(value.to_string());
                    prefix = true;
                }
                "credentials" | "authorization" if auth => {
                    return Err(format!("line {n}: a second credentials or authorization: one Authorization goes"))
                }
                "credentials" => {
                    use base64::Engine as _;
                    let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(value));
                    secret.authorization = Some(Zeroizing::new(format!("Basic {}", encoded.as_str())));
                    auth = true;
                }
                "authorization" => {
                    secret.authorization = Some(Zeroizing::new(value.to_string()));
                    auth = true;
                }
                _ => {
                    return Err(format!(
                        "line {n}: a line is path-prefix PREFIX, credentials USER[:PASSWORD] or authorization VALUE"
                    ))
                }
            }
        }
        Ok(secret)
    }

    /// Whether the file gave more than wstunnel's defaults.
    pub fn is_default(&self) -> bool {
        *self == Secret::default()
    }

    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
    }

    pub(crate) fn authorization(&self) -> Option<&str> {
        self.authorization.as_deref().map(String::as_str)
    }
}

/// A secret goes over TLS, or to this host: over `ws://` elsewhere the
/// network would read it.
pub fn check(server: &Server, secret: &Secret) -> Result<(), String> {
    if !server.tls() && !server.is_loopback() && !secret.is_default() {
        return Err(format!(
            "{} has no TLS, and the network would read the path prefix and the credentials: give wss://",
            server.shown()
        ));
    }
    Ok(())
}

/// How a tunnel reaches its server.
pub struct Dial<'a> {
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// Bound on the dial, TLS and the upgrade.
    pub timeout: Duration,
    /// Whether the end of this side's bytes sends a Close at once (an SSH
    /// session's end), or waits for the server's, as a pipe does.
    pub close_at_end: bool,
}

/// Why a server carried no tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WstunnelError {
    /// The target cannot go in a token.
    Target(String),
    /// TCP, the host's proxy, or TLS.
    Connect(ConnectError),
    /// The server's answer to the upgrade, in its words ([`upgrade`]).
    Refused { status: u16, words: String },
    /// An answer that is not wstunnel's: no server of 7 or later.
    NotWstunnel(String),
}

impl WstunnelError {
    /// The line that says it, the server named as `shown`.
    pub fn line(&self, shown: &str) -> String {
        match self {
            WstunnelError::Target(why) => format!("{PEER} {shown}: {why}"),
            WstunnelError::Connect(ConnectError::Tls(why)) => format!("TLS with {PEER} {shown} failed: {why}"),
            WstunnelError::Connect(other) => format!("{PEER} {shown}: {other}"),
            WstunnelError::Refused { status, words } => format!("{PEER} {shown} refused the tunnel: {status} {words}"),
            WstunnelError::NotWstunnel(why) => format!("{shown} is no wstunnel server that podssh speaks to: {why}"),
        }
    }
}

/// A tunnel to `host:port` through `server`: TCP through the proxy that
/// `dial` names, TLS for `wss://` checked for the server's name, the
/// upgrade with the token and the secret, then the bytes in binary frames.
pub async fn open(
    server: &Server,
    secret: &Secret,
    host: &str,
    port: u16,
    dial: &Dial<'_>,
) -> Result<Carried, WstunnelError> {
    dial::check_name(host).map_err(|e| WstunnelError::Target(e.to_string()))?;
    // Neither fails but where the system gives no random bytes.
    let no_random = |why: String| WstunnelError::Connect(ConnectError::Config(why));
    let token = token::for_target(host, port).map_err(no_random)?;
    let key = crate::handshake::generate_key().map_err(|e| no_random(e.to_string()))?;
    let request = upgrade::request(&server.url.host_header(), secret, &token, &key);
    let (h, p, limit) = (server.host(), server.port(), dial.timeout);
    let stream = if server.tls() {
        let tls = client::open_tls(h, p, h, dial.trust, dial.proxy, limit).await;
        Stream::Tls(Box::new(tls.map_err(WstunnelError::Connect)?))
    } else {
        let tcp = dial::dial(h, p, dial.proxy, limit).await;
        Stream::Plain(tcp.map_err(|e| WstunnelError::Connect(ConnectError::Dial(e)))?)
    };
    let upgraded = tokio::time::timeout(limit, upgrade::upgrade(stream, request.as_bytes(), &key)).await;
    let late = |_| WstunnelError::Connect(ConnectError::Timeout { step: "the WebSocket upgrade", after: limit });
    let (stream, pending) = upgraded.map_err(late)??;
    let idle = Some(client::DEFAULT_IDLE_TIMEOUT);
    let session = RelaySession::new(stream, pending, idle, WRITE_TIMEOUT).naming(PEER).with_zero_mask();
    session.set_receive_cap(RECEIVE_CAP);
    // The server dialed the target before its 101: there is no answer to
    // wait for, and a text frame, which it never sends, would be a note.
    let note: crate::forwarder::Note = std::sync::Arc::new(|_: &str| {});
    let (carried, _first) = carry::spawn(session, Form::Query, dial.close_at_end, note, PEER);
    Ok(carried)
}

#[cfg(test)]
mod tests;
