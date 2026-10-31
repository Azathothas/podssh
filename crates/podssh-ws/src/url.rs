//! A WebSocket that the user names (T-368): `wss://HOST[:PORT]/PATH` or
//! `ws://HOST[:PORT]/PATH`, the URL as a user writes it, dialed with no
//! token: TLS checked for HOST with podssh's trust, or plain TCP, through
//! the proxy that the environment names, as each road is. No token of the
//! relay goes on this road, so the relay's rule for its path (no query but
//! its knobs) is not this road's: the path and its query are the user's,
//! sent as written but for a byte that is not ASCII, which is
//! percent-encoded. podssh's own lines show the URL without its query,
//! which may hold the service's own secret.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::client::{self, ConnectError, RelayStream, WRITE_TIMEOUT};
use crate::dial::{self, ProxyChoice};
use crate::handshake;
use crate::session::RelaySession;
use crate::tls::Trust;

/// What podssh says it is, as on the road of `cloudflared`.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));

/// A WebSocket's URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsUrl {
    /// `wss://`: TLS, checked for `host`.
    pub tls: bool,
    /// A name or an IP address, an IPv6 one with no brackets.
    pub host: String,
    pub port: u16,
    /// The path and its query, from `/`, as the request line carries them.
    pub target: String,
}

impl WsUrl {
    /// `ws://` or `wss://`, a host, a port when it is not the scheme's own,
    /// and the path with its query; a fragment is not sent. A user and a
    /// password in the URL are refused: a credential does not go in a URL.
    pub fn parse(text: &str) -> Result<WsUrl, String> {
        let lower = text.get(..6).unwrap_or(text).to_ascii_lowercase();
        let (tls, rest) = if lower.starts_with("wss://") {
            (true, &text[6..])
        } else if lower.starts_with("ws://") {
            (false, &text[5..])
        } else {
            // The text is not shown: its query may hold a secret.
            return Err("not a WebSocket's URL, which is ws://HOST[:PORT]/PATH or wss://HOST[:PORT]/PATH".into());
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err("a WebSocket's URL takes no user and no password: a credential does not go in a URL".into());
        }
        let (host, port) = host_port(authority, if tls { 443 } else { 80 })?;
        let tail = tail.split('#').next().unwrap_or_default();
        let target = if tail.starts_with('/') { tail.to_string() } else { format!("/{tail}") };
        Ok(WsUrl { tls, host, port, target: request_target(&target)? })
    }

    /// The URL without its query, for podssh's lines.
    pub fn shown(&self) -> String {
        let path = self.target.split('?').next().unwrap_or("/");
        format!("{}://{}{path}", if self.tls { "wss" } else { "ws" }, self.host_header())
    }

    /// The value of `Host`: the port only when it is not the scheme's own
    /// (RFC 6455 section 4.1), an IPv6 address in brackets.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The scheme's own port: 443 for `wss://`, 80 for `ws://`.
    pub fn default_port(&self) -> u16 {
        if self.tls {
            443
        } else {
            80
        }
    }
}

/// `HOST`, `HOST:PORT`, `[IPV6]` or `[IPV6]:PORT`; `default` with no port.
fn host_port(authority: &str, default: u16) -> Result<(String, u16), String> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']').ok_or_else(|| format!("{authority:?}: '[' is not closed"))?;
            host.parse::<std::net::Ipv6Addr>().map_err(|_| format!("{authority:?}: brackets hold an IPv6 address"))?;
            match after {
                "" => (host, None),
                _ => (host, Some(after.strip_prefix(':').ok_or_else(|| format!("{authority:?}: text after ']'"))?)),
            }
        }
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if !authority.starts_with('[') {
        crate::names::check_host(host).map_err(|why| format!("a WebSocket's URL: {why}"))?;
    }
    let port = match port {
        None => default,
        Some(text) => text.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{text:?} is not a port"))?,
    };
    Ok((host.to_string(), port))
}

/// The request-target of `target`: CR, LF, a space and each control byte
/// refused, as each would break the request line; a byte that is not ASCII
/// percent-encoded, as a browser sends it.
pub fn request_target(target: &str) -> Result<String, String> {
    if !target.starts_with('/') {
        return Err("a WebSocket's path begins with /".into());
    }
    let mut out = String::with_capacity(target.len());
    for b in target.bytes() {
        match b {
            b' ' => return Err("a WebSocket's path holds a space; write it %20".into()),
            0..=0x1f | 0x7f => return Err("a WebSocket's path holds a control character, CR or LF".into()),
            0x80..=0xff => out.push_str(&format!("%{b:02X}")),
            _ => out.push(b as char),
        }
    }
    Ok(out)
}

/// The upgrade request of `url`, with `key`: no token, no subprotocol, no
/// extension and no `Origin`, as a program sends it.
pub fn request(url: &WsUrl, key: &str) -> Result<Vec<u8>, ConnectError> {
    let target = request_target(&url.target).map_err(ConnectError::Config)?;
    let mut request = format!("GET {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\n", url.host_header());
    request.push_str("Upgrade: websocket\r\nConnection: Upgrade\r\n");
    request.push_str(&format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"));
    Ok(request.into_bytes())
}

/// The stream under a session of this road: TLS, or plain TCP.
pub enum Stream {
    Plain(TcpStream),
    Tls(Box<RelayStream>),
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(tcp) => Pin::new(tcp).poll_read(cx, buf),
            Stream::Tls(tls) => Pin::new(&mut **tls).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(tcp) => Pin::new(tcp).poll_write(cx, buf),
            Stream::Tls(tls) => Pin::new(&mut **tls).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(tcp) => Pin::new(tcp).poll_flush(cx),
            Stream::Tls(tls) => Pin::new(&mut **tls).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(tcp) => Pin::new(tcp).poll_shutdown(cx),
            Stream::Tls(tls) => Pin::new(&mut **tls).poll_shutdown(cx),
        }
    }
}

/// Dial `url` and upgrade, with no token: each step bounded by `timeout`,
/// each read of the session by `idle`. The session names the other end
/// `the server` in its errors.
pub async fn dial(
    url: &WsUrl,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    idle: Option<Duration>,
) -> Result<RelaySession<Stream>, ConnectError> {
    let key = handshake::generate_key().map_err(|e| ConnectError::Upgrade(e.to_string()))?;
    let request = request(url, &key)?;
    let stream = if url.tls {
        Stream::Tls(Box::new(client::open_tls(&url.host, url.port, &url.host, trust, proxy, timeout).await?))
    } else {
        Stream::Plain(dial::dial(&url.host, url.port, proxy, timeout).await.map_err(ConnectError::Dial)?)
    };
    let upgraded = tokio::time::timeout(timeout, client::upgrade_with(stream, &request, &key)).await;
    let late = |_| ConnectError::Timeout { step: "the WebSocket upgrade", after: timeout };
    let (stream, pending) = upgraded.map_err(late)??;
    Ok(RelaySession::new(stream, pending, idle, WRITE_TIMEOUT).naming("the server"))
}

/// What a failure of [`dial`] means, in this road's words: the URL as
/// shown, with no query.
pub fn failure(url: &WsUrl, e: &ConnectError) -> String {
    let shown = url.shown();
    match e {
        ConnectError::Refused { status, body } if body.is_empty() => {
            format!("{shown} refused the upgrade: HTTP {status}")
        }
        ConnectError::Refused { status, body } => format!("{shown} refused the upgrade: HTTP {status}: {body}"),
        ConnectError::Tls(why) => format!("TLS with {} failed: {why}", url.host),
        ConnectError::Upgrade(why) => format!("the WebSocket upgrade with {shown} failed: {why}"),
        other => format!("{shown}: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> WsUrl {
        WsUrl::parse(text).unwrap()
    }

    #[test]
    fn a_url_gives_its_scheme_host_port_and_target_and_shows_no_query() {
        let plain = url("ws://127.0.0.1:8080/echo?room=1&token=SECRET#frag");
        assert_eq!((plain.tls, plain.host.as_str(), plain.port), (false, "127.0.0.1", 8080));
        assert_eq!(plain.target, "/echo?room=1&token=SECRET");
        assert_eq!(plain.shown(), "ws://127.0.0.1:8080/echo");
        let tls = url("WSS://Example.org?x=1");
        assert_eq!((tls.tls, tls.port, tls.target.as_str()), (true, 443, "/?x=1"));
        assert_eq!(tls.host_header(), "Example.org");
        let v6 = url("wss://[2001:db8::1]:8443/p");
        assert_eq!((v6.host.as_str(), v6.host_header()), ("2001:db8::1", "[2001:db8::1]:8443".into()));
        assert_eq!(url("ws://h/caf\u{e9}").target, "/caf%C3%A9");
    }

    #[test]
    fn a_url_that_would_break_the_request_or_carries_a_credential_is_refused() {
        for bad in [
            "http://example.org/",
            "ws:example.org:80/x",
            "ws://user:pass@example.org/",
            "ws://example.org:0/",
            "ws://example.org:x/",
            "ws:///path",
            "ws://exa mple.org/",
            "ws://[::1/",
            "ws://[nope]/",
            "ws://[::1]junk/",
            "ws://example.org/a b",
            "ws://example.org/a\r\nX-Relay-Token: t",
        ] {
            assert!(WsUrl::parse(bad).is_err(), "{bad:?}");
        }
        let refused = WsUrl::parse("ws://user:SECRET@example.org/").unwrap_err();
        assert!(!refused.contains("SECRET"), "{refused}");
    }

    #[test]
    fn the_request_has_no_token_no_origin_and_no_subprotocol() {
        let request = String::from_utf8(request(&url("ws://h:81/x?q=1"), "dGhlIHNhbXBsZSBub25jZQ==").unwrap()).unwrap();
        assert!(request.starts_with("GET /x?q=1 HTTP/1.1\r\nHost: h:81\r\n"), "{request}");
        assert!(request.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"));
        for absent in ["x-relay-token", "origin", "sec-websocket-protocol", "sec-websocket-extensions"] {
            assert!(!request.to_ascii_lowercase().contains(absent), "{absent}: {request}");
        }
        let failure = failure(&url("wss://h/p?k=SECRET"), &ConnectError::Refused { status: 403, body: "no".into() });
        assert_eq!(failure, "wss://h/p refused the upgrade: HTTP 403: no");
    }
}
