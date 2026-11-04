//! The WebSocket over HTTP/2's extended CONNECT (RFC 8441, T-321, GitHub
//! #51): the sessions of one process to a relay host as streams of one TLS
//! connection, where the host offers it, as podssh's relay role does. TLS of
//! this road alone offers `h2`, then `http/1.1`, by ALPN; each other road of
//! podssh offers none (`tls.rs`). On `h2`: HTTP/2's handshake with the
//! road's windows, a PING whose answer comes after the server's SETTINGS,
//! and then, only where those SETTINGS offered the protocol
//! (`SETTINGS_ENABLE_CONNECT_PROTOCOL`, RFC 8441 section 3), a CONNECT for
//! each session with `:protocol websocket`, the `:scheme`, `:path` and
//! `:authority` of the upgrade, `sec-websocket-version` and the token, in a
//! field that HPACK never indexes (section 4). A 2xx opens the session,
//! whose frames of RFC 6455 run on the stream as on TCP (section 5); another
//! status is the relay's refusal, read as a refused upgrade is.
//!
//! Where TLS chose `http/1.1`, or no protocol, the upgrade goes on that same
//! connection, as [`crate::connect`] sends it. Where it chose `h2` and the
//! SETTINGS offered no extended CONNECT, or HTTP/2 did not carry the
//! CONNECT, the connection is closed first and the upgrade goes on a new
//! one, so that a session holds one connection at a time; the process then
//! takes HTTP/1.1 to that host for [`REMEMBERED`] ([`pool`]). A caller's own
//! TLS configuration is used as it is, with no ALPN (`Trust::caller`), so it
//! takes the upgrade alone.

mod dial;
mod pool;

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::client::{ConnectError, RelayStream, WsClientConfig};
use crate::session::RelaySession;
use crate::tls::Trust;

pub use dial::{probe, Offered};

/// The protocols that this road offers by ALPN, in its order.
pub const H2: &[u8] = b"h2";
pub const HTTP1: &[u8] = b"http/1.1";

/// The most sessions on one connection: the connection's window is theirs
/// together, so that no stream that a slow reader holds full takes the
/// window of another; a session past them opens another connection.
pub const STREAMS: usize = 16;

/// The window of each session's stream: 160 Mbit/s at 50 ms, four times the
/// relay's largest frame.
pub const STREAM_WINDOW: u32 = 1 << 20;

/// The connection's window: each session's window, together.
pub const CONNECTION_WINDOW: u32 = STREAM_WINDOW * STREAMS as u32;

/// How long a connection with no session stays open, for the next session
/// of a fan-out.
pub const IDLE: Duration = Duration::from_secs(30);

/// How long a host that took HTTP/1.1 at the cost of a connection is not
/// asked for HTTP/2 again.
pub const REMEMBERED: Duration = Duration::from_secs(600);

/// How long, and how much of, a refusal's body is read, as of a refused
/// upgrade.
const REFUSAL_WAIT: Duration = Duration::from_secs(3);
const REFUSAL_BODY: usize = 4096;

/// How a session of [`connect`] is carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Road {
    /// A stream of an HTTP/2 connection; `shared` when another session took
    /// the connection before.
    Stream { shared: bool },
    /// The upgrade of HTTP/1.1, and why.
    Http1(Fallback),
}

/// Why a session took the upgrade of HTTP/1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fallback {
    /// TLS chose `http/1.1`, or no protocol: the upgrade on that connection.
    NotChosen,
    /// HTTP/2's SETTINGS offered no extended CONNECT: a new connection.
    NotOffered,
    /// HTTP/2 did not carry the CONNECT, a reset or no answer to its PING:
    /// a new connection.
    Carried(String),
    /// The process found one of these at this host within [`REMEMBERED`],
    /// so it asked for no HTTP/2.
    Remembered(Box<Fallback>),
    /// The caller's TLS configuration, which offers no ALPN.
    Caller,
}

impl Fallback {
    /// Why, in words.
    pub fn reason(&self) -> String {
        match self {
            Fallback::NotChosen => "the relay's TLS chose HTTP/1.1, not h2".into(),
            Fallback::NotOffered => "the relay's SETTINGS of HTTP/2 offer no extended CONNECT (RFC 8441)".into(),
            Fallback::Carried(why) => format!("HTTP/2 did not carry the CONNECT: {why}"),
            Fallback::Remembered(why) => {
                format!("{}, as this process found within {} minutes", why.reason(), REMEMBERED.as_secs() / 60)
            }
            Fallback::Caller => "the caller's TLS configuration offers no ALPN".into(),
        }
    }
}

impl Road {
    /// The road in the words of a line of `-v`, after the relay host's name;
    /// none for the upgrade on the one connection, as before the road.
    pub fn words(&self) -> Option<String> {
        Some(match self {
            Road::Stream { shared: false } => "over HTTP/2 (RFC 8441), on a connection that it opened".into(),
            Road::Stream { shared: true } => "over HTTP/2 (RFC 8441), on a connection that it shares".into(),
            Road::Http1(Fallback::NotChosen | Fallback::Caller) => return None,
            Road::Http1(why @ (Fallback::NotOffered | Fallback::Carried(_))) => {
                format!("over HTTP/1.1 on a new connection, as {}", why.reason())
            }
            Road::Http1(why) => format!("over HTTP/1.1, as {}", why.reason()),
        })
    }
}

/// A session's stream of HTTP/2: the DATA of one stream both ways, and
/// END_STREAM at its shutdown, as a tunnel of `via` carries; a client's
/// gives its place on its connection back when it drops.
pub struct Stream {
    inner: crate::via::Stream,
    _place: Option<pool::Place>,
}

/// The stream of `send` and `recv`, as a server answers an extended
/// CONNECT with them (podssh's relay role, `serve::http2`).
pub fn duplex(send: SendStream<Bytes>, recv: RecvStream) -> Stream {
    Stream { inner: crate::via::Stream::from_parts(send, recv), _place: None }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Why a CONNECT on a connection gave no session.
enum Carry {
    /// The relay answered, or the step's bound passed: the session's end.
    Answer(ConnectError),
    /// The connection's own end (a GOAWAY, its I/O, a stream refused before
    /// it was processed, RFC 9113 section 8.7): another connection may pass.
    Connection(String),
    /// The server reset this CONNECT: HTTP/1.1 carries the session.
    Reset(String),
}

impl Carry {
    fn of(e: h2::Error) -> Carry {
        let refused = e.is_reset() && e.reason() == Some(h2::Reason::REFUSED_STREAM);
        if e.is_go_away() || e.is_io() || refused || !e.is_reset() {
            return Carry::Connection(e.to_string());
        }
        Carry::Reset(e.to_string())
    }
}

/// Connect as [`crate::connect`] does, with `token` in a field and nowhere
/// else, on this road where the host takes it, else by the upgrade of
/// HTTP/1.1: the session, and how it is carried.
pub async fn connect(config: &WsClientConfig, token: &str) -> Result<(RelaySession, Road), ConnectError> {
    config.validate().map_err(ConnectError::Config)?;
    if token.contains(['\r', '\n']) {
        return Err(ConnectError::Config("the relay token contains a line break".into()));
    }
    if matches!(config.trust, Trust::Caller(_)) {
        return Ok((crate::connect(config, token).await?, Road::Http1(Fallback::Caller)));
    }
    // A connection that ended under the CONNECT, as at a GOAWAY, gives way
    // to a new one, once; the last one's words go into the fallback's.
    let mut ended = String::new();
    for _ in 0..2 {
        let (conn, place, shared) = match pool::place(config).await? {
            pool::Got::Place { conn, place, shared } => (conn, place, shared),
            pool::Got::Http1(tls) => {
                return Ok((upgrade_on(*tls, config, token).await?, Road::Http1(Fallback::NotChosen)));
            }
            pool::Got::Fallback(why) => return Ok((crate::connect(config, token).await?, Road::Http1(why))),
        };
        match open_on(&conn, place, config, token).await {
            Ok(session) => return Ok((session, Road::Stream { shared })),
            Err(Carry::Answer(e)) => return Err(e),
            Err(Carry::Connection(why)) => {
                ended = why;
                conn.retire();
            }
            Err(Carry::Reset(why)) => {
                let why = Fallback::Carried(why);
                pool::remember(config, why.clone()).await;
                return Ok((crate::connect(config, token).await?, Road::Http1(why)));
            }
        }
    }
    let why = Fallback::Carried(format!("two connections of HTTP/2 ended under the CONNECT, the last: {ended}"));
    Ok((crate::connect(config, token).await?, Road::Http1(why)))
}

/// The CONNECT of RFC 8441 for `config`'s path, with `token`.
fn request(config: &WsClientConfig, token: &str) -> Result<http::Request<()>, ConnectError> {
    let authority = crate::dial::authority(&config.endpoint.host, config.endpoint.port);
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(config.endpoint.path.as_str())
        .build()
        .map_err(|e| ConnectError::Config(format!("the relay's name or path is no URI of HTTP/2: {e}")))?;
    // Never indexed: a shared connection's table of HPACK never holds it.
    let mut value = http::HeaderValue::from_str(token)
        .map_err(|_| ConnectError::Config("the relay token is no value of an HTTP field".into()))?;
    value.set_sensitive(true);
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .header("sec-websocket-version", "13")
        .header(http::header::USER_AGENT, crate::url::USER_AGENT)
        .header("x-relay-token", value)
        .body(())
        .map_err(|e| ConnectError::Config(format!("the CONNECT: {e}")))?;
    request.extensions_mut().insert(h2::ext::Protocol::from_static("websocket"));
    Ok(request)
}

/// The session of a CONNECT on `conn`, in the place that the pool gave it.
async fn open_on(
    conn: &pool::Conn,
    place: pool::Place,
    config: &WsClientConfig,
    token: &str,
) -> Result<RelaySession, Carry> {
    let request = request(config, token).map_err(Carry::Answer)?;
    let limit = config.timeout;
    let asked = async {
        let mut sender = conn.sender().ready().await.map_err(Carry::of)?;
        let (response, send) = sender.send_request(request, false).map_err(Carry::of)?;
        let response = response.await.map_err(Carry::of)?;
        Ok::<_, Carry>((response, send))
    };
    let late = |_| Carry::Answer(ConnectError::Timeout { step: "the WebSocket upgrade", after: limit });
    let (response, send) = tokio::time::timeout(limit, asked).await.map_err(late)??;
    let status = response.status();
    if !status.is_success() {
        let reason = status.canonical_reason().unwrap_or_default().to_string();
        let body = refusal_text(response.into_body()).await;
        let body = if body.is_empty() { reason } else { body };
        return Err(Carry::Answer(ConnectError::Refused { status: status.as_u16(), body }));
    }
    let stream = Stream { inner: crate::via::Stream::from_parts(send, response.into_body()), _place: Some(place) };
    Ok(RelaySession::over_h2(stream, conn.peer(), config.idle_timeout))
}

/// The start of a refusal's body, as the body of a refused upgrade is
/// read: within [`REFUSAL_WAIT`], made one line for a terminal.
async fn refusal_text(mut body: RecvStream) -> String {
    let mut got = Vec::new();
    let read = async {
        while let Some(Ok(chunk)) = body.data().await {
            let _ = body.flow_control().release_capacity(chunk.len());
            got.extend_from_slice(&chunk);
            if got.len() >= REFUSAL_BODY {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(REFUSAL_WAIT, read).await;
    got.truncate(REFUSAL_BODY);
    crate::http::Response { status: 0, reason: String::new(), headers: Vec::new(), body: got }.body_text(200)
}

/// The upgrade of HTTP/1.1 on `tls`, a connection whose TLS chose it.
async fn upgrade_on(tls: RelayStream, config: &WsClientConfig, token: &str) -> Result<RelaySession, ConnectError> {
    let host_header = crate::dial::authority(&config.endpoint.host, config.endpoint.port);
    let upgraded = crate::client::upgrade(tls, &host_header, &config.endpoint.path, token);
    let (tls, pending) = tokio::time::timeout(config.timeout, upgraded)
        .await
        .map_err(|_| ConnectError::Timeout { step: "the WebSocket upgrade", after: config.timeout })??;
    Ok(RelaySession::over_tls(tls, pending, config.idle_timeout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Endpoint;
    use crate::dial::ProxyChoice;

    fn config(path: &str) -> WsClientConfig {
        WsClientConfig {
            endpoint: Endpoint { host: "relay.example".into(), port: 8443, path: path.into() },
            trust: Trust::Default,
            server_name: "relay.example".into(),
            timeout: Duration::from_secs(5),
            idle_timeout: None,
            proxy: ProxyChoice::Direct,
        }
    }

    /// RFC 8441 section 4: `:protocol`, a scheme, the authority and the
    /// path of the upgrade, its query among them; the token in a field that
    /// HPACK never indexes, and no key of RFC 6455.
    #[test]
    fn the_connect_names_websocket_the_path_and_hides_the_token_from_hpack() {
        let request = request(&config("/connect/github.com/22?family=6"), "tok.en").unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        let protocol = request.extensions().get::<h2::ext::Protocol>().map(|p| p.as_str().to_string());
        assert_eq!(protocol.as_deref(), Some("websocket"));
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().authority().map(|a| a.as_str()), Some("relay.example:8443"));
        assert_eq!(request.uri().path_and_query().map(|p| p.as_str()), Some("/connect/github.com/22?family=6"));
        assert!(request.headers()["x-relay-token"].is_sensitive());
        assert_eq!(request.headers()["sec-websocket-version"], "13");
        assert!(request.headers().get("sec-websocket-key").is_none());
        let refused = request_err("bad\u{7f}token");
        assert!(!refused.contains("bad"), "the token is not said: {refused}");
    }

    fn request_err(token: &str) -> String {
        request(&config("/connect/h/22"), token).err().map(|e| e.to_string()).unwrap_or_default()
    }

    /// Each road is said for `-v`, a fallback with its reason; the upgrade
    /// on the one connection, as before the road, with none.
    #[test]
    fn each_road_has_its_words() {
        let words = |road: Road| road.words().unwrap_or_default();
        assert!(words(Road::Stream { shared: true }).contains("on a connection that it shares"));
        let new = words(Road::Http1(Fallback::NotOffered));
        assert!(new.starts_with("over HTTP/1.1 on a new connection, as the relay's SETTINGS"), "{new}");
        let again = words(Road::Http1(Fallback::Remembered(Box::new(Fallback::NotOffered))));
        assert!(again.starts_with("over HTTP/1.1, as the relay's SETTINGS"), "{again}");
        assert!(again.ends_with("as this process found within 10 minutes"), "{again}");
        assert_eq!(Road::Http1(Fallback::NotChosen).words(), None);
        assert_eq!(Fallback::NotChosen.reason(), "the relay's TLS chose HTTP/1.1, not h2");
    }
}
