//! The road to a service that Cloudflare's `cloudflared` publishes (T-264).
//! `cloudflared access tcp` carries a TCP stream over a WebSocket to
//! `wss://HOST/`, the public name of a tunnel's `ssh://` or `tcp://` rule, and
//! podssh does the same with no program of Cloudflare's. The upgrade is the
//! one that cloudflared sends, read in its source at `bf4f502`
//! (`carrier/carrier.go`, `carrier/websocket.go`,
//! `cmd/cloudflared/access/carrier.go`) with gorilla/websocket 1.5.3: `GET /`,
//! a `Host` with no port, the other headers in the order of their names, and
//! the credentials of Cloudflare Access, for a name behind it, in their
//! headers, never in the URL.
//!
//! The origin reads each message into a buffer of 16 KiB and drops the rest
//! of a longer one (`websocket/connection.go`), so no message is longer. It
//! answers a Ping outside the lock of its other writes, so podssh sends none;
//! the idle bound of each read finds a dead link, against the origin's own
//! Ping every 54 s. Neither end sends a Close: the end of the stream is the
//! end of the session.

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::client::{self, ConnectError, WRITE_TIMEOUT};
use crate::dial::ProxyChoice;
use crate::handshake;
use crate::session::RelaySession;
use crate::tls::Trust;

/// The port of `wss://HOST/`.
pub const PORT: u16 = 443;
/// The path of the upgrade, as cloudflared asks for a bare name.
pub const PATH: &str = "/";
/// The largest message that the origin takes whole.
pub const MAX_MESSAGE: usize = 16 * 1024;
/// The path of the login page of Cloudflare Access, where it sends a client
/// that has no token for the name (in an organization of before 2026-10-05;
/// a later one answers 401 or 403).
pub const LOGIN_PATH: &str = "/cdn-cgi/access/login";
/// The headers of Cloudflare Access, as cloudflared writes their names.
pub const CLIENT_ID: &str = "Cf-Access-Client-Id";
pub const CLIENT_SECRET: &str = "Cf-Access-Client-Secret";
pub const TOKEN: &str = "Cf-Access-Token";
/// What podssh says it is, where cloudflared says `cloudflared/VERSION`.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));

/// The credentials of Cloudflare Access: a service token (its id and its
/// secret), a token of a user (`cloudflared access token`), both, or none for
/// a name that Access does not guard. Kept in memory that is wiped; never
/// shown.
#[derive(Default, Clone)]
pub struct Access {
    pub client_id: Option<Zeroizing<String>>,
    pub client_secret: Option<Zeroizing<String>>,
    pub token: Option<Zeroizing<String>>,
}

impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Access")
            .field("service_token", &(self.client_id.is_some() && self.client_secret.is_some()))
            .field("token", &self.token.is_some())
            .finish()
    }
}

impl Access {
    /// The values that must not be shown.
    fn secrets(&self) -> impl Iterator<Item = &str> {
        [&self.client_id, &self.client_secret, &self.token].into_iter().flatten().map(|s| s.as_str())
    }

    /// The headers of the credentials, in the order of their names.
    fn headers(&self) -> Vec<(&'static str, &str)> {
        let mut headers = Vec::new();
        if let (Some(id), Some(secret)) = (&self.client_id, &self.client_secret) {
            headers.push((CLIENT_ID, id.as_str()));
            headers.push((CLIENT_SECRET, secret.as_str()));
        }
        if let Some(token) = &self.token {
            headers.push((TOKEN, token.as_str()));
        }
        headers
    }
}

/// The upgrade request to `host`, with `key`, as cloudflared writes it but
/// for `user_agent`. A value with a control character is refused, and the
/// refusal names the header, never the value.
pub fn request(host: &str, access: &Access, key: &str, user_agent: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if host.is_empty() || host.contains(|c: char| c.is_control() || c.is_whitespace() || "/?#@".contains(c)) {
        return Err(format!("{host:?} is not a host name"));
    }
    let mut headers = access.headers();
    headers.extend([
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Key", key),
        ("Sec-WebSocket-Version", "13"),
        ("Upgrade", "websocket"),
    ]);
    headers.sort_by_key(|(name, _)| *name);
    if let Some((name, _)) = headers.iter().find(|(_, value)| value.contains(|c: char| c.is_control())) {
        return Err(format!("the value of {name} holds a control character"));
    }
    // Sized once, so that no copy of a credential is left in a freed buffer.
    let size = 64 + host.len() + user_agent.len() + headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>();
    let mut request = Zeroizing::new(Vec::with_capacity(size));
    request.extend_from_slice(format!("GET {PATH} HTTP/1.1\r\n").as_bytes());
    put_line(&mut request, "Host", host);
    put_line(&mut request, "User-Agent", user_agent);
    for (name, value) in &headers {
        put_line(&mut request, name, value);
    }
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

fn put_line(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// Whether a refusal is Cloudflare Access's: a redirect to its login page,
/// or 401 or 403.
pub fn refused_by_access(status: u16, body: &str) -> bool {
    matches!(status, 401 | 403) || ((300..400).contains(&status) && body.contains(LOGIN_PATH))
}

/// Open a session to the tunnel of `host`, through `proxy`, with the
/// credentials of `access`. Each step is bounded by `timeout`, and each read
/// of the session by `idle`.
pub async fn connect(
    host: &str,
    access: &Access,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    idle: Option<Duration>,
) -> Result<RelaySession, ConnectError> {
    let tls = client::open_tls(host, PORT, host, trust, proxy, timeout).await?;
    let (tls, pending) = upgrade(tls, host, access, timeout).await?;
    Ok(session(tls, pending, idle))
}

/// The same over plain TCP to the loopback, for the tests of the road
/// (feature `plain-ws`); `Host` names `host` alone, as on the road.
#[cfg(feature = "plain-ws")]
pub async fn connect_loopback(
    host: &str,
    port: u16,
    access: &Access,
    timeout: Duration,
    idle: Option<Duration>,
) -> Result<RelaySession<tokio::net::TcpStream>, ConnectError> {
    let tcp = crate::plain::loopback_tcp(host, port, timeout).await?;
    let (tcp, pending) = upgrade(tcp, host, access, timeout).await?;
    Ok(session(tcp, pending, idle))
}

async fn upgrade<S>(stream: S, host: &str, access: &Access, timeout: Duration) -> Result<(S, Vec<u8>), ConnectError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let key = handshake::generate_key().map_err(|e| ConnectError::Upgrade(e.to_string()))?;
    let request = request(host, access, &key, USER_AGENT).map_err(ConnectError::Config)?;
    match tokio::time::timeout(timeout, client::upgrade_with(stream, &request, &key)).await {
        Err(_) => Err(ConnectError::Timeout { step: "the WebSocket upgrade", after: timeout }),
        // An answer may quote what it was sent.
        Ok(Err(ConnectError::Refused { status, body })) => {
            let body = access.secrets().filter(|s| !s.is_empty()).fold(body, |b, s| b.replace(s, "<not shown>"));
            Err(ConnectError::Refused { status, body })
        }
        Ok(answer) => answer,
    }
}

fn session<S>(stream: S, pending: Vec<u8>, idle: Option<Duration>) -> RelaySession<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    RelaySession::new(stream, pending, idle, WRITE_TIMEOUT).with_max_message(MAX_MESSAGE).without_pings()
}
