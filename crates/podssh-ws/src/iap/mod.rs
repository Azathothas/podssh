//! The road of GCP's Identity-Aware Proxy for TCP (T-351): a WebSocket to
//! `wss://tunnel.cloudproxy.app/v4/connect`, through `HTTPS_PROXY` when one
//! is set, with the subprotocol `relay.tunnel.cloudproxy.app` and the user's
//! OAuth token in its `Authorization` header, never in the URL. Its query
//! names the VM, as gcloud names it; IAP's own messages ([`frame`]) carry
//! the stream, with acknowledgements ([`flow`]), and a session that loses
//! its link takes it up on a new one ([`carry`]).
//!
//! The upgrade is the one that gcloud 570.0.0 sends, captured from its own
//! client against a stand-in on the loopback (2026-10-31): the request line
//! with the target's query, then `Upgrade`, `Connection`, `Host`,
//! `Origin: bot:iap-tunneler`, the key, the version, the subprotocol, the
//! `User-Agent` and the token, in that order. Google's documents: IAP "isn't
//! intended for bulk transfer of data", and it ends a session after an
//! hour with no traffic.

pub mod carry;
pub mod close;
pub mod flow;
pub mod frame;

use std::fmt;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::client::{self, ConnectError, WRITE_TIMEOUT};
use crate::dial::ProxyChoice;
use crate::handshake;
use crate::session::RelaySession;
use crate::tls::Trust;

pub const HOST: &str = "tunnel.cloudproxy.app";
pub const PORT: u16 = 443;
pub const CONNECT_PATH: &str = "/v4/connect";
pub const RECONNECT_PATH: &str = "/v4/reconnect";
pub const SUBPROTOCOL: &str = "relay.tunnel.cloudproxy.app";
/// What gcloud says its origin is.
pub const ORIGIN: &str = "bot:iap-tunneler";
/// The VM's network interface: gcloud's default.
pub const INTERFACE: &str = "nic0";
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));
/// The longest token: an access token of Google is about 2 KiB.
pub const MAX_TOKEN: usize = 8192;

/// A port of a VM behind IAP: its project, zone, name and interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub project: String,
    pub zone: String,
    pub instance: String,
    pub interface: String,
    pub port: u16,
}

impl Target {
    /// The target, each name checked as GCP writes it; a refusal names the
    /// part, which is no secret.
    pub fn new(project: &str, zone: &str, instance: &str, port: u16) -> Result<Target, String> {
        let lower = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
        // A project of a domain, as example.com:name, keeps its . and :.
        let project_ok = project.len() <= 128
            && project.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && project.bytes().all(|b| lower(b) || b == b'.' || b == b':');
        if !project_ok {
            return Err(format!("{project:?} is not the ID of a project: lower-case letters, digits and -"));
        }
        if zone.is_empty() || zone.len() > 63 || !zone.contains('-') || !zone.bytes().all(lower) {
            return Err(format!("{zone:?} is not a zone, as us-central1-a is one"));
        }
        let instance_ok = instance.len() <= 63
            && instance.starts_with(|c: char| c.is_ascii_lowercase())
            && !instance.ends_with('-')
            && instance.bytes().all(lower);
        if !instance_ok {
            return Err(format!(
                "{instance:?} is not the name of a VM: a lower-case letter, then up to 62 lower-case letters, \
                 digits or -"
            ));
        }
        if port == 0 {
            return Err("port 0 is no port".into());
        }
        Ok(Target {
            project: project.into(),
            zone: zone.into(),
            instance: instance.into(),
            interface: INTERFACE.into(),
            port,
        })
    }
}

/// Where a new link takes a session up: its id, and the bytes of the
/// server's stream that reached the client.
#[derive(Clone, PartialEq, Eq)]
pub struct Resume {
    pub sid: Vec<u8>,
    pub received: u64,
}

impl fmt::Debug for Resume {
    // The id lets a reconnect take the session up: its length only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Resume {{ sid: {} bytes, received: {} }}", self.sid.len(), self.received)
    }
}

/// The path and query of a connect to `target`, or of a reconnect with
/// `resume`, as gcloud writes them. They name the VM and the session, never
/// a credential: the token goes in a header.
pub fn path(target: &Target, resume: Option<&Resume>) -> String {
    let pairs: Vec<(&str, String)> = match resume {
        None => vec![
            ("project", form(target.project.as_bytes())),
            ("port", target.port.to_string()),
            ("newWebsocket", "True".into()),
            ("zone", form(target.zone.as_bytes())),
            ("instance", form(target.instance.as_bytes())),
            ("interface", form(target.interface.as_bytes())),
        ],
        Some(resume) => vec![
            ("sid", form(&resume.sid)),
            ("ack", resume.received.to_string()),
            ("newWebsocket", "True".into()),
            ("zone", form(target.zone.as_bytes())),
        ],
    };
    let base = if resume.is_some() { RECONNECT_PATH } else { CONNECT_PATH };
    let query: Vec<String> = pairs.into_iter().map(|(name, value)| format!("{name}={value}")).collect();
    format!("{base}?{}", query.join("&"))
}

/// `value` as Python's `urlencode` writes it, as gcloud builds its URL:
/// letters, digits and `_.-~` as they are, a space as `+`, each other byte
/// as `%XX`.
fn form(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Whether `token` can go in a header: 1 to [`MAX_TOKEN`] printable
/// characters. The refusal never quotes it.
pub fn check_token(token: &str) -> Result<(), String> {
    if token.is_empty() || token.len() > MAX_TOKEN || !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(format!("the token is not one of Google's: 1 to {MAX_TOKEN} printable characters, with no space"));
    }
    Ok(())
}

/// The upgrade to `path` at `host`, with `key`, as gcloud writes it but for
/// `user_agent`. Sized once, so that no copy of the token is left in a
/// freed buffer.
pub fn request(host: &str, path: &str, token: &str, key: &str, user_agent: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if host.is_empty() || host.contains(|c: char| c.is_control() || c.is_whitespace() || "/?#@".contains(c)) {
        return Err(format!("{host:?} is not a host name"));
    }
    if !path.starts_with('/') || path.contains(|c: char| c.is_control() || c.is_whitespace()) {
        return Err("the path of the upgrade holds a space or a control character".into());
    }
    check_token(token)?;
    let lines = [
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Host", host),
        ("Origin", ORIGIN),
        ("Sec-WebSocket-Key", key),
        ("Sec-WebSocket-Version", "13"),
        ("Sec-WebSocket-Protocol", SUBPROTOCOL),
        ("User-Agent", user_agent),
    ];
    if let Some((name, _)) = lines.iter().find(|(_, value)| value.contains(|c: char| c.is_control())) {
        return Err(format!("the value of {name} holds a control character"));
    }
    let size = 64 + path.len() + token.len() + lines.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>();
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(b"GET ");
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in lines {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    // The token, in its header and nowhere else.
    out.extend_from_slice(b"Authorization: Bearer ");
    out.extend_from_slice(token.as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    Ok(out)
}

/// A new link to IAP for `target`, or one that takes the session of
/// `resume` up, through `proxy`, with `token` in its header. Each step is
/// bounded by `timeout`.
pub async fn connect(
    target: &Target,
    resume: Option<&Resume>,
    token: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<RelaySession, ConnectError> {
    check_token(token).map_err(ConnectError::Config)?;
    let tls = client::open_tls(HOST, PORT, HOST, trust, proxy, timeout).await?;
    let (tls, pending) = upgrade(tls, HOST, target, resume, token, timeout).await?;
    Ok(session(tls, pending))
}

/// The upgrade over `stream`; a refusal's body, which may quote what it was
/// sent, shows no token.
pub(crate) async fn upgrade<S>(
    stream: S,
    host: &str,
    target: &Target,
    resume: Option<&Resume>,
    token: &str,
    timeout: Duration,
) -> Result<(S, Vec<u8>), ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = handshake::generate_key().map_err(|e| ConnectError::Upgrade(e.to_string()))?;
    let request = request(host, &path(target, resume), token, &key, USER_AGENT).map_err(ConnectError::Config)?;
    match tokio::time::timeout(timeout, client::upgrade_with(stream, &request, &key)).await {
        Err(_) => Err(ConnectError::Timeout { step: "the WebSocket upgrade", after: timeout }),
        Ok(Err(ConnectError::Refused { status, body })) => {
            Err(ConnectError::Refused { status, body: hide_token(&body, token) })
        }
        Ok(answer) => answer,
    }
}

/// `body` with no part of `token`: each whole copy, and the start of one
/// that the cut of a refusal's text left at its end.
fn hide_token(body: &str, token: &str) -> String {
    let whole = body.replace(token, "<not shown>");
    let (text, cut) = match whole.strip_suffix('\u{2026}') {
        Some(text) => (text, "\u{2026}"),
        None => (whole.as_str(), ""),
    };
    // Eight characters or more: a shorter start is no more than a word.
    let start = (8..token.len()).rev().find(|&k| token.is_char_boundary(k) && text.ends_with(&token[..k]));
    match start {
        Some(k) => format!("{}<not shown>{cut}", &text[..text.len() - k]),
        None => whole,
    }
}

/// A link of IAP. No bound on a read: IAP sends nothing on a quiet session,
/// and SSH's keepalives find a dead link. No Ping goes: gcloud sends none.
pub(crate) fn session<S>(stream: S, pending: Vec<u8>) -> RelaySession<S>
where
    S: AsyncRead + AsyncWrite,
{
    RelaySession::new(stream, pending, None, WRITE_TIMEOUT).without_pings()
}

#[cfg(test)]
mod tests;
