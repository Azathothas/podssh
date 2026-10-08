//! HTTP CONNECT proxy dialer: the sandbox's only egress.
//!
//! On the target host there is no `/dev/net/tun`, no capability, no UDP, and
//! direct 443 is dropped; DNS is broken. The only way out is an HTTP CONNECT
//! proxy, and the proxy resolves — so under proxy the CONNECT authority is
//! always the **hostname** (never a dial-plan IP, never `FixedAddr`), and the
//! local resolver is never consulted.
//!
//! ⛔ **One dialer for all three sites.** Control (`ControlTcpDialer`), DERP
//! (`dial_by_ipusage`) and `dial_tcp` all route through [`connect`] when a
//! proxy is configured. A fourth dial path that goes direct is how a sandbox
//! node silently keeps the one route that cannot work.
//!
//! ⛔ **No silent fallback to direct.** If the proxy refuses (403, like the
//! sandbox's port-22 refusal) or is unreachable, [`connect`] returns the
//! error. Falling back to a direct dial would hang on a host whose direct
//! route is dropped — the hang wearing a retry loop.
//!
//! Configuration is process-global ([`configure`]) because the three call
//! sites have fixed signatures (`TcpDialer::dial`, `dial_tcp`,
//! `dial_by_ipusage`) owned by three crates. Tests scope it: configure, use,
//! reset in the same test.

use std::io;
use std::sync::{Mutex, OnceLock};

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Bound on a CONNECT response head: 16 KiB. A proxy that sends more without
/// a blank line is not answering, and an unbounded read is the hang with a
/// bigger buffer.
pub const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// Bound on the whole CONNECT exchange (dial + request + response).
pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Default proxy port when the URL names none. Convention, documented here
/// rather than guessed at the call site.
pub const DEFAULT_PORT: u16 = 8080;

/// A configured proxy: where it is, and what it answers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Proxy hostname. Dialed by name — never resolved locally first, because
    /// on the target there is nothing to resolve with.
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// `Proxy-Authorization` value (`Basic …`), if the proxy needs one.
    /// Stored encoded so the password is never re-derived per connection.
    auth_header: Option<String>,
}

impl ProxyConfig {
    /// Parse `http://[user:pass@]host[:port]`. Only the `http` scheme names a
    /// CONNECT proxy; anything else is refused rather than reinterpreted.
    pub fn from_url(url: &str) -> Result<Self, String> {
        let parsed =
            url::Url::parse(url).map_err(|e| format!("proxy URL {url:?} does not parse: {e}"))?;
        if parsed.scheme() != "http" {
            return Err(format!(
                "proxy URL {url:?} is not http: only http:// names a CONNECT proxy"
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("proxy URL {url:?} names no host"))?
            .to_string();
        if host.is_empty() {
            return Err(format!("proxy URL {url:?} names no host"));
        }
        let port = parsed.port().unwrap_or(DEFAULT_PORT);
        let auth_header = match (parsed.username(), parsed.password()) {
            ("", _) => None,
            (user, pass) => {
                let credentials = format!("{user}:{}", pass.unwrap_or(""));
                Some(format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(credentials)
                ))
            }
        };
        Ok(Self { host, port, auth_header })
    }

    /// The first of `HTTPS_PROXY` / `https_proxy` / `HTTP_PROXY` / `http_proxy`
    /// that parses, or `None` when none is set. A set-but-broken variable is
    /// reported, not skipped: silently ignoring it dials direct on a host
    /// whose direct route is dropped.
    pub fn from_env() -> Result<Option<Self>, String> {
        for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            if let Ok(value) = std::env::var(name) {
                if value.trim().is_empty() {
                    continue;
                }
                return Self::from_url(&value).map(Some).map_err(|e| format!("{name}: {e}"));
            }
        }
        Ok(None)
    }
}

fn slot() -> &'static Mutex<Option<ProxyConfig>> {
    static PROXY: OnceLock<Mutex<Option<ProxyConfig>>> = OnceLock::new();
    PROXY.get_or_init(|| Mutex::new(None))
}

/// Configure (or clear, with `None`) the process proxy. The runtime feeds
/// `RuntimeOptions` here at startup; tests scope it per test and reset it
/// before returning.
pub fn configure(config: Option<ProxyConfig>) {
    *slot().lock().expect("proxy slot poisoned") = config;
}

/// Whether a proxy is configured. The three dial sites branch on this.
pub fn is_configured() -> bool {
    slot().lock().expect("proxy slot poisoned").is_some()
}

/// Dial `host:port` through the configured proxy. `host` is a hostname —
/// the proxy resolves it — and must not be a dial-plan IP the proxy was
/// never asked about.
///
/// Fails when no proxy is configured (a caller that did not check
/// [`is_configured`] is a caller guessing), when the proxy is unreachable,
/// when the response head exceeds [`MAX_RESPONSE_HEAD`], when the exchange
/// exceeds [`CONNECT_TIMEOUT`], and when the status is not 2xx — the status
/// and any reason travel in the error, because a 403 names the policy and a
/// timeout names nothing.
pub async fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let config = slot()
        .lock()
        .expect("proxy slot poisoned")
        .clone()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no proxy configured")
        })?;

    tokio::time::timeout(CONNECT_TIMEOUT, connect_via(&config, host, port))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("CONNECT {host}:{port} via {}:{} timed out", config.host, config.port),
            )
        })?
}

async fn connect_via(config: &ProxyConfig, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect((config.host.as_str(), config.port)).await?;

    let mut request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(auth) = &config.auth_header {
        request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if head.len() >= MAX_RESPONSE_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "proxy {}:{} sent {MAX_RESPONSE_HEAD} bytes with no complete response head",
                    config.host, config.port
                ),
            ));
        }
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
            break;
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut response = httparse::Response::new(&mut headers);
    let status = match response.parse(&head).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("proxy response does not parse: {e}"))
    })? {
        httparse::Status::Complete(_) => response.code.unwrap_or(0),
        httparse::Status::Partial => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy response head is partial",
            ))
        }
    };
    if !(200..300).contains(&status) {
        let reason = response.reason.unwrap_or("");
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("proxy refused CONNECT {host}:{port}: {status} {reason}"),
        ));
    }

    Ok(stream)
}
