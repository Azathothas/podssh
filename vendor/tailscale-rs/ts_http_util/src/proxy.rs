//! HTTP CONNECT proxy dialer: the sandbox's only egress.
//!
//! On the target host there is no `/dev/net/tun`, no capability, no UDP, and
//! direct 443 is dropped; DNS is broken. The only way out is an HTTP CONNECT
//! proxy, and the proxy resolves — so under proxy the CONNECT authority is
//! always the **hostname** (never a dial-plan IP, never `FixedAddr`), and the
//! local resolver is never consulted.
//!
//! ⛔ **One dialer for all four sites.** Control (`ControlTcpDialer`), DERP
//! (`dial_by_ipusage`), DERP over WebSocket (`ws::connect_with_subprotocol`)
//! and `dial_tcp` all ask [`applies`] for their host, and go through
//! [`connect`] when it says so; [`dial`] makes that choice for a caller that
//! has a host name and no plan (podssh's patch 0017). A fifth dial path that
//! goes direct is how a sandbox node silently keeps the one route that cannot
//! work.
//!
//! A host that the proxy's `no_proxy` list names goes direct
//! ([`ProxyConfig::with_no_proxy`]): the process has one proxy, and the list
//! is how a user keeps one host off it.
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
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Proxy hostname. Dialed by name — never resolved locally first, because
    /// on the target there is nothing to resolve with.
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// `Proxy-Authorization` value (`Basic …`), if the proxy needs one.
    /// Stored encoded so the password is never re-derived per connection.
    auth_header: Option<String>,
    /// The entries of the `no_proxy` list: hosts that go direct.
    no_proxy: Vec<String>,
}

/// The credentials are not shown: Base64 is not a secret's cover (podssh's
/// patch 0017).
impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "auth_header",
                &self.auth_header.as_ref().map(|_| "<redacted>"),
            )
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

impl ProxyConfig {
    /// Parse `http://[user:pass@]host[:port]`. Only the `http` scheme names a
    /// CONNECT proxy; anything else is refused rather than reinterpreted.
    ///
    /// The user name and the password are percent-decoded, as the proxy
    /// expects them, and no error quotes the URL, which may hold them
    /// (podssh's patch 0017).
    pub fn from_url(url: &str) -> Result<Self, String> {
        let parsed =
            url::Url::parse(url).map_err(|e| format!("the proxy URL does not parse: {e}"))?;
        if parsed.scheme() != "http" {
            return Err(format!(
                "the proxy URL is {}://, not http://: only http:// names a CONNECT proxy",
                parsed.scheme()
            ));
        }
        // An IPv6 address without the URL's brackets, as a socket address
        // takes it: `[::1]` resolves nowhere.
        let host = match parsed.host() {
            Some(url::Host::Ipv6(address)) => address.to_string(),
            Some(_) => parsed.host_str().unwrap_or_default().to_string(),
            None => return Err("the proxy URL names no host".to_string()),
        };
        if host.is_empty() {
            return Err("the proxy URL names no host".to_string());
        }
        let port = parsed.port().unwrap_or(DEFAULT_PORT);
        let auth_header = match (parsed.username(), parsed.password()) {
            ("", _) => None,
            (user, pass) => {
                let credentials = format!(
                    "{}:{}",
                    percent_decode(user)?,
                    percent_decode(pass.unwrap_or(""))?
                );
                Some(format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(credentials)
                ))
            }
        };
        Ok(Self {
            host,
            port,
            auth_header,
            no_proxy: Vec::new(),
        })
    }

    /// The same proxy, with `list` as its `no_proxy` list (podssh's patch
    /// 0017): entries apart at commas or white space; `*` is every host;
    /// `example.com`, `.example.com` and `*.example.com` each name
    /// `example.com` and its subdomains; a `:port` on an entry is ignored;
    /// case does not count. These are podssh's rules for the same variable.
    pub fn with_no_proxy(mut self, list: &str) -> Self {
        self.no_proxy = list
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect();
        self
    }

    /// Whether `host` goes direct, by the `no_proxy` list.
    pub fn bypasses(&self, host: &str) -> bool {
        self.no_proxy
            .iter()
            .any(|entry| no_proxy_entry_matches(entry, host))
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

/// Whether a proxy is configured.
pub fn is_configured() -> bool {
    slot().lock().expect("proxy slot poisoned").is_some()
}

/// Whether a dial to `host` goes through the proxy: one is configured, and
/// its `no_proxy` list does not name the host. The dial sites branch on this
/// (podssh's patch 0017).
pub fn applies(host: &str) -> bool {
    slot()
        .lock()
        .expect("proxy slot poisoned")
        .as_ref()
        .is_some_and(|config| !config.bypasses(host))
}

/// Open TCP to `host:port` by name: through the proxy when it
/// [`applies`], else direct, each within [`CONNECT_TIMEOUT`] (podssh's patch
/// 0017). A direct dial had no bound, and waited as long as the system
/// lets a connect wait.
pub async fn dial(host: &str, port: u16) -> io::Result<TcpStream> {
    if applies(host) {
        return connect(host, port).await;
    }
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "connect to {host}:{port} timed out after {} s",
                    CONNECT_TIMEOUT.as_secs()
                ),
            )
        })?
}

/// Whether a `no_proxy` list names `host`, by the rules of
/// [`ProxyConfig::with_no_proxy`].
pub fn no_proxy_matches(list: &str, host: &str) -> bool {
    list.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|entry| no_proxy_entry_matches(entry, host))
}

fn no_proxy_entry_matches(entry: &str, host: &str) -> bool {
    if entry == "*" {
        return true;
    }
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let entry = without_port(entry)
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}")))
}

/// An entry without its `:port`: `[v6]`, `[v6]:port` and `host:port` lose
/// it; a bare IPv6 address, or a port that is not a number, keeps the entry
/// whole.
fn without_port(entry: &str) -> &str {
    if let Some(rest) = entry.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((host, "")) => host,
            Some((host, after))
                if after
                    .strip_prefix(':')
                    .is_some_and(|p| p.parse::<u16>().is_ok()) =>
            {
                host
            }
            _ => entry,
        };
    }
    match entry.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host,
        _ => entry,
    }
}

/// `%XX` escapes decoded, as in a URL's user name and password.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let value = s
                .get(i + 1..i + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                .ok_or_else(|| {
                    "a % escape in the proxy credentials is not two hex digits".to_string()
                })?;
            out.push(value);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "the proxy credentials are not UTF-8".to_string())
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no proxy configured"))?;

    tokio::time::timeout(CONNECT_TIMEOUT, connect_via(&config, host, port))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "CONNECT {host}:{port} via {}:{} timed out",
                    config.host, config.port
                ),
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
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("proxy response does not parse: {e}"),
        )
    })? {
        httparse::Status::Complete(_) => response.code.unwrap_or(0),
        httparse::Status::Partial => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy response head is partial",
            ));
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
