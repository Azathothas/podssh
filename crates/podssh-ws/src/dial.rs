//! Opening the TCP connection to the relay: directly, or through an HTTP
//! CONNECT proxy named by the environment (`https_proxy`, `HTTPS_PROXY`,
//! `all_proxy`, `ALL_PROXY`, minus anything `no_proxy`/`NO_PROXY` excludes).
//!
//! On the hosts podssh is for, the proxy is often the only way out: a direct
//! `connect()` is refused or silently dropped and DNS does not resolve, while
//! the proxy accepts `CONNECT name:443` and resolves the name itself. So the
//! proxy path sends the relay's *name*, never an address, and needs no DNS.

use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// The longest CONNECT response head podssh reads before giving up.
const MAX_PROXY_RESPONSE: usize = 16 * 1024;

/// An HTTP proxy that tunnels with `CONNECT`.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpProxy {
    pub host: String,
    pub port: u16,
    /// `user:password`, percent-decoded, sent as Basic auth. Never displayed.
    credentials: Option<String>,
}

impl std::fmt::Debug for HttpProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("credentials", &self.credentials.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl std::fmt::Display for HttpProxy {
    /// `host:port` only: the credentials never appear in a message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", authority(&self.host, self.port))
    }
}

impl HttpProxy {
    /// Parse `http://[user:pass@]host[:port][/]`, or a bare `host:port`. The
    /// port defaults to 80, as for any `http://` URL.
    pub fn parse(url: &str) -> Result<HttpProxy, String> {
        let url = url.trim();
        let rest = match url.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
            Some((scheme, _)) => {
                return Err(format!(
                    "proxy scheme {scheme}:// is not supported; podssh speaks HTTP CONNECT to an http:// proxy"
                ))
            }
            None => url,
        };
        let rest = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let (credentials, hostport) = match rest.rsplit_once('@') {
            Some((userinfo, hostport)) => (Some(percent_decode(userinfo)?), hostport),
            None => (None, rest),
        };
        let (host, port) = split_host_port(hostport)?;
        let port = port.unwrap_or(80);
        if host.is_empty() {
            return Err("the proxy URL names no host".into());
        }
        Ok(HttpProxy { host, port, credentials })
    }
}

/// How to reach the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyChoice {
    /// Use the proxy the environment names, if any (the default).
    FromEnvironment,
    /// Connect directly and ignore the environment.
    Direct,
    /// Use this proxy.
    Via(HttpProxy),
}

/// Why a connection could not be opened. Every message names what failed and
/// the address or proxy involved, and never a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialError {
    /// The target or proxy name is not usable (empty, or contains whitespace
    /// or control characters that would break the request).
    InvalidTarget(String),
    /// The proxy settings in the environment could not be understood.
    BadProxy(String),
    /// The name did not resolve (direct connections only).
    Resolve { host: String, detail: String },
    /// Every address failed.
    Connect { target: String, detail: String },
    /// A step did not finish in time.
    Timeout { step: String, after: Duration },
    /// The proxy itself could not be reached.
    ProxyUnreachable { proxy: String, detail: String },
    /// The proxy answered CONNECT with a status other than 2xx.
    ProxyRefused { proxy: String, target: String, status: u16, reason: String },
    /// The proxy did not answer like an HTTP proxy.
    ProxyProtocol { proxy: String, detail: String },
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::InvalidTarget(why) => write!(f, "invalid destination: {why}"),
            DialError::BadProxy(why) => write!(f, "the proxy setting is not usable: {why}"),
            DialError::Resolve { host, detail } => write!(f, "could not resolve {host}: {detail}"),
            DialError::Connect { target, detail } => write!(f, "could not connect to {target}: {detail}"),
            DialError::Timeout { step, after } => write!(f, "{step} timed out after {}s", after.as_secs()),
            DialError::ProxyUnreachable { proxy, detail } => {
                write!(f, "could not reach the proxy {proxy}: {detail}")
            }
            DialError::ProxyRefused { proxy, target, status, reason } => {
                write!(f, "the proxy {proxy} refused CONNECT {target}: {status} {reason}")
            }
            DialError::ProxyProtocol { proxy, detail } => {
                write!(f, "the proxy {proxy} did not answer like an HTTP proxy: {detail}")
            }
        }
    }
}

impl std::error::Error for DialError {}

/// The proxy, if any, the process environment selects for `target_host`.
pub fn proxy_from_env(target_host: &str) -> Result<Option<HttpProxy>, String> {
    proxy_from_vars(target_host, |name| std::env::var(name).ok())
}

/// [`proxy_from_env`] with the variables supplied by the caller. Lower-case
/// names win over upper-case ones, as in curl; an empty value counts as unset.
/// A loopback target never goes through a proxy (as in Go's net/http): the
/// proxy's loopback is not this host's, and podbox measured a proxy answering
/// 405 to `CONNECT 127.0.0.1`.
pub fn proxy_from_vars(
    target_host: &str,
    var: impl Fn(&str) -> Option<String>,
) -> Result<Option<HttpProxy>, String> {
    if is_loopback(target_host) {
        return Ok(None);
    }
    let get = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| var(n).filter(|v| !v.trim().is_empty()))
    };
    let Some(url) = get(&["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]) else {
        return Ok(None);
    };
    if let Some(list) = get(&["no_proxy", "NO_PROXY"]) {
        if no_proxy_matches(&list, target_host) {
            return Ok(None);
        }
    }
    HttpProxy::parse(&url).map(Some)
}

/// `localhost`, `*.localhost`, `127.0.0.0/8` and `::1`, with or without
/// brackets.
pub fn is_loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    h.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether a `no_proxy` list excludes `host`. Entries are separated by commas
/// or whitespace; `*` matches everything; `example.com`, `.example.com` and
/// `*.example.com` all match `example.com` and its subdomains; a `:port`
/// suffix on an entry is ignored. Matching is case-insensitive.
pub fn no_proxy_matches(list: &str, host: &str) -> bool {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    list.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .any(|entry| {
            if entry == "*" {
                return true;
            }
            let entry = match split_host_port(entry) {
                Ok((h, _)) => h,
                Err(_) => entry.to_string(),
            };
            let entry = entry
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}")))
        })
}

/// Open a TCP connection to `host:port`, through the proxy `proxy` selects.
/// The whole operation (resolution, connect, and the CONNECT exchange) is
/// bounded by `timeout`.
pub async fn dial(
    host: &str,
    port: u16,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<TcpStream, DialError> {
    check_name(host)?;
    let proxy = match proxy {
        ProxyChoice::Direct => None,
        ProxyChoice::Via(p) => Some(p.clone()),
        ProxyChoice::FromEnvironment => proxy_from_env(host).map_err(DialError::BadProxy)?,
    };
    let deadline = Instant::now() + timeout;
    let stream = match proxy {
        None => connect_direct(host, port, deadline, timeout).await?,
        Some(p) => connect_via(&p, host, port, deadline, timeout).await?,
    };
    // A keystroke and an echo must not wait for Nagle.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Resolve and connect, trying every address in turn until one answers.
async fn connect_direct(
    host: &str,
    port: u16,
    deadline: Instant,
    budget: Duration,
) -> Result<TcpStream, DialError> {
    let target = authority(host, port);
    // Pinned addresses, the system resolver, then DNS over HTTPS: a host with
    // a broken resolver but working TCP egress still gets there.
    let addrs = crate::resolve::resolve(host, port, deadline)
        .await
        .map_err(|detail| DialError::Resolve { host: host.to_string(), detail })?;
    if Instant::now() >= deadline {
        return Err(DialError::Timeout { step: format!("resolving {host}"), after: budget });
    }
    let mut last = String::new();
    for addr in addrs {
        match tokio::time::timeout_at(deadline, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = format!("{addr}: {e}"),
            Err(_) => {
                return Err(DialError::Timeout { step: format!("connecting to {target}"), after: budget })
            }
        }
    }
    Err(DialError::Connect { target, detail: last })
}

/// Connect to the proxy and ask it for a tunnel to `host:port`.
async fn connect_via(
    proxy: &HttpProxy,
    host: &str,
    port: u16,
    deadline: Instant,
    budget: Duration,
) -> Result<TcpStream, DialError> {
    check_name(&proxy.host)?;
    let proxy_name = proxy.to_string();
    let target = authority(host, port);
    let mut stream = connect_direct(&proxy.host, proxy.port, deadline, budget)
        .await
        .map_err(|e| match e {
            DialError::Timeout { .. } => DialError::Timeout {
                step: format!("connecting to the proxy {proxy_name}"),
                after: budget,
            },
            other => DialError::ProxyUnreachable { proxy: proxy_name.clone(), detail: other.to_string() },
        })?;

    let mut request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: podssh/{}\r\n",
        env!("CARGO_PKG_VERSION")
    );
    if let Some(credentials) = &proxy.credentials {
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");

    let exchange = async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        read_head_exact(&mut stream).await
    };
    let head = tokio::time::timeout_at(deadline, exchange)
        .await
        .map_err(|_| DialError::Timeout { step: format!("the CONNECT exchange with {proxy_name}"), after: budget })?
        .map_err(|e| DialError::ProxyProtocol { proxy: proxy_name.clone(), detail: e.to_string() })?;

    let (status, reason) = parse_status_line(&head)
        .map_err(|detail| DialError::ProxyProtocol { proxy: proxy_name.clone(), detail })?;
    if (200..300).contains(&status) {
        Ok(stream)
    } else {
        Err(DialError::ProxyRefused { proxy: proxy_name, target, status, reason })
    }
}

/// Read a response head one byte at a time, so nothing after `\r\n\r\n` is
/// consumed: those bytes belong to the TLS session that follows.
async fn read_head_exact(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the connection closed before the response ended",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&head).into_owned());
        }
        if head.len() > MAX_PROXY_RESPONSE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("no end of headers within {MAX_PROXY_RESPONSE} bytes"),
            ));
        }
    }
}

/// `HTTP/1.1 200 Connection Established` → `(200, "Connection Established")`.
pub fn parse_status_line(head: &str) -> Result<(u16, String), String> {
    let line = head.lines().next().unwrap_or_default();
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(format!("not an HTTP status line: {line:?}"));
    }
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("no status code in {line:?}"))?;
    // The reason phrase is the proxy's text and ends up on the user's terminal.
    Ok((status, crate::text::one_line(parts.next().unwrap_or_default())))
}

/// `host:port`, with brackets around an IPv6 literal.
pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Refuse a name that would break a request line or a header.
fn check_name(host: &str) -> Result<(), DialError> {
    if host.is_empty() {
        return Err(DialError::InvalidTarget("the host name is empty".into()));
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#' | '@')) {
        return Err(DialError::InvalidTarget(format!("{host:?} is not a host name")));
    }
    Ok(())
}

/// Split `host`, `host:port`, `[v6]` or `[v6]:port`. A bare IPv6 literal with
/// no brackets is returned whole, with no port.
fn split_host_port(s: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated [ in {s:?}"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().map_err(|_| format!("bad port in {s:?}"))?),
            None if after.is_empty() => None,
            None => return Err(format!("unexpected text after ] in {s:?}")),
        };
        return Ok((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port.parse::<u16>().map_err(|_| format!("bad port in {s:?}"))?;
            Ok((host.to_string(), Some(port)))
        }
        _ => Ok((s.to_string(), None)),
    }
}

/// Decode `%XX` escapes in proxy credentials.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3).ok_or("a % escape is cut short in the proxy credentials")?;
            let value = u8::from_str_radix(hex, 16)
                .map_err(|_| "a % escape in the proxy credentials is not hex".to_string())?;
            out.push(value);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "the proxy credentials are not UTF-8".to_string())
}
