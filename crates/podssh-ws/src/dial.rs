//! Opening the TCP connection to the relay: directly, or through an HTTP
//! CONNECT proxy or a SOCKS5 proxy (T-070, `socks5.rs`) named by the
//! environment (`https_proxy`, `HTTPS_PROXY`, `all_proxy`, `ALL_PROXY`, minus
//! anything `no_proxy`/`NO_PROXY` excludes).
//!
//! On the hosts podssh is for, the proxy is often the only way out: a direct
//! `connect()` is refused or silently dropped and DNS does not resolve, while
//! the proxy accepts `CONNECT name:443` and resolves the name itself. So the
//! proxy path sends the relay's *name*, never an address, and needs no DNS.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

pub use crate::mptcp::Multipath;
pub use crate::proxy::{HttpProxy, Proxy, ProxyKind};

/// The longest CONNECT response head podssh reads before giving up.
const MAX_PROXY_RESPONSE: usize = 16 * 1024;
/// How long one address may take to connect before the next is tried as
/// well (RFC 8305's attempt delay): an address that never answers, as an
/// IPv6 address with no route can, does not hold the whole dial (T-265).
pub const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// How to reach the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyChoice {
    /// Use the proxy the environment names, if any (the default).
    FromEnvironment,
    /// Connect directly and ignore the environment.
    Direct,
    /// Use this proxy.
    Via(Proxy),
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
    /// The proxy answered CONNECT with a status other than 2xx; a SOCKS5
    /// proxy's refusal carries the HTTP status of the same case (403 for its
    /// rules, 407 for its authentication, 502 for the rest).
    ProxyRefused { proxy: String, target: String, status: u16, reason: String },
    /// The proxy did not answer as its protocol says.
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
                write!(f, "the proxy {proxy} did not answer as its protocol says: {detail}")
            }
        }
    }
}

impl std::error::Error for DialError {}

/// The variables that name a proxy, in the order podssh reads them: the
/// first that is set, and not empty, is the proxy.
pub const PROXY_VARS: [&str; 4] = ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"];

/// The variables that list the hosts that bypass the proxy, in the order
/// podssh reads them.
pub const NO_PROXY_VARS: [&str; 2] = ["no_proxy", "NO_PROXY"];

/// The proxy, if any, the process environment selects for `target_host`.
pub fn proxy_from_env(target_host: &str) -> Result<Option<Proxy>, String> {
    proxy_from_vars(target_host, |name| std::env::var(name).ok())
}

/// [`proxy_from_env`] with the variables supplied by the caller. Lower-case
/// names win over upper-case ones, as in curl; an empty value counts as unset.
/// A loopback target never goes through a proxy (as in Go's net/http): the
/// proxy's loopback is not this host's, and podbox measured a proxy answering
/// 405 to `CONNECT 127.0.0.1`. A name pinned to loopback addresses only is
/// such a target too (T-318).
pub fn proxy_from_vars(target_host: &str, var: impl Fn(&str) -> Option<String>) -> Result<Option<Proxy>, String> {
    if is_loopback(target_host) || pinned_to_loopback(target_host) {
        return Ok(None);
    }
    let get = |names: &[&str]| names.iter().find_map(|n| var(n).filter(|v| !v.trim().is_empty()));
    let Some(url) = get(&PROXY_VARS) else {
        return Ok(None);
    };
    if let Some(list) = get(&NO_PROXY_VARS) {
        if no_proxy_matches(&list, target_host) {
            return Ok(None);
        }
    }
    Proxy::parse(&url).map(Some)
}

/// A name that `--relay-addr` or `PODSSH_RELAY_ADDR` pins to loopback
/// addresses alone: a relay on this host, which no proxy can reach. A pin to
/// any other address keeps the proxy, which is given the name.
fn pinned_to_loopback(host: &str) -> bool {
    let pins = crate::resolve::pinned(host);
    !pins.is_empty() && pins.iter().all(std::net::IpAddr::is_loopback)
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
/// suffix on an entry is ignored. Matching is case-insensitive. A block
/// `ADDR/BITS`, IPv4 or IPv6, matches each address inside it, as in curl
/// (7.86 on), Go and Python's requests; a name is never resolved for it.
pub fn no_proxy_matches(list: &str, host: &str) -> bool {
    no_proxy_entry(list, host).is_some()
}

/// The first entry of a `no_proxy` list that excludes `host`, by the rules of
/// [`no_proxy_matches`]: `podssh doctor` names it.
pub fn no_proxy_entry<'a>(list: &'a str, host: &str) -> Option<&'a str> {
    let host = host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
    list.split(|c: char| c == ',' || c.is_whitespace()).map(str::trim).filter(|e| !e.is_empty()).find(|raw| {
        if *raw == "*" || in_block(raw, &host) {
            return true;
        }
        let entry = match split_host_port(raw) {
            Ok((h, _)) => h,
            Err(_) => raw.to_string(),
        };
        let entry = entry.trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
        !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}")))
    })
}

/// Whether `host`, an address, lies inside the block `entry` (`ADDR/BITS`). An
/// IPv4 address written as IPv6 (`::ffff:10.1.2.3`) is the IPv4 address.
fn in_block(entry: &str, host: &str) -> bool {
    use std::net::IpAddr;
    let Some((net, bits)) = entry.split_once('/') else { return false };
    let (Ok(net), Ok(bits)) =
        (net.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>(), bits.parse::<u32>())
    else {
        return false;
    };
    let Ok(addr) = host.parse::<IpAddr>() else { return false };
    let addr = match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        v4 => v4,
    };
    match (net, addr) {
        (IpAddr::V4(net), IpAddr::V4(addr)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(net) & mask == u32::from(addr) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(net) & mask == u128::from(addr) & mask
        }
        _ => false,
    }
}

/// Open a TCP connection to `host:port`, through the proxy `proxy` selects.
/// The whole operation (resolution, connect, and the CONNECT exchange) is
/// bounded by `timeout`.
pub async fn dial(host: &str, port: u16, proxy: &ProxyChoice, timeout: Duration) -> Result<TcpStream, DialError> {
    dial_as(host, port, proxy, timeout, false).await.map(|(stream, _)| stream)
}

/// [`dial`], with Multipath TCP asked for (T-172, [`crate::mptcp`]): only a
/// connection with no proxy can carry it, and only Linux makes it. Else, and
/// where the kernel refuses it, the stream is plain TCP, as [`dial`] gives
/// it; the second value says which, and why.
pub async fn dial_multipath(
    host: &str,
    port: u16,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<(TcpStream, Multipath), DialError> {
    dial_as(host, port, proxy, timeout, true).await
}

async fn dial_as(
    host: &str,
    port: u16,
    proxy: &ProxyChoice,
    timeout: Duration,
    multipath: bool,
) -> Result<(TcpStream, Multipath), DialError> {
    check_name(host)?;
    let proxy = match proxy {
        ProxyChoice::Direct => None,
        ProxyChoice::Via(p) => Some(p.clone()),
        ProxyChoice::FromEnvironment => proxy_from_env(host).map_err(DialError::BadProxy)?,
    };
    let deadline = Instant::now() + timeout;
    // Through a proxy, MPTCP could reach the proxy only, never the target.
    let proxied = || Multipath::Plain("a proxy carries the connection, and Multipath TCP would reach it only".into());
    let (stream, how) = match proxy {
        None => connect_race(host, port, deadline, timeout, multipath.then(crate::mptcp::probe)).await?,
        Some(p) if p.kind == ProxyKind::Socks5 => {
            (crate::socks5::connect(&p, host, port, deadline, timeout).await?, proxied())
        }
        Some(p) => (connect_via(&p, host, port, deadline, timeout).await?, proxied()),
    };
    // A keystroke and an echo must not wait for Nagle.
    let _ = stream.set_nodelay(true);
    Ok((stream, how))
}

/// Resolve and connect: the addresses in the order of [`interleave`], each
/// started [`ATTEMPT_DELAY`] after the one before, or at once when the one
/// before failed; the first that connects wins, and the others stop.
pub(crate) async fn connect_direct(
    host: &str,
    port: u16,
    deadline: Instant,
    budget: Duration,
) -> Result<TcpStream, DialError> {
    connect_race(host, port, deadline, budget, None).await.map(|(stream, _)| stream)
}

/// One attempt of the race: plain TCP, or with `ask`, the probe's answer,
/// Multipath TCP where the host offers it.
async fn attempt(addr: SocketAddr, ask: Option<Result<(), String>>) -> std::io::Result<(TcpStream, Multipath)> {
    match ask {
        Some(offer) => crate::mptcp::connect(addr, offer).await,
        None => Ok((TcpStream::connect(addr).await?, Multipath::Plain("Multipath TCP was not asked for".into()))),
    }
}

/// [`connect_direct`], each attempt as `ask` says.
async fn connect_race(
    host: &str,
    port: u16,
    deadline: Instant,
    budget: Duration,
    ask: Option<Result<(), String>>,
) -> Result<(TcpStream, Multipath), DialError> {
    let target = authority(host, port);
    // Pinned addresses, the system resolver, then DNS over HTTPS: a host with
    // a broken resolver but working TCP egress still gets there.
    let addrs = crate::resolve::resolve(host, port, deadline)
        .await
        .map_err(|detail| DialError::Resolve { host: host.to_string(), detail })?;
    if Instant::now() >= deadline {
        return Err(DialError::Timeout { step: format!("resolving {host}"), after: budget });
    }
    let mut waiting = interleave(addrs).into_iter();
    // Dropped at the return: each attempt that still runs stops.
    let mut running = tokio::task::JoinSet::new();
    let mut next_at = Instant::now();
    let mut last = String::new();
    loop {
        if running.is_empty() || Instant::now() >= next_at {
            if let Some(addr) = waiting.next() {
                let ask = ask.clone();
                running.spawn(async move { (addr, attempt(addr, ask).await) });
                next_at = Instant::now() + ATTEMPT_DELAY;
                continue;
            }
            if running.is_empty() {
                return Err(DialError::Connect { target, detail: last });
            }
        }
        let wake = if waiting.len() > 0 { next_at.min(deadline) } else { deadline };
        tokio::select! {
            joined = running.join_next() => match joined {
                Some(Ok((_, Ok(stream)))) => return Ok(stream),
                Some(Ok((addr, Err(e)))) => {
                    last = format!("{addr}: {e}");
                    next_at = Instant::now();
                }
                // An attempt that panicked counts as one that failed.
                Some(Err(e)) => last = e.to_string(),
                None => {}
            },
            _ = tokio::time::sleep_until(wake) => {
                if Instant::now() >= deadline {
                    return Err(DialError::Timeout { step: format!("connecting to {target}"), after: budget });
                }
            }
        }
    }
}

/// The addresses with the families taking turns, the first family first
/// (RFC 8305, section 4): a family that does not work costs one attempt
/// delay, not each of its addresses in a row.
pub fn interleave(addrs: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    let Some(first) = addrs.first().map(|a| a.is_ipv6()) else { return addrs };
    let (mut lead, mut other): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv6() == first);
    let mut out = Vec::with_capacity(lead.len() + other.len());
    lead.reverse();
    other.reverse();
    loop {
        match (lead.pop(), other.pop()) {
            (None, None) => return out,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
}

/// Connect to the proxy and ask it for a tunnel to `host:port`.
async fn connect_via(
    proxy: &Proxy,
    host: &str,
    port: u16,
    deadline: Instant,
    budget: Duration,
) -> Result<TcpStream, DialError> {
    check_name(&proxy.host)?;
    let proxy_name = proxy.to_string();
    let target = authority(host, port);
    let mut stream = connect_direct(&proxy.host, proxy.port, deadline, budget).await.map_err(|e| match e {
        DialError::Timeout { .. } => {
            DialError::Timeout { step: format!("connecting to the proxy {proxy_name}"), after: budget }
        }
        other => DialError::ProxyUnreachable { proxy: proxy_name.clone(), detail: other.to_string() },
    })?;

    let mut request =
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: podssh/{}\r\n", env!("CARGO_PKG_VERSION"));
    if let Some((user, password)) = proxy.credentials() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}").as_bytes());
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

    let (status, reason) =
        parse_status_line(&head).map_err(|detail| DialError::ProxyProtocol { proxy: proxy_name.clone(), detail })?;
    if (200..300).contains(&status) {
        Ok(stream)
    } else {
        // A 407 says why with the schemes that the proxy takes (T-320).
        let reason = if status == 407 {
            crate::proxy_auth::explain(&reason, &head, proxy.credentials().is_some())
        } else {
            reason
        };
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
    let status =
        parts.next().and_then(|s| s.parse::<u16>().ok()).ok_or_else(|| format!("no status code in {line:?}"))?;
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
pub(crate) fn check_name(host: &str) -> Result<(), DialError> {
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
pub(crate) fn split_host_port(s: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(|| format!("unterminated [ in {s:?}"))?;
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
