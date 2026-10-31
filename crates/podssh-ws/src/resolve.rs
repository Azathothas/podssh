//! Turning a host name into addresses without trusting that this host's
//! resolver works. In order (`resolve/order.rs`):
//!
//! 1. an IP literal is its own address;
//! 2. addresses pinned for the name ([`set_pins`]: podssh's `--relay-addr` and
//!    `PODSSH_RELAY_ADDR`), for hosts with no DNS at all;
//! 3. the system resolver;
//! 4. the addresses that carried a session to the name within [`FRESH`]
//!    ([`set_remembered`]: podssh keeps them in its cache, T-344);
//! 5. DNS over HTTPS to public resolvers reached by IP literal, whose
//!    certificates are verified against those IPs like any other — for hosts
//!    whose resolver is broken but whose TCP egress works: each resolver's
//!    JSON API where it serves one, and RFC 8484's wire form ([`wire`]) where
//!    it serves none or its answer is not of that form;
//! 6. the older addresses that carried a session, last.
//!
//! With an HTTP proxy none of this runs for the target: the proxy is given the
//! name and resolves it. TLS to the target always checks the target's name, so
//! a wrong pinned, resolved or remembered address fails the handshake instead
//! of connecting somewhere else.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::dial::ProxyChoice;
use crate::http;
use crate::tls::{self, Trust};

pub mod h2;
mod memory;
mod order;
pub mod wire;

pub(crate) use memory::note_dialed;
pub use memory::{dialed, last_dialed, remembered, set_remembered, split, Remembered, FRESH};
pub use order::{resolve, resolve_from, Found, Source, ORDER, SOURCE_WAIT};

/// A public resolver of DNS over HTTPS, by IP literal (a resolver needs no
/// resolver), whose certificate names that address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Doh {
    pub ip: &'static str,
    /// The path of its JSON API (`?name=...&type=...`), where it serves one.
    pub json: Option<&'static str>,
    /// The path of RFC 8484's wire form (`?dns=...`).
    pub wire: &'static str,
    /// Whether it serves HTTP/2 alone, so that it is asked over HTTP/2
    /// (`resolve/h2.rs`): Quad9 answered HTTP/1.1 with `505`.
    pub http2: bool,
}

/// The resolvers, in order: Cloudflare's and Google's, two addresses each,
/// the operators taking turns, then Quad9's two, which serve the wire form
/// alone (Quad9 answered the JSON API's query with 400, 2026-10-31), over
/// HTTP/2 alone (505 to HTTP/1.1, the same day).
pub const DOH_RESOLVERS: &[Doh] = &[
    Doh { ip: "1.1.1.1", json: Some("/dns-query"), wire: "/dns-query", http2: false },
    Doh { ip: "8.8.8.8", json: Some("/resolve"), wire: "/dns-query", http2: false },
    Doh { ip: "1.0.0.1", json: Some("/dns-query"), wire: "/dns-query", http2: false },
    Doh { ip: "8.8.4.4", json: Some("/resolve"), wire: "/dns-query", http2: false },
    Doh { ip: "9.9.9.9", json: None, wire: "/dns-query", http2: true },
    Doh { ip: "149.112.112.112", json: None, wire: "/dns-query", http2: true },
];

/// The bound on one resolver's answers, inside the caller's overall deadline.
const DOH_EACH: Duration = Duration::from_secs(5);

/// The bound on the connection to one resolver: an address that a firewall
/// drops costs this, not [`DOH_EACH`], before the next resolver is asked.
const DOH_CONNECT: Duration = Duration::from_secs(3);

/// The largest answer read: a DNS message is at most 64 KiB.
const MAX_ANSWER: usize = 64 * 1024;

/// A resolver's answer that the name does not exist (DNS status 3). It holds
/// for every record type and every resolver, so the lookup stops there.
pub const NXDOMAIN: &str = "no such name (NXDOMAIN)";

/// How a resolver is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// Its JSON API, `application/dns-json`, which no standard defines.
    Json,
    /// RFC 8484's GET with `?dns=`, `application/dns-message`.
    Wire,
}

impl Form {
    /// The form in a few words, as `podssh doctor` names it.
    pub fn words(self) -> &'static str {
        match self {
            Form::Json => "its JSON API",
            Form::Wire => "RFC 8484's wire form",
        }
    }

    fn accept(self) -> &'static str {
        match self {
            Form::Json => "application/dns-json",
            Form::Wire => "application/dns-message",
        }
    }
}

impl Doh {
    /// The forms to ask, in order: the JSON API first where there is one,
    /// then the wire form, its fallback and the only form of a resolver with
    /// no JSON.
    pub fn forms(&self) -> Vec<Form> {
        self.json.map(|_| Form::Json).into_iter().chain([Form::Wire]).collect()
    }

    /// The request target of the question of `kind` for `name` in `form`.
    fn target(&self, form: Form, name: &str, kind: &str) -> Result<String, String> {
        match (form, self.json) {
            (Form::Json, Some(path)) => Ok(format!("{path}?name={name}&type={kind}")),
            _ => {
                let code = wire::code(kind).ok_or_else(|| format!("no record type {kind}"))?;
                Ok(format!("{}?dns={}", self.wire, wire::query_param(name, code)?))
            }
        }
    }
}

static PINS: RwLock<Vec<(String, IpAddr)>> = RwLock::new(Vec::new());

/// `HOST=IP[,HOST=IP...]`; a host may appear more than once. IPv6 addresses
/// may be bracketed.
pub fn parse_pins(text: &str) -> Result<Vec<(String, IpAddr)>, String> {
    let mut pins = Vec::new();
    for item in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (host, ip) = item.split_once('=').ok_or_else(|| format!("{item:?} is not HOST=IP"))?;
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || !dns_safe(&host) {
            return Err(format!("{item:?}: not a host name"));
        }
        let ip: IpAddr = ip
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| format!("{item:?}: not an IP address"))?;
        pins.push((host, ip));
    }
    Ok(pins)
}

/// Replace the process-wide pins.
pub fn set_pins(pins: Vec<(String, IpAddr)>) {
    *PINS.write().unwrap_or_else(|e| e.into_inner()) = pins;
}

/// The addresses pinned for `host`, in the order given.
pub fn pinned(host: &str) -> Vec<IpAddr> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    PINS.read().unwrap_or_else(|e| e.into_inner()).iter().filter(|(h, _)| *h == host).map(|(_, ip)| *ip).collect()
}

/// Ask the [`DOH_RESOLVERS`] in turn for A, then AAAA records; the first
/// resolver that answers with addresses wins, and the first that says the
/// name does not exist ends the lookup.
pub async fn doh_lookup(host: &str, deadline: Instant) -> Result<Vec<IpAddr>, String> {
    doh_lookup_with(DOH_RESOLVERS, host, deadline).await
}

/// [`doh_lookup`] over a given list of resolvers.
pub async fn doh_lookup_with(resolvers: &[Doh], host: &str, deadline: Instant) -> Result<Vec<IpAddr>, String> {
    let mut reasons = Vec::new();
    for resolver in resolvers {
        if Instant::now() >= deadline {
            reasons.push("out of time".to_string());
            break;
        }
        match doh_ask(resolver, host, deadline).await {
            Ok((ips, _)) => return Ok(ips),
            Err(e) if e.ends_with(NXDOMAIN) => return Err(e),
            Err(e) => reasons.push(e),
        }
    }
    Err(if reasons.is_empty() { "no resolver answered".into() } else { reasons.join("; ") })
}

/// One resolver, straight to its address: A, then AAAA when A gave none,
/// each in the first of its forms that answers in its form, within
/// [`DOH_EACH`] and `deadline`. The addresses and the form that gave them, or
/// why none came, each reason after the resolver's address.
pub async fn doh_ask(resolver: &Doh, host: &str, deadline: Instant) -> Result<(Vec<IpAddr>, Form), String> {
    let ip = resolver.ip;
    let each = (Instant::now() + DOH_EACH).min(deadline);
    let config = tls::config_for(&Trust::Default).map_err(|e| format!("{ip}: {e}"))?;
    let mut forms = resolver.forms();
    let (mut found, mut by, mut reasons) = (Vec::new(), None, Vec::new());
    'kinds: for kind in ["A", "AAAA"] {
        while let Some(&form) = forms.first() {
            match tokio::time::timeout_at(each, ask_direct(&config, resolver, form, host, kind)).await {
                Ok(Ok(mut ips)) => {
                    found.append(&mut ips);
                    by = Some(form);
                    break;
                }
                Ok(Err(Miss::Said(e))) if e == NXDOMAIN => return Err(format!("{ip}: {e}")),
                // The other form would say the same.
                Ok(Err(Miss::Said(e))) => {
                    reasons.push(format!("{ip}: {e}"));
                    break;
                }
                // Not served here, or not as podssh reads it: the next form,
                // for this question and the next.
                Ok(Err(Miss::Form(e))) => {
                    reasons.push(format!("{ip} ({}): {e}", form.words()));
                    forms.remove(0);
                }
                Ok(Err(Miss::Way(e))) => {
                    reasons.push(format!("{ip}: {e}"));
                    break 'kinds;
                }
                Err(_) => {
                    reasons.push(format!("{ip}: timed out"));
                    break 'kinds;
                }
            }
        }
        if !found.is_empty() {
            break;
        }
    }
    match by {
        Some(form) if !found.is_empty() => Ok((found, form)),
        _ if reasons.is_empty() => Err(format!("{ip}: no addresses")),
        _ => Err(reasons.join("; ")),
    }
}

/// Why a question got no addresses: the way to the resolver failed, and the
/// other form would meet the same; the answer was not of the form asked, and
/// the other form may work; or the resolver said why there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Miss {
    Way(String),
    Form(String),
    Said(String),
}

/// What an answer gives, by `parse`, or why it gives nothing. The status of a
/// resolver that is busy or broken is the way's: the other form would meet it.
fn read<T>(response: &http::Response, parse: impl FnOnce(&[u8]) -> Result<T, String>) -> Result<T, Miss> {
    match response.status {
        200 => parse(&response.body).map_err(|e| if said(&e) { Miss::Said(e) } else { Miss::Form(e) }),
        status @ (429 | 500..=599) => Err(Miss::Way(format!("HTTP {status}"))),
        status => Err(Miss::Form(format!("HTTP {status}"))),
    }
}

/// Whether the text of a parse is a resolver's own status, rather than an
/// answer of another form than the one asked.
fn said(e: &str) -> bool {
    e == NXDOMAIN || e.strip_prefix("DNS status ").is_some_and(|n| n.parse::<u16>().is_ok())
}

/// One question over a connection of its own, straight to the resolver.
async fn ask_direct(
    config: &Arc<ClientConfig>,
    resolver: &Doh,
    form: Form,
    host: &str,
    kind: &str,
) -> Result<Vec<IpAddr>, Miss> {
    let target = resolver.target(form, host, kind).map_err(Miss::Way)?;
    let response = get_direct(config, resolver, &target, form.accept()).await.map_err(Miss::Way)?;
    read(&response, |body| match (form, wire::code(kind)) {
        (Form::Json, _) => parse_answer(body, kind),
        (Form::Wire, Some(code)) => wire::addrs(body, host, code),
        (Form::Wire, None) => Err(format!("no record type {kind}")),
    })
}

/// GET `target` of `resolver`: TCP within [`DOH_CONNECT`], then TLS
/// verified for its address, and HTTP/2 where it serves no HTTP/1.1.
async fn get_direct(
    config: &Arc<ClientConfig>,
    resolver: &Doh,
    target: &str,
    accept: &str,
) -> Result<http::Response, String> {
    let ip = resolver.ip;
    let name = rustls_pki_types::ServerName::try_from(ip.to_string()).map_err(|e| e.to_string())?;
    let addr: IpAddr = ip.parse().map_err(|_| format!("{ip} is not an IP"))?;
    let tcp = tokio::time::timeout(DOH_CONNECT, TcpStream::connect(SocketAddr::new(addr, 443)))
        .await
        .map_err(|_| format!("no connection within {} s", DOH_CONNECT.as_secs()))?
        .map_err(|e| e.to_string())?;
    if resolver.http2 {
        return h2::get_over(config, tcp, ip, target, accept, MAX_ANSWER).await;
    }
    let mut stream = tokio_rustls::TlsConnector::from(config.clone())
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS: {}", tls::handshake_failure(&e)))?;
    http::exchange(&mut stream, "GET", ip, target, &[("Accept", accept)], b"", MAX_ANSWER)
        .await
        .map_err(|e| e.to_string())
}

/// The addresses in a DNS JSON answer (`Answer[].data` of type 1 or 28).
pub fn parse_answer(body: &[u8], kind: &str) -> Result<Vec<IpAddr>, String> {
    let want: u64 = if kind == "AAAA" { 28 } else { 1 };
    Ok(answers(body, want)?.iter().filter_map(|data| data.parse().ok()).collect())
}

/// The `data` of each answer of the type `want` in a DNS JSON answer, or why
/// there is none.
fn answers(body: &[u8], want: u64) -> Result<Vec<String>, String> {
    let doc: serde_json::Value = serde_json::from_slice(body).map_err(|_| "not a DNS JSON answer".to_string())?;
    match doc.get("Status").and_then(|s| s.as_u64()) {
        Some(0) => {}
        Some(3) => return Err(NXDOMAIN.to_string()),
        other => {
            return Err(format!("DNS status {}", other.map(|s| s.to_string()).unwrap_or_else(|| "missing".into())))
        }
    }
    Ok(doc
        .get("Answer")
        .and_then(|a| a.as_array())
        .map(|answers| {
            answers
                .iter()
                .filter(|a| a.get("type").and_then(|t| t.as_u64()) == Some(want))
                .filter_map(|a| a.get("data").and_then(|d| d.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// One SRV record (RFC 2782): where a service is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    /// The target's name, with no final dot.
    pub target: String,
}

/// The SRV records in a DNS JSON answer: each `data` of type 33 is
/// `PRIORITY WEIGHT PORT TARGET`; one that does not read so is left out.
pub fn parse_srv(body: &[u8]) -> Result<Vec<Srv>, String> {
    Ok(answers(body, 33)?
        .iter()
        .filter_map(|data| {
            let mut field = data.split_whitespace();
            let (priority, weight, port) = (field.next()?.parse().ok()?, field.next()?.parse().ok()?, field.next()?);
            let target = field.next()?.trim_end_matches('.').to_ascii_lowercase();
            (field.next().is_none() && dns_safe(&target)).then_some(Srv {
                priority,
                weight,
                port: port.parse().ok()?,
                target,
            })
        })
        .collect())
}

/// The SRV records of `name`, from the [`DOH_RESOLVERS`] in turn, through
/// `proxy` when one is set, as podssh reaches anything else (T-339), each in
/// the first of its forms that answers in its form (T-344): the first
/// resolver that answers wins.
pub async fn doh_srv(name: &str, proxy: &ProxyChoice, deadline: Instant) -> Result<Vec<Srv>, String> {
    if !dns_safe(name) {
        return Err(format!("{name:?} is not a name to ask a resolver for"));
    }
    let mut reasons = Vec::new();
    for resolver in DOH_RESOLVERS {
        let ip = resolver.ip;
        for form in resolver.forms() {
            let left = deadline.saturating_duration_since(Instant::now()).min(DOH_EACH);
            if left.is_zero() {
                reasons.push("out of time".to_string());
                return Err(reasons.join("; "));
            }
            let target = resolver.target(form, name, "SRV")?;
            let answer = if resolver.http2 {
                let config = crate::tls::config_for(&Trust::Default).map_err(|e| e.to_string())?;
                h2::get_via(&config, ip, &target, form.accept(), MAX_ANSWER, proxy, left).await.map_err(Miss::Way)
            } else {
                crate::client::https_get_accepting(
                    ip,
                    443,
                    &target,
                    form.accept(),
                    MAX_ANSWER,
                    &Trust::Default,
                    proxy,
                    left,
                )
                .await
                .map_err(|e| Miss::Way(e.to_string()))
            };
            let records = answer.and_then(|response| {
                read(&response, |body| match form {
                    Form::Json => parse_srv(body),
                    Form::Wire => wire::srv(body, name),
                })
            });
            match records {
                Ok(records) => return Ok(records),
                Err(Miss::Said(e)) if e == NXDOMAIN => return Err(format!("{ip}: {e}")),
                Err(Miss::Form(e)) => reasons.push(format!("{ip} ({}): {e}", form.words())),
                Err(Miss::Said(e) | Miss::Way(e)) => {
                    reasons.push(format!("{ip}: {e}"));
                    break;
                }
            }
        }
    }
    Err(if reasons.is_empty() { "no resolver answered".into() } else { reasons.join("; ") })
}

/// Letters, digits, `.`, `-` and `_` only: safe in a query string and in DNS.
fn dns_safe(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}

#[cfg(test)]
mod tests;
