//! E15 — ⛔ **the DoH request: the endpoint, the error set, and the two queries.**
//!
//! ⛔ **The DoH request reuses E03's `rustls` connector** — ⛔ **not a second TLS
//! stack, not a plaintext port 853 fallback.** ⛔ `podssh-ws` owns the pure-Rust
//! provider and the connector ⛔ (`crates/podssh-ws/src/tls.rs`,
//! `crates/podssh-ws/src/client.rs`), ⛔ and ⛔ **a second TLS client in this
//! crate would be a second answer to ⛔ "which roots does podssh trust"**, ⛔ which
//! is a question with one right answer. ⛔ **The `DohTransport` seam is where that
//! connector is plugged in**, ⛔ and ⛔ **no socket of any kind is opened here.**
//!
//! ⛔ **The DoH endpoint is resolved by IP literal, because `rustls` needs an
//! address to dial**, ⛔ so ⛔ **a DoH request resolved by name makes the
//! fallback depend on the thing it is a fallback for.** ⛔ [`DohEndpoint`]
//! refuses a hostname with no address for exactly that reason.
//!
//! ⛔ **Every query asks for both `A` and `AAAA`, one call each.**
//! **READ**, `dropssh` `src/dns.c:221-223`: ⛔ *"THE DNS QUERY TYPE IS ASKED FOR
//! EXPLICITLY AND BOTH FAMILIES ARE REQUESTED IN ONE CALL, so a name that is
//! AAAA-only does not need a second round trip to be discovered."*
//!
//! ⛔ **An unparseable body and an empty answer are two different errors, and
//! neither is an empty `Vec`.** ⛔ `dns.md`'s third plant requires both, and ⛔
//! ⛔ *"an empty `Vec<SocketAddr>` some caller treats as success"* ⛔ is named
//! there as the defect this module exists to prevent.
//!
//! ⛔ **The three submodules, and why there are three.** ⛔ `wire` holds the
//! question and its encoding ⛔ — ⛔ **it is pure and needs nothing else**;
//! ⛔ `json` holds the reader ⛔ — ⛔ **it is the part that has to be careful**;
//! ⛔ `transport` holds the seam ⛔ — ⛔ **it is the part that touches a socket**.
//!
//! ⛔ **The file was one file once and was 737 lines.** ⛔ **The split is
//! not cosmetic**: ⛔ `wire` is pure and needs nothing else, ⛔ `json` is
//! the part that has to be careful with a peer's bytes, ⛔ and ⛔ `transport`
//! is the only one that can reach a socket. ⛔ **A file a reader cannot hold
//! in one screen stops being reviewed**, ⛔ and ⛔ that is the whole of the
//! 500-line rule.

pub mod json;
pub mod wire;

mod transport;

pub use json::parse_json;
pub use transport::{decode_question, DohTransport, ScriptedTransport};
pub use wire::{base64url, base64url_decode, DohQuery};

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;


/// ⛔ **The two query types.** ⛔ `A` first, then `AAAA`, ⛔ **and both are asked
/// even when the first answers** — a host with both families is the common case
/// and a v6-only host must not cost two round trips to discover.
pub const TYPE_A: &str = "A";
pub const TYPE_AAAA: &str = "AAAA";

/// ⛔ **HTTPS only, and the check is a constructor.** ⛔ `dropssh` `src/dns.c:231-234`
/// accepts both `https://` and `http://` and strips either; ⛔ **podssh does not,
/// and the reason is in the sibling's own comment at `src/dns.c:23-25`**: *"HTTPS
/// only, never plaintext, because the whole point is that a name which cannot be
/// resolved is still a name that must not be sent in the clear to a party that
/// might answer for it wrongly."* ⛔ **An `http://` endpoint is `Err` here and not
/// a fallback.**
pub const SCHEME: &str = "https://";
pub const DEFAULT_PATH: &str = "/dns-query";

/// ⛔ **A DoH endpoint as a `(name, address)` pair, and both are required.**
///
/// ⛔ **The address is an IP literal and the name is for the certificate.** ⛔ This
/// is `relay-hostname.md`'s rule applied to the resolver: a pinned address with
/// no hostname is a TLS failure, because the endpoint is behind an SNI-based
/// certificate ⛔ **and the hostname must therefore survive to
/// `rustls::ServerName` while the address is what gets dialled.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohEndpoint {
    /// ⛔ **The name the certificate must carry.** ⛔ Never empty: an endpoint
    /// with no name to verify is a client with no name to verify *against*, and
    /// `podssh-ws` refuses the same case in `WsClientConfig::validate`.
    pub name: String,
    /// ⛔ **The literal to dial.** ⛔ An IP, never a name ⛔ — a DoH request
    /// resolved by name makes the fallback depend on the thing it is a fallback
    /// for.
    pub address: SocketAddr,
    pub path: String,
}

/// ⛔ **Why an endpoint could not be built.** ⛔ Named, because ⛔ **"DoH did not
/// answer" is the message that costs a session** and each of these has a
/// different fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohError {
    /// ⛔ **Not `https://`.** ⛔ Never downgraded.
    NotHttps { url: String },
    /// ⛔ **A hostname with no addresses.** ⛔ The literal requirement.
    NotAnAddress { url: String, host: String },
    /// ⛔ **No name to verify the certificate against.**
    NoServerName { url: String },
    /// ⛔ **The body was not JSON, or not the shape this reads.** ⛔ **Never a
    /// panic**, and ⛔ **never an empty answer** ⛔ — the endpoint is named.
    Unparseable { endpoint: String, detail: String },
    /// ⛔ **A well-formed answer carrying no records for the name.** ⛔ Distinct
    /// from `Unparseable`, because ⛔ **a real name with no records is a
    /// different fact from a broken endpoint** and the operator's fix differs.
    EmptyAnswer { endpoint: String, name: String, status: Option<i32> },
    /// ⛔ **The endpoint answered with a status that is not a DNS answer.**
    Http { endpoint: String, status: u16 },
    /// ⛔ The transport failed, with its own message.
    Transport { endpoint: String, detail: String },
    /// ⛔ The budget expired.
    TimedOut { endpoint: String, budget: Duration },
}

impl std::fmt::Display for DohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DohError::NotHttps { url } => write!(
                f,
                "DoH endpoint {url} is not https; podssh resolves over HTTPS only, never \
                 plaintext, because a name that cannot be resolved must not be sent in the \
                 clear to a party that might answer for it wrongly"
            ),
            DohError::NotAnAddress { url, host } => write!(
                f,
                "DoH endpoint {url} names {host} and no IP literal; the fallback must not \
                 depend on the resolution it is a fallback for. Configure the endpoint as \
                 (name, address)"
            ),
            DohError::NoServerName { url } => write!(
                f,
                "DoH endpoint {url} carries no hostname; a pinned address with no name is a \
                 TLS failure, because the certificate is issued for the name"
            ),
            DohError::Unparseable { endpoint, detail } => {
                write!(f, "DoH endpoint {endpoint} answered a body that is not a DNS answer: {detail}")
            }
            DohError::EmptyAnswer { endpoint, name, status } => match status {
                Some(s) => write!(
                    f,
                    "DoH endpoint {endpoint} answered status {s} with no A or AAAA record for \
                     {name}; an empty answer is not a resolution"
                ),
                None => write!(
                    f,
                    "DoH endpoint {endpoint} answered with no A or AAAA record for {name}; an \
                     empty answer is not a resolution"
                ),
            },
            DohError::Http { endpoint, status } => {
                write!(f, "DoH endpoint {endpoint} answered HTTP {status}")
            }
            DohError::Transport { endpoint, detail } => {
                write!(f, "DoH endpoint {endpoint}: {detail}")
            }
            DohError::TimedOut { endpoint, budget } => {
                write!(f, "DoH endpoint {endpoint} did not answer within {budget:?}")
            }
        }
    }
}

impl std::error::Error for DohError {}

impl DohEndpoint {
    /// ⛔ **Build an endpoint from a configured URL, refusing everything that
    /// would make the fallback depend on itself.**
    ///
    /// ```text
    /// https://1.1.1.1/dns-query          -> name "1.1.1.1", address 1.1.1.1:443
    /// https://cloudflare-dns.com/dns-query -> Err(NotAnAddress)
    /// http://1.1.1.1/dns-query            -> Err(NotHttps)
    /// ```
    ///
    /// ⛔ **The second line is the whole point and it is a refusal, not a
    /// convenience.** `relay-hostname.md` records the measurement: ⛔ *"on this
    /// development host `curl https://cloudflare-dns.com/dns-query` fails with
    /// `curl: (6) Could not resolve host` while `curl https://1.1.1.1/dns-query`
    /// returns `Status 0`. ⛔ A DoH endpoint specified by name needs the same
    /// resolution podssh is trying to perform."*
    pub fn from_url(url: &str, port: u16) -> Result<Self, DohError> {
        let rest = url.strip_prefix(SCHEME).ok_or_else(|| DohError::NotHttps { url: url.to_string() })?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, DEFAULT_PATH),
        };
        // ⛔ An IPv6 literal in a URL is bracketed, and the brackets are not part
        // of the address.
        let host = authority
            .strip_prefix('[')
            .and_then(|a| a.strip_suffix(']'))
            .unwrap_or(authority);
        if host.is_empty() {
            return Err(DohError::NoServerName { url: url.to_string() });
        }
        let ip: IpAddr = host
            .parse()
            .map_err(|_| DohError::NotAnAddress { url: url.to_string(), host: host.to_string() })?;
        Ok(DohEndpoint {
            name: host.to_string(),
            address: SocketAddr::new(ip, port),
            path: path.to_string(),
        })
    }

    /// ⛔ **A named endpoint with an explicit address** — the operator's form, and
    /// the only way a name that is not an IP literal is ever accepted. ⛔ The name
    /// is required ⛔ **and the address must parse**, because
    /// `relay-hostname.md`'s plant requires a bare-IP configuration with no
    /// hostname to be **rejected at parse time**.
    pub fn named(name: &str, address: &str, port: u16) -> Result<Self, DohError> {
        if name.is_empty() {
            return Err(DohError::NoServerName { url: address.to_string() });
        }
        let host = address
            .strip_prefix('[')
            .and_then(|a| a.strip_suffix(']'))
            .unwrap_or(address);
        let ip: IpAddr = host.parse().map_err(|_| DohError::NotAnAddress {
            url: format!("{name}={address}"),
            host: host.to_string(),
        })?;
        Ok(DohEndpoint {
            name: name.to_string(),
            address: SocketAddr::new(ip, port),
            path: DEFAULT_PATH.to_string(),
        })
    }

    /// ⛔ **The GET line.** ⛔ **No `name=` goes into the `Host` header** — the
    /// header carries the endpoint's own authority, ⛔ **and no token ever goes
    /// into a URL**, which is the one rule E02's `endpoint.rs` already states.
    pub fn request_line(&self, query: DohQuery) -> String {
        format!("GET {path}?dns={encoded} HTTP/1.1", path = self.path, encoded = query.wire())
    }

    /// ⛔ **The headers that go with it.**
    ///
    /// ⛔ **`host` carries the literal address and never the DoH name**, and the
    /// reason is worth stating because it is the opposite of what an operator
    /// would guess: the `SNI` and the certificate check use `DohEndpoint::name`,
    /// while the `Host` header tells the server which endpoint was reached. ⛔ A
    /// name in `Host` would make the server answer for a vhost podssh is not
    /// asking for, ⛔ **and E17's measurement is that the pool answers for the
    /// name in SNI and for the address on the wire.**
    pub fn headers(&self) -> Vec<(String, String)> {
        let authority = match self.address {
            SocketAddr::V4(_) => self.address.to_string(),
            SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
        };
        vec![
            ("host".to_string(), authority),
            ("accept".to_string(), "application/dns-json".to_string()),
            ("connection".to_string(), "close".to_string()),
        ]
    }
}

/// ⛔ **What an HTTP response carried.** ⛔ Separated from the wire so the body is
/// parsed by a function that takes a `&str` ⛔ **and the plants can hand it the
/// two bodies `dns.md` names**: an unparseable one and a real name with an empty
/// answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohResponse {
    pub status: u16,
    pub body: String,
}

/// ⛔ **A DNS JSON answer, as far as this module reads it.** ⛔ **Only the two
/// fields that matter, and the rest is ignored** ⛔ — a DoH server may add fields
/// and a strict parser would turn a version bump into a resolution failure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DohAnswer {
    pub status: Option<i32>,
    pub addresses: Vec<IpAddr>,
    /// ⛔ **`TC` — truncated.** ⛔ A truncated answer is ⛔ **not** a resolution:
    /// the nameserver ran out of room, so the answer is incomplete and a caller
    /// that dialed it would be dialing a partial fact.
    pub truncated: bool,
}
