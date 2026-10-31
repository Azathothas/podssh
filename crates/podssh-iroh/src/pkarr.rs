//! A node's record at a server of pkarr (T-350): its home relay, signed with
//! its key, so that a client whose ticket names an older relay finds it.
//!
//! The record is iroh's own: a signed packet of pkarr whose `_iroh` TXT names
//! `relay=URL` (iroh-dns writes and reads it), so iroh's tools and n0's DNS
//! read it too. It names the relay alone, never an address of the host.
//! podssh puts it and asks for it over podssh-ws, through podssh's proxy and
//! trust store, as it asks a relay's `/ping`: iroh's own publisher and
//! resolver would take the one proxy that the endpoint has, ask at each
//! dial, and say why they failed to their traces alone.
//!
//! The server is n0's when an end's relays are n0's, as Q50 makes n0's
//! relays and n0's server a fallback; [`ENV`] names another one, or `off`.
//! The node's end is [`keep`]; a client's is [`Finder`], which
//! [`crate::Dialer`] asks when the ticket's relay does not reach the node.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint_info::EndpointInfo;
use iroh::{Endpoint, PublicKey, RelayUrl, SecretKey, Watcher as _};
use podssh_ws::{dial, http, ProxyChoice, Trust};
use url::Url;

pub use iroh_dns::pkarr::SignedPacket;
use iroh_dns::pkarr::SignedPacketVerifyError;

/// n0's server of pkarr, as iroh 1.4.1 names it (`N0_DNS_PKARR_RELAY_PROD`);
/// a test holds it to iroh's.
pub const N0: &str = "https://dns.iroh.link/pkarr";

/// The variable that names the server: a URL, or `off` for none.
pub const ENV: &str = "PODSSH_IROH_PKARR";

/// How long a cache of DNS keeps the record's names: iroh's own publisher's
/// value (`DEFAULT_PKARR_TTL`), a short life.
pub const TTL: u32 = 30;

/// The bound on one request, the connection through the proxy included.
pub const LIMIT: Duration = Duration::from_secs(10);

/// How often a node puts its record again while its home relay stays, as
/// iroh's own publisher does (`DEFAULT_REPUBLISH_INTERVAL`).
pub const REPUBLISH: Duration = Duration::from_secs(5 * 60);

/// The first wait after a record could not be put; each next one is twice
/// as long, up to [`REPUBLISH`].
const RETRY: Duration = Duration::from_secs(5);

/// The cap on a response's body: a record is 1104 bytes at most, and an
/// error page may be longer.
const MAX_BODY: usize = 16 * 1024;

/// A server of pkarr: `https://HOST[:PORT][/PATH]`, where a record is
/// `PATH/KEY`, KEY in z-base-32.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server(Url);

impl Server {
    /// The server of `text`. User information, a query and a fragment are
    /// refused, as on a relay's URL; plain HTTP too, as each road of podssh
    /// speaks TLS.
    pub fn parse(text: &str) -> Result<Server, String> {
        let url = Url::parse(text.trim()).map_err(|e| format!("{text:?} is not a URL: {e}"))?;
        if url.scheme() != "https" {
            return Err(format!("{text:?}: a server of pkarr is reached over https:// only"));
        }
        // Not quoted: what follows `https://` may be a password.
        if !url.username().is_empty() || url.password().is_some() {
            return Err("the URL of a server of pkarr takes no user name or password".into());
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(format!(
                "{text:?}: a server of pkarr is https://HOST[:PORT][/PATH], with no query or fragment"
            ));
        }
        let host = url.host_str().ok_or_else(|| format!("{text:?} names no host"))?;
        podssh_ws::names::check_host(host).map_err(|why| format!("{text:?}: {why}"))?;
        Ok(Server(url))
    }

    /// n0's server.
    pub fn n0() -> Server {
        Server::parse(N0).expect("n0's server is a server's URL")
    }

    pub fn url(&self) -> &Url {
        &self.0
    }

    /// The host, for a message and for TLS.
    pub fn host(&self) -> &str {
        self.0.host_str().unwrap_or_default().trim_end_matches('.')
    }

    /// The path of the record of `key`.
    pub fn path_of(&self, key: &PublicKey) -> String {
        format!("{}/{}", self.0.path().trim_end_matches('/'), key.to_z32())
    }
}

impl std::fmt::Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// What the variable says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// Unset or empty: n0's server for n0's relays, else none.
    Default,
    /// `off`: no record is put or asked for.
    Off,
    /// A server that the user names.
    At(Server),
}

/// The choice of the variable's value; a bad one is an error that names it.
pub fn choice(value: Option<&str>) -> Result<Choice, String> {
    match value.map(str::trim) {
        None | Some("") => Ok(Choice::Default),
        Some(v) if v.eq_ignore_ascii_case("off") => Ok(Choice::Off),
        Some(v) => Server::parse(v).map(Choice::At).map_err(|why| format!("{ENV}: {why}")),
    }
}

/// [`choice`] of this process's variable.
pub fn choice_from_environment() -> Result<Choice, String> {
    choice(std::env::var(ENV).ok().as_deref())
}

/// Whether each relay of `relays` is one of n0's public relays: the table
/// of [`crate::relays::DEFAULT`], by host, with or without the final dot.
pub fn n0_relays(relays: &[RelayUrl]) -> bool {
    let normal = |host: &str| host.trim_end_matches('.').to_ascii_lowercase();
    let table: Vec<String> = crate::relays::defaults().iter().filter_map(|r| r.host_str().map(normal)).collect();
    !relays.is_empty() && relays.iter().all(|r| r.host_str().is_some_and(|h| table.contains(&normal(h))))
}

/// The server for an end whose relays are `relays`: the one that the user
/// named; else n0's when the relays are n0's; else none, as a node on the
/// user's own relays tells n0 nothing.
pub fn server_for(choice: &Choice, relays: &[RelayUrl]) -> Option<Server> {
    match choice {
        Choice::Off => None,
        Choice::At(server) => Some(server.clone()),
        Choice::Default => n0_relays(relays).then(Server::n0),
    }
}

/// [`server_for`] with this process's variable.
pub fn choose(relays: &[RelayUrl]) -> Result<Option<Server>, String> {
    Ok(server_for(&choice_from_environment()?, relays))
}

/// A node's record, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The relays that it names, `https://` alone, in its order.
    pub relays: Vec<RelayUrl>,
    /// When the node signed it, in microseconds since the epoch (pkarr's
    /// sequence number).
    pub signed_at: u64,
}

impl Record {
    /// The names of `packet`, whose signature the caller checked.
    pub fn of(packet: &SignedPacket) -> Result<Record, String> {
        let info = EndpointInfo::from_pkarr_signed_packet(packet)
            .map_err(|e| format!("the record is not iroh's record of a node: {e}"))?;
        // A relay that podssh would not dial is no relay of the record.
        let relays: Vec<RelayUrl> =
            info.relay_urls().filter_map(|url| crate::relays::parse_url(url.as_str()).ok()).collect();
        if relays.is_empty() {
            return Err("the record names no https:// relay".into());
        }
        Ok(Record { relays, signed_at: packet.timestamp().as_micros() })
    }

    /// How long ago the node signed it; none for a time after this host's.
    pub fn age(&self) -> Duration {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros()).unwrap_or_default();
        Duration::from_micros(u64::try_from(now).unwrap_or(u64::MAX).saturating_sub(self.signed_at))
    }
}

/// How a client reads a server's answer for the record of `key`.
pub type Read = fn(&PublicKey, &[u8]) -> Result<Record, String>;

/// The record of `key` in a server's answer: its signature is checked
/// against `key` (iroh-dns's reading), so a record that a server forged, or
/// that another key signed, is refused.
pub fn read(key: &PublicKey, payload: &[u8]) -> Result<Record, String> {
    let packet = SignedPacket::from_relay_payload(key, payload).map_err(|e| {
        if matches!(e, SignedPacketVerifyError::SignatureError { .. }) {
            "the record is not signed by the node's key, and is refused".to_string()
        } else {
            format!("the answer is not a signed record of pkarr: {e}")
        }
    })?;
    Record::of(&packet)
}

/// One request for the record of `key` at `server`: `PUT` with `body`, or
/// `GET`; through `proxy`, the server's certificate checked against `trust`,
/// within `limit`.
async fn request(
    server: &Server,
    method: &str,
    key: &PublicKey,
    body: &[u8],
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
) -> Result<http::Response, String> {
    let host = server.host();
    let port = server.url().port_or_known_default().unwrap_or(443);
    let path = server.path_of(key);
    let host_header = if port == 443 { host.to_string() } else { dial::authority(host, port) };
    let asked = async {
        let mut tls = podssh_ws::client::open_tls(host, port, host, trust, proxy, limit)
            .await
            .map_err(|e| format!("{host}: {e}"))?;
        http::exchange(&mut tls, method, &host_header, &path, &[], body, MAX_BODY)
            .await
            .map_err(|e| format!("{host}: {method} {path}: {e}"))
    };
    tokio::time::timeout(limit, asked).await.map_err(|_| format!("{host}: no answer within {} s", limit.as_secs()))?
}

/// Put the record of `secret`'s key, which names `relay` alone, at `server`.
pub async fn publish(
    server: &Server,
    secret: &SecretKey,
    relay: &RelayUrl,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
) -> Result<(), String> {
    let info = EndpointInfo::new(secret.public()).with_relay_url(relay.clone());
    let packet = info.to_pkarr_signed_packet(secret, TTL).map_err(|e| format!("the record could not be made: {e}"))?;
    let key = secret.public();
    let response = request(server, "PUT", &key, &packet.to_relay_payload(), trust, proxy, limit).await?;
    match response.status {
        200..=299 => Ok(()),
        status => Err(format!("{} answered HTTP {status} {}", server.host(), response.body_text(120))),
    }
}

/// The record of `key` at `server`, checked by `read`; none when the server
/// has none.
pub async fn lookup_with(
    server: &Server,
    key: &PublicKey,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
    read: Read,
) -> Result<Option<Record>, String> {
    let response = request(server, "GET", key, b"", trust, proxy, limit).await?;
    match response.status {
        200 => read(key, &response.body).map(Some),
        404 => Ok(None),
        status => Err(format!("{} answered HTTP {status} {}", server.host(), response.body_text(120))),
    }
}

/// [`lookup_with`] with podssh's [`read`].
pub async fn lookup(
    server: &Server,
    key: &PublicKey,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
) -> Result<Option<Record>, String> {
    lookup_with(server, key, trust, proxy, limit, read).await
}

/// What [`keep`] last said, so that it says each change once.
#[derive(PartialEq, Eq)]
enum Said {
    Put(RelayUrl),
    Failed,
}

/// Keep the record of `endpoint`'s home relay at `server` until the
/// endpoint closes: at once, again when the home relay changes, and each
/// [`REPUBLISH`]; after a failure, again within 5 s, then twice as long each
/// time. `say` hears the first record of each relay, and the first failure
/// of a run of them.
pub async fn keep(endpoint: Endpoint, server: Server, trust: Trust, proxy: ProxyChoice, say: impl Fn(String)) {
    let secret = endpoint.secret_key().clone();
    let mut addrs = endpoint.watch_addr();
    let mut relay = crate::ticket::home_relay(&endpoint);
    let mut said: Option<Said> = None;
    let mut retry = RETRY;
    loop {
        let wait = match &relay {
            None => REPUBLISH,
            Some(url) => match publish(&server, &secret, url, &trust, &proxy, LIMIT).await {
                Ok(()) => {
                    if said.as_ref() != Some(&Said::Put(url.clone())) {
                        say(format!(
                            "its record at {} names the home relay {url}, for a client whose ticket names another",
                            server.host()
                        ));
                        said = Some(Said::Put(url.clone()));
                    }
                    retry = RETRY;
                    REPUBLISH
                }
                Err(why) => {
                    if said != Some(Said::Failed) {
                        say(format!("its record could not be put at {}: {why}; it is tried again", server.host()));
                        said = Some(Said::Failed);
                    }
                    let wait = retry;
                    retry = (retry * 2).min(REPUBLISH);
                    wait
                }
            },
        };
        let deadline = tokio::time::Instant::now() + wait;
        // Until the time to put it again, or a new home relay; a change of
        // the endpoint's other addresses changes nothing in the record.
        loop {
            tokio::select! {
                changed = addrs.updated() => match changed {
                    Ok(addr) => {
                        let now = addr.relay_urls().next().cloned();
                        if now.is_some() && now != relay {
                            relay = now;
                            break;
                        }
                    }
                    // The endpoint closed: the node has stopped.
                    Err(_) => return,
                },
                () = tokio::time::sleep_until(deadline) => break,
            }
        }
    }
}

/// A client's way to the record of a node: the server, the way out to it,
/// and what it says of each lookup.
#[derive(Clone)]
pub struct Finder {
    pub server: Server,
    pub trust: Trust,
    pub proxy: ProxyChoice,
    /// Whether to ask before the first dial: the ticket's relay did not
    /// answer `/ping`, so the node is not reached there either.
    pub first: bool,
    /// What a lookup found, in words, for `-v`.
    pub say: Arc<dyn Fn(String) + Send + Sync>,
    /// The reading of an answer: [`read`]; a test plants another.
    pub read: Read,
}

impl Finder {
    pub fn new(server: Server, trust: Trust, proxy: ProxyChoice) -> Finder {
        Finder { server, trust, proxy, first: false, say: Arc::new(|_: String| {}), read }
    }

    /// Asked before the first dial when `first`.
    pub fn first(mut self, first: bool) -> Finder {
        self.first = first;
        self
    }

    /// With `say` for what each lookup found.
    pub fn saying(mut self, say: impl Fn(String) + Send + Sync + 'static) -> Finder {
        self.say = Arc::new(say);
        self
    }

    /// With `read` in place of [`read`], as a test plants a reader that
    /// skips the check.
    pub fn reading(mut self, read: Read) -> Finder {
        self.read = read;
        self
    }

    /// The record of `key`, within [`LIMIT`].
    pub async fn find(&self, key: &PublicKey) -> Result<Option<Record>, String> {
        lookup_with(&self.server, key, &self.trust, &self.proxy, LIMIT, self.read).await
    }
}

impl std::fmt::Debug for Finder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Finder").field("server", &self.server).field("first", &self.first).finish()
    }
}

#[cfg(test)]
#[path = "pkarr_tests.rs"]
mod tests;
