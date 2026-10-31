//! The relay's pool of hosts, as its `/relays.json` publishes it, cached
//! between runs so podssh knows where else to go before the first host fails.
//!
//! The pool is fetched only when a token is minted (rarely: tokens last up to
//! 72 h), so it costs no extra connection on an ordinary run. Until a pool is
//! cached, the default relay's alternates come from [`SEED`]. Only hosts under
//! the primary relay's own parent domain are accepted, because the token is
//! sent to them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_ws::client::open_tls;
use podssh_ws::{dial, http, ProxyChoice, Trust};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::cache;
use crate::relay::{check_host, Relay, DEFAULT_RELAY_HOST};

/// Hosts of the default relay's pool, read from its `/relays.json` on
/// 2026-10-08 and spread across regions. A cached pool replaces them.
pub const SEED: &[&str] = &[
    "tcp-us-east-1.ssh.relay.ajam.dev",
    "tcp-eu-west-3.ssh.relay.ajam.dev",
    "tcp-ap-southeast-1.ssh.relay.ajam.dev",
    "tcp-azure-westeurope.ssh.relay.ajam.dev",
    "tcp-us-central1.ssh.relay.ajam.dev",
    "tcp-ap-south-1.ssh.relay.ajam.dev",
];

/// A cached pool older than this is still used, and refreshed at the next mint.
pub const STALE_AFTER_MS: i64 = 7 * 24 * 3600 * 1000;

/// The largest `/relays.json` read: the pool is a short list, and a larger
/// body is refused before it takes more of podssh's memory (T-201).
pub const MAX_BODY: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
struct CachedPool {
    fetched_ms: i64,
    hosts: Vec<String>,
    /// The `limits` of the same `/relays.json` (T-342); none in a cache of
    /// an older podssh.
    #[serde(default)]
    limits: Limits,
}

/// The relay's `limits`, as its `/relays.json` gives them (T-342): each
/// one that is there and a whole number above zero. podssh's budgets go
/// under them and its cap on a received frame widens to them
/// (`relay::byte_budget_under`, `relay::time_budget`,
/// `podssh_ws::frame::receive_cap`); none is fetched for this alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub idle_timeout_ms: Option<u64>,
    pub max_session_ms: Option<u64>,
    pub max_session_bytes: Option<u64>,
    pub max_frame_bytes: Option<u64>,
}

/// The `limits` of a `/relays.json` body: a value that is missing, not a
/// whole number, or 0 is left out, as if the relay had said nothing.
pub fn parse_limits(body: &[u8]) -> Limits {
    let doc: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let get = |name: &str| doc.get("limits").and_then(|l| l.get(name)).and_then(|v| v.as_u64()).filter(|n| *n > 0);
    Limits {
        idle_timeout_ms: get("idle_timeout_ms"),
        max_session_ms: get("max_session_ms"),
        max_session_bytes: get("max_session_bytes"),
        max_frame_bytes: get("max_frame_bytes"),
    }
}

/// The limits cached with `primary`'s pool; none when nothing is cached.
pub fn cached_limits(primary: &str) -> Limits {
    cache::load_file(&file_name(primary))
        .and_then(|text| serde_json::from_str::<CachedPool>(&text).ok())
        .map(|c| c.limits)
        .unwrap_or_default()
}

/// The limits of the relay that this run's sessions use: those cached with
/// the primary of the last session that the opener opened.
static IN_USE: std::sync::RwLock<Limits> = std::sync::RwLock::new(Limits {
    idle_timeout_ms: None,
    max_session_ms: None,
    max_session_bytes: None,
    max_frame_bytes: None,
});

/// Keep `limits` as the run's, for the budgets of its sessions.
pub fn set_in_use(limits: Limits) {
    *IN_USE.write().unwrap_or_else(|e| e.into_inner()) = limits;
}

/// The run's limits: none until a session opened.
pub fn in_use() -> Limits {
    *IN_USE.read().unwrap_or_else(|e| e.into_inner())
}

/// The cache file of the pool of `primary`.
pub fn file_name(primary: &str) -> String {
    format!("relay-pool-{}.json", cache::safe_name(primary))
}

/// The alternates for `primary`, best first: the cached pool, else (for the
/// default relay only) [`SEED`].
pub fn alternates(primary: &str) -> Vec<String> {
    let cached: Vec<String> = cache::load_file(&file_name(primary))
        .and_then(|text| serde_json::from_str::<CachedPool>(&text).ok())
        .map(|c| c.hosts)
        .unwrap_or_default();
    let hosts: Vec<String> = if !cached.is_empty() {
        cached
    } else if primary.eq_ignore_ascii_case(DEFAULT_RELAY_HOST) {
        SEED.iter().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    };
    hosts.into_iter().filter(|h| same_deployment(primary, h)).collect()
}

/// The pool cached for `primary`: when it was fetched, and how many hosts
/// it has.
pub fn cached(primary: &str) -> Option<(i64, usize)> {
    cache::load_file(&file_name(primary))
        .and_then(|text| serde_json::from_str::<CachedPool>(&text).ok())
        .map(|c| (c.fetched_ms, c.hosts.len()))
}

/// Whether the pool cached for `primary` is missing or older than
/// [`STALE_AFTER_MS`] at `now_ms`.
pub fn needs_refresh(primary: &str, now_ms: i64) -> bool {
    cache::load_file(&file_name(primary))
        .and_then(|text| serde_json::from_str::<CachedPool>(&text).ok())
        .is_none_or(|c| now_ms.saturating_sub(c.fetched_ms) > STALE_AFTER_MS || c.hosts.is_empty())
}

/// Whether `host` belongs to `primary`'s deployment: another host under its
/// parent domain (for `tcp.ssh.relay.ajam.dev`, anything under
/// `ssh.relay.ajam.dev`). A parent with no dot (a bare top-level domain) never
/// matches.
pub fn same_deployment(primary: &str, host: &str) -> bool {
    let primary = primary.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let Some((_, parent)) = primary.split_once('.') else { return false };
    parent.contains('.') && host != primary && check_host(&host).is_ok() && host.ends_with(&format!(".{parent}"))
}

/// The `pool[].host` names of a `/relays.json` body, in its order, kept only
/// when they belong to `primary`'s deployment.
pub fn parse_pool(body: &[u8], primary: &str) -> Result<Vec<String>, String> {
    #[derive(Deserialize)]
    struct Doc {
        pool: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        host: String,
    }
    let doc: Doc = serde_json::from_slice(body).map_err(|_| "the pool is not the expected JSON".to_string())?;
    let mut hosts: Vec<String> = Vec::new();
    for entry in doc.pool {
        let host = entry.host.trim().to_ascii_lowercase();
        if same_deployment(primary, &host) && !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    if hosts.is_empty() {
        return Err("the pool lists no usable host".into());
    }
    Ok(hosts)
}

/// Fetch `/relays.json` from `relay` and cache its pool under `primary`.
/// Returns how many hosts were cached.
pub async fn refresh(
    relay: &Relay,
    primary: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<usize, String> {
    let mut tls =
        open_tls(&relay.host, relay.port, &relay.host, trust, proxy, timeout).await.map_err(|e| e.to_string())?;
    let host_header = if relay.port == 443 { relay.host.clone() } else { dial::authority(&relay.host, relay.port) };
    let (hosts, limits) = tokio::time::timeout(timeout, request_with_limits(&mut tls, &host_header, primary))
        .await
        .map_err(|_| format!("the pool request took more than {} s", timeout.as_secs()))??;
    let body = serde_json::to_vec(&CachedPool { fetched_ms: now_ms(), hosts: hosts.clone(), limits })
        .map_err(|e| e.to_string())?;
    cache::store_file(&file_name(primary), &body)?;
    Ok(hosts.len())
}

/// The hosts of `primary`'s deployment that `/relays.json` lists, asked for
/// over `stream`, with the body read up to [`MAX_BODY`] bytes.
pub async fn request<S>(stream: &mut S, host_header: &str, primary: &str) -> Result<Vec<String>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    request_with_limits(stream, host_header, primary).await.map(|(hosts, _)| hosts)
}

/// [`request`], with the `limits` of the same body.
pub async fn request_with_limits<S>(
    stream: &mut S,
    host_header: &str,
    primary: &str,
) -> Result<(Vec<String>, Limits), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let accept = [("Accept", "application/json")];
    let response = http::exchange(stream, "GET", host_header, "/relays.json", &accept, b"", MAX_BODY)
        .await
        .map_err(|e| format!("the pool request failed: {e}"))?;
    if !(200..300).contains(&response.status) {
        return Err(format!("the pool request answered HTTP {}", response.status));
    }
    Ok((parse_pool(&response.body, primary)?, parse_limits(&response.body)))
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_hosts_of_the_same_deployment_are_accepted() {
        let p = DEFAULT_RELAY_HOST;
        assert!(same_deployment(p, "tcp-us-east-1.ssh.relay.ajam.dev"));
        assert!(same_deployment(p, "TCP-EU-WEST-3.SSH.RELAY.AJAM.DEV"));
        assert!(!same_deployment(p, p), "the primary is not its own alternate");
        assert!(!same_deployment(p, "tcp.ssh.relay.ajam.dev.evil.example"));
        assert!(!same_deployment(p, "evil.example"));
        assert!(!same_deployment(p, "relay.ajam.dev"), "the parent itself is not a pool host");
        assert!(!same_deployment(p, "x.ssh.relay.ajam.dev/path"));
        assert!(!same_deployment("relay.example", "x.example"), "a bare TLD parent never matches");
        assert!(!same_deployment("localhost", "x.localhost"));
    }

    #[test]
    fn the_seed_hosts_belong_to_the_default_deployment() {
        for host in SEED {
            assert!(same_deployment(DEFAULT_RELAY_HOST, host), "{host}");
        }
    }

    #[test]
    fn a_relays_json_pool_is_read_in_order_and_filtered() {
        let body = br#"{"service":"tcp-ssh-relay","pool":[
            {"rank":0,"name":"a","host":"tcp-a.ssh.relay.ajam.dev"},
            {"rank":1,"name":"evil","host":"tcp-b.attacker.example"},
            {"rank":2,"name":"default","host":"tcp.ssh.relay.ajam.dev"},
            {"rank":3,"name":"b","host":"tcp-b.ssh.relay.ajam.dev"},
            {"rank":4,"name":"a-again","host":"TCP-A.ssh.relay.ajam.dev"}]}"#;
        assert_eq!(
            parse_pool(body, DEFAULT_RELAY_HOST).unwrap(),
            vec!["tcp-a.ssh.relay.ajam.dev", "tcp-b.ssh.relay.ajam.dev"]
        );
        assert!(parse_pool(b"{\"pool\":[]}", DEFAULT_RELAY_HOST).is_err());
        assert!(parse_pool(b"not json", DEFAULT_RELAY_HOST).is_err());
    }

    /// T-342: the limits of the same body, each a whole number above zero;
    /// a cache of an older podssh, with none, reads as none.
    #[test]
    fn a_relays_json_limits_are_read_and_cached_with_the_pool() {
        let body = br#"{"pool":[],"limits":{"connect_timeout_ms":10000,"idle_timeout_ms":180000,
            "max_session_ms":43200000,"max_session_bytes":67108864,"max_frame_bytes":262144}}"#;
        let limits = parse_limits(body);
        assert_eq!(
            limits,
            Limits {
                idle_timeout_ms: Some(180_000),
                max_session_ms: Some(43_200_000),
                max_session_bytes: Some(64 << 20),
                max_frame_bytes: Some(262_144),
            }
        );
        let odd = br#"{"limits":{"idle_timeout_ms":0,"max_session_bytes":"64 MiB","max_frame_bytes":-1}}"#;
        assert_eq!(parse_limits(odd), Limits::default(), "0, a string and a negative are left out");
        assert_eq!(parse_limits(b"not json"), Limits::default());
        let old: CachedPool = serde_json::from_str(r#"{"fetched_ms":1,"hosts":["a"]}"#).unwrap();
        assert_eq!(old.limits, Limits::default());
        let kept = serde_json::to_string(&CachedPool { fetched_ms: 1, hosts: vec![], limits }).unwrap();
        assert_eq!(serde_json::from_str::<CachedPool>(&kept).unwrap().limits, limits);
    }

    /// T-342: the budgets go under a smaller limit with the same margin, and
    /// a larger one leaves them as they are.
    #[test]
    fn the_budgets_go_under_the_relays_limits_and_never_above_their_own() {
        use crate::relay::{byte_budget_under, idle_secs, time_budget, SESSION_BYTE_BUDGET, SESSION_TIME_BUDGET};
        let with_bytes = |n: u64| Limits { max_session_bytes: Some(n), ..Limits::default() };
        assert_eq!(byte_budget_under(None, &with_bytes(32 << 20)), 28 << 20);
        assert_eq!(byte_budget_under(None, &with_bytes(128 << 20)), SESSION_BYTE_BUDGET);
        assert_eq!(byte_budget_under(None, &Limits::default()), SESSION_BYTE_BUDGET);
        assert_eq!(byte_budget_under(None, &with_bytes(4 << 20)), SESSION_BYTE_BUDGET, "no room under it: left out");
        assert_eq!(byte_budget_under(Some("10485760"), &with_bytes(32 << 20)), 10 << 20, "the variable lowers it");
        assert_eq!(byte_budget_under(Some("104857600"), &with_bytes(32 << 20)), 28 << 20, "and never raises it");
        let with_ms = |ms: u64| Limits { max_session_ms: Some(ms), ..Limits::default() };
        assert_eq!(time_budget(&with_ms(6 * 3_600_000)), Duration::from_secs(5 * 3600 + 30 * 60));
        assert_eq!(time_budget(&with_ms(24 * 3_600_000)), SESSION_TIME_BUDGET);
        assert_eq!(time_budget(&with_ms(60_000)), SESSION_TIME_BUDGET, "no room under it: left out");
        let with_idle = |ms: u64| Limits { idle_timeout_ms: Some(ms), ..Limits::default() };
        assert_eq!((idle_secs(&with_idle(90_000)), idle_secs(&with_idle(300_000))), (90, 180));
    }
}
