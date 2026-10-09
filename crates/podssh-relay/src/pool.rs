//! The relay's pool of hosts, as its `/relays.json` publishes it, cached
//! between runs so podssh knows where else to go before the first host fails.
//!
//! The pool is fetched only when a token is minted (rarely: tokens last up to
//! 72 h), so it costs no extra connection on an ordinary run. Until a pool is
//! cached, the default relay's alternates come from [`SEED`]. Only hosts under
//! the primary relay's own parent domain are accepted, because the token is
//! sent to them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_ws::{https_get, ProxyChoice, Trust};
use serde::{Deserialize, Serialize};

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

/// The largest `/relays.json` read.
const MAX_BODY: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
struct CachedPool {
    fetched_ms: i64,
    hosts: Vec<String>,
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
    let response = https_get(&relay.host, relay.port, "/relays.json", MAX_BODY, trust, proxy, timeout)
        .await
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&response.status) {
        return Err(format!("the pool request answered HTTP {}", response.status));
    }
    let hosts = parse_pool(&response.body, primary)?;
    let body =
        serde_json::to_vec(&CachedPool { fetched_ms: now_ms(), hosts: hosts.clone() }).map_err(|e| e.to_string())?;
    cache::store_file(&file_name(primary), &body)?;
    Ok(hosts.len())
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
}
