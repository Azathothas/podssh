//! The rank of the relay hosts as measured from this host (T-606): each
//! host's probes, its figures, the order of the hosts, and the private file
//! of the cache that keeps a rank for a day, for the egress that measured it.
//! The probes come from the caller, which measures one host at a time, so
//! that a run makes one outbound connection at a time (rule 2 of AGENTS.md).
//!
//! The order is the one of `scripts/relay-measure.py` (T-605), so that the
//! harness can check podssh's own: the share of probes that failed first,
//! then the median time to open, then its p95; two medians closer than
//! [`TIE_MS`] or [`TIE_SHARE`] of the larger are a tie, which keeps the order
//! that the hosts came in, so that one run's noise moves no host.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cache;

/// The file of the rank, in the cache, beside the record of failures.
pub const FILE: &str = "relay-rank.json";
/// The form of the file.
pub const SCHEMA: u32 = 1;
/// How long a rank holds: a host's network changes sooner than a pool.
pub const HOLDS: Duration = Duration::from_secs(24 * 3600);
/// Two medians closer than this, in ms, are the same.
pub const TIE_MS: f64 = 50.0;
/// Two medians closer than this share of the larger are the same.
pub const TIE_SHARE: f64 = 0.10;
/// The egress of a host with no proxy.
pub const DIRECT: &str = "direct";

/// One probe of one host: the time to open a session (the dial, TLS and the
/// upgrade, the token's time left out, as a session pays it once for days),
/// the median of its pings, or why it failed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Probe {
    pub open_ms: Option<f64>,
    pub ping_ms: Option<f64>,
    pub why: Option<String>,
}

impl Probe {
    /// Whether the session opened.
    pub fn opened(&self) -> bool {
        self.open_ms.is_some() && self.why.is_none()
    }
}

/// What the probes of one host say.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Figures {
    pub host: String,
    pub tries: u32,
    pub opened: u32,
    pub open_p50_ms: Option<f64>,
    pub open_p95_ms: Option<f64>,
    pub ping_p50_ms: Option<f64>,
    /// The words of its last failure, if one failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

impl Figures {
    /// The share of its probes that failed; all of them for none.
    pub fn failed_share(&self) -> f64 {
        if self.tries == 0 {
            return 1.0;
        }
        f64::from(self.tries - self.opened) / f64::from(self.tries)
    }
}

/// The nearest-rank percentile `percent` of values in order, as `podssh
/// ping` gives its own; `None` for none.
pub fn nearest(sorted: &[f64], percent: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let at = ((percent / 100.0 * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    Some(sorted[at - 1])
}

/// The figures of `host` from its probes.
pub fn figures(host: &str, probes: &[Probe]) -> Figures {
    let mut opens: Vec<f64> = probes.iter().filter(|p| p.opened()).filter_map(|p| p.open_ms).collect();
    let mut pings: Vec<f64> = probes.iter().filter(|p| p.opened()).filter_map(|p| p.ping_ms).collect();
    opens.sort_by(f64::total_cmp);
    pings.sort_by(f64::total_cmp);
    Figures {
        host: host.to_string(),
        tries: probes.len() as u32,
        opened: opens.len() as u32,
        open_p50_ms: nearest(&opens, 50.0),
        open_p95_ms: nearest(&opens, 95.0),
        ping_p50_ms: nearest(&pings, 50.0),
        why: probes.iter().rev().find_map(|p| if p.opened() { None } else { p.why.clone() }),
    }
}

/// Whether two medians are the same, within the tie.
fn same(a: f64, b: f64) -> bool {
    (a - b).abs() < TIE_MS.max(TIE_SHARE * a.max(b))
}

/// Whether `a` goes strictly before `b`; a tie never moves `a` up.
pub fn before(a: &Figures, b: &Figures) -> bool {
    let (sa, sb) = (a.failed_share(), b.failed_share());
    if (sa - sb).abs() > f64::EPSILON {
        return sa < sb;
    }
    let (Some(a50), Some(b50)) = (a.open_p50_ms, b.open_p50_ms) else { return false };
    if !same(a50, b50) {
        return a50 < b50;
    }
    match (a.open_p95_ms, b.open_p95_ms) {
        (Some(a95), Some(b95)) => !same(a95, b95) && a95 < b95,
        _ => false,
    }
}

/// The hosts in the order to try them: each moves up past each host that it
/// goes strictly before, and no further; a host that never opened goes last.
pub fn order(hosts: Vec<Figures>) -> Vec<Figures> {
    let mut out: Vec<Figures> = Vec::with_capacity(hosts.len());
    for host in hosts {
        let mut at = out.len();
        while at > 0 && before(&host, &out[at - 1]) {
            at -= 1;
        }
        out.insert(at, host);
    }
    out
}

/// The egress of a run, so that a rank holds only where it was made: the
/// first 16 hexadecimal digits of the SHA-256 of the proxy's host and port,
/// or [`DIRECT`]. No credential and no name of the proxy is kept.
pub fn egress(proxy: Option<(&str, u16)>) -> String {
    match proxy {
        None => DIRECT.to_string(),
        Some((host, port)) => {
            let digest = Sha256::digest(format!("{}:{port}", host.to_ascii_lowercase()).as_bytes());
            digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
        }
    }
}

/// A rank, as the cache keeps it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rank {
    pub schema: u32,
    /// When it was made, in ms since the epoch.
    pub made_ms: i64,
    pub egress: String,
    /// The target of its sessions, `HOST:PORT`.
    pub target: String,
    pub rounds: u32,
    /// Whether the user named the hosts (`--relay-host`): then the rank is
    /// of those hosts, not of the default list.
    pub named: bool,
    /// The hosts, in the order to try them.
    pub hosts: Vec<Figures>,
    /// The samples of the sessions' own races (T-607), by host: kept with
    /// or without a rank, and read where none holds.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub samples: std::collections::BTreeMap<String, Vec<crate::rank_list::Sample>>,
}

impl Rank {
    /// Its age at `now_ms`; `None` for a time from the future, of a clock
    /// that moved.
    pub fn age(&self, now_ms: i64) -> Option<Duration> {
        (self.made_ms > 0 && self.made_ms <= now_ms).then(|| Duration::from_millis((now_ms - self.made_ms) as u64))
    }

    /// Whether it holds at `now_ms` for `egress`: its form, its egress, and
    /// younger than [`HOLDS`].
    pub fn holds(&self, now_ms: i64, egress: &str) -> bool {
        self.schema == SCHEMA && self.egress == egress && self.age(now_ms).is_some_and(|age| age < HOLDS)
    }

    /// The first host that opened.
    pub fn first(&self) -> Option<&Figures> {
        self.hosts.iter().find(|h| h.opened > 0)
    }
}

/// The rank kept in the cache, if one reads.
pub fn load() -> Option<Rank> {
    load_from(&cache::read_dirs())
}

/// [`load`] over explicit directories (for tests).
pub fn load_from(dirs: &[PathBuf]) -> Option<Rank> {
    cache::load_file_from(dirs, FILE).and_then(|text| serde_json::from_str(&text).ok())
}

/// Keep `rank` in the cache, a private file; where it went.
pub fn save(rank: &Rank) -> Result<PathBuf, String> {
    save_in(&cache::candidate_dirs(), rank)
}

/// [`save`] over explicit directories (for tests).
pub fn save_in(dirs: &[PathBuf], rank: &Rank) -> Result<PathBuf, String> {
    let body = serde_json::to_vec_pretty(rank).map_err(|e| e.to_string())?;
    cache::store_file_in_first(dirs, FILE, &body)
}

/// Forget the rank, wherever it is ours to delete.
pub fn forget() {
    cache::remove_named_from(&cache::read_dirs(), FILE);
}

#[cfg(test)]
#[path = "rank_tests.rs"]
mod tests;
