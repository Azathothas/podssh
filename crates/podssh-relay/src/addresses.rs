//! The addresses that carried a session to each relay host (T-344), kept
//! across runs: a host whose resolver fails tomorrow still knows where its
//! relay was. The record is a private file of the cache, [`FILE`], with each
//! host's last addresses and when each last carried a session through its
//! `101`. The dialer asks them after the system resolver fails and before DNS
//! over HTTPS, and an old one last (`podssh_ws::resolve`). TLS checks the
//! relay's name on each, so a wrong address fails the handshake; an address
//! of the cache at which a host failed as no relay would is forgotten.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Once;

use podssh_ws::resolve::{self, Remembered, Source};
use serde::{Deserialize, Serialize};

/// The file of the record, in the cache.
pub const FILE: &str = "relay-addresses.json";
/// The addresses kept for each host, the newest first.
pub const PER_HOST: usize = 4;
/// The hosts kept, those that carried a session last first.
pub const HOSTS: usize = 32;
/// A time younger than this is not written again: a run that opens a
/// session after another writes the file once.
const REFRESH_MS: i64 = 3600 * 1000;

/// Each host's addresses, by name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addresses {
    pub hosts: BTreeMap<String, Vec<Seen>>,
}

/// An address, and when it last carried a session (milliseconds since the
/// epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    pub ip: IpAddr,
    pub at_ms: i64,
}

impl Addresses {
    /// The record of the cache; an empty one when there is none, or one that
    /// does not read.
    pub fn load() -> Addresses {
        Self::load_from(&crate::cache::candidate_dirs())
    }

    /// [`Addresses::load`] over explicit directories (for tests).
    pub fn load_from(dirs: &[PathBuf]) -> Addresses {
        crate::cache::load_file_from(dirs, FILE).and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    /// Keep the record in the cache. A record that cannot be kept costs a
    /// later run its fallback, nothing else: the failure is ignored.
    pub fn store_in(&self, dirs: &[PathBuf]) {
        if let Ok(body) = serde_json::to_vec(self) {
            let _ = crate::cache::store_file_in_first(dirs, FILE, &body);
        }
    }

    /// `ip` carried a session to `host` at `now_ms`: it goes first among the
    /// host's, past [`PER_HOST`] the host's oldest go, and past [`HOSTS`] the
    /// host that carried none for the longest. Whether the record changed
    /// enough to be written: a new address, or a time older than an hour.
    pub fn note(&mut self, host: &str, ip: IpAddr, now_ms: i64) -> bool {
        let seen = self.hosts.entry(key(host)).or_default();
        let recent = |s: &Seen| s.ip == ip && s.at_ms <= now_ms && now_ms - s.at_ms < REFRESH_MS;
        if seen.first().is_some_and(recent) {
            return false;
        }
        seen.retain(|s| s.ip != ip);
        seen.insert(0, Seen { ip, at_ms: now_ms });
        seen.truncate(PER_HOST);
        while self.hosts.len() > HOSTS {
            let last = |seen: &Vec<Seen>| seen.first().map_or(i64::MIN, |s| s.at_ms);
            let Some(stale) = self.hosts.iter().min_by_key(|(_, seen)| last(seen)).map(|(h, _)| h.clone()) else {
                break;
            };
            self.hosts.remove(&stale);
        }
        true
    }

    /// A host failed at `ip` as no relay would ([`failed`]): it goes.
    /// Whether the record changed.
    pub fn forget(&mut self, host: &str, ip: IpAddr) -> bool {
        let host = key(host);
        let Some(seen) = self.hosts.get_mut(&host) else { return false };
        let before = seen.len();
        seen.retain(|s| s.ip != ip);
        let changed = seen.len() != before;
        if seen.is_empty() {
            self.hosts.remove(&host);
        }
        changed
    }

    /// The record as the dialer takes it.
    pub fn remembered(&self) -> Vec<Remembered> {
        self.hosts
            .iter()
            .flat_map(|(host, seen)| {
                seen.iter().map(move |s| Remembered { host: host.clone(), ip: s.ip, at_ms: s.at_ms })
            })
            .collect()
    }
}

/// A name as the record keeps it: lower case, no final dot.
fn key(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

static INSTALLED: Once = Once::new();

/// Give the dialer the record of the cache, once a run: each command that
/// reaches the relay does this before it dials, and the opener does too.
pub fn install() {
    INSTALLED.call_once(|| resolve::set_remembered(Addresses::load().remembered()));
}

/// A session through `host` reached `101` over `peer`: the address is kept
/// when the dialer reached it straight, for a name that no pin holds, and it
/// is not this host's own.
pub fn carried(host: &str, peer: Option<SocketAddr>) {
    let Some(peer) = peer.filter(|peer| worth_keeping(host, *peer)) else { return };
    let dirs = crate::cache::candidate_dirs();
    let mut record = Addresses::load_from(&dirs);
    if record.note(host, peer.ip(), crate::pool::now_ms()) {
        record.store_in(&dirs);
    }
    resolve::set_remembered(record.remembered());
}

/// An attempt at `host` failed after its connection opened, as the relay
/// itself would not fail: TLS refused the name, the upgrade broke, or a server
/// refused it that is not the relay, as Cloudflare's edge does at an address
/// of another site of its own, with a valid certificate (its error 1034). The
/// address that the dialer reached for `host` last goes, when the cache gave
/// it; one that a resolver gave is not the cache's to judge.
pub fn failed(host: &str) {
    let Some((peer, source)) = resolve::last_dialed(host) else { return };
    if !matches!(source, Source::Cache | Source::OldCache) {
        return;
    }
    let dirs = crate::cache::candidate_dirs();
    let mut record = Addresses::load_from(&dirs);
    if record.forget(host, peer.ip()) {
        record.store_in(&dirs);
    }
    resolve::set_remembered(record.remembered());
}

/// Whether `peer`, which carried a session to `host`, is worth a run whose
/// resolver fails: through a proxy it is the proxy's, a pin or an address in
/// place of the name is the user's own, and a relay on this host needs no
/// DNS.
pub fn worth_keeping(host: &str, peer: SocketAddr) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.parse::<IpAddr>().is_err()
        && elsewhere(peer.ip())
        && resolve::pinned(host).is_empty()
        && matches!(podssh_ws::dial::proxy_from_env(host), Ok(None))
        && !matches!(resolve::dialed(host, peer), Some(Source::Pin | Source::Literal))
}

/// Whether `ip` is another host's: not the loopback, not unspecified, not a
/// group's.
fn elsewhere(ip: IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000_000;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A new address goes first; the same one within the hour changes
    /// nothing; past [`PER_HOST`] the oldest goes.
    #[test]
    fn a_session_s_address_goes_first_and_the_oldest_go() {
        let mut record = Addresses::default();
        assert!(record.note("Relay.Example.", ip("192.0.2.1"), NOW - 7_200_000));
        assert!(record.note("relay.example", ip("192.0.2.2"), NOW - 10_000));
        assert!(!record.note("relay.example", ip("192.0.2.2"), NOW), "the same address within the hour");
        assert!(record.note("relay.example", ip("192.0.2.1"), NOW), "an older one comes first again");
        let order: Vec<IpAddr> = record.hosts["relay.example"].iter().map(|s| s.ip).collect();
        assert_eq!(order, [ip("192.0.2.1"), ip("192.0.2.2")]);
        for i in 3..=6 {
            record.note("relay.example", ip(&format!("192.0.2.{i}")), NOW + i);
        }
        let kept: Vec<IpAddr> = record.hosts["relay.example"].iter().map(|s| s.ip).collect();
        assert_eq!(kept, [ip("192.0.2.6"), ip("192.0.2.5"), ip("192.0.2.4"), ip("192.0.2.3")]);
        assert_eq!(kept.len(), PER_HOST);
    }

    /// Past [`HOSTS`], the host that carried nothing for the longest goes;
    /// a refused address goes, and a host with none left.
    #[test]
    fn hosts_are_bounded_and_a_refused_address_goes() {
        let mut record = Addresses::default();
        for i in 0..=HOSTS as i64 {
            record.note(&format!("h{i}.example"), ip("192.0.2.1"), NOW + i);
        }
        assert_eq!(record.hosts.len(), HOSTS);
        assert!(!record.hosts.contains_key("h0.example"), "the oldest host went");
        assert!(record.forget("H1.example", ip("192.0.2.1")));
        assert!(!record.hosts.contains_key("h1.example"));
        assert!(!record.forget("h1.example", ip("192.0.2.1")), "nothing left to forget");
        let dialer: Vec<Remembered> = record.remembered();
        assert_eq!(dialer.len(), HOSTS - 1);
        assert!(dialer.iter().all(|r| r.ip == ip("192.0.2.1") && r.host.ends_with(".example")));
    }

    /// The record is a private file of the cache, and one that does not read
    /// is none.
    #[test]
    fn the_record_is_a_private_file_of_the_cache() {
        let dir = std::env::temp_dir().join(format!("podssh-addresses-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dirs = vec![dir.clone()];
        assert_eq!(Addresses::load_from(&dirs), Addresses::default());
        let mut record = Addresses::default();
        record.note("relay.example", ip("2001:db8::1"), NOW);
        record.store_in(&dirs);
        assert_eq!(Addresses::load_from(&dirs), record);
        let text = std::fs::read_to_string(dir.join(FILE)).unwrap();
        assert!(text.contains(r#""ip":"2001:db8::1""#), "{text}");
        std::fs::write(dir.join(FILE), "not json").unwrap();
        assert_eq!(Addresses::load_from(&dirs), Addresses::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An address in place of the name is no name's; this host's own
    /// addresses, and a group's, are no relay's elsewhere.
    #[test]
    fn only_another_host_s_address_of_a_name_is_kept() {
        let peer = |s: &str| SocketAddr::new(ip(s), 443);
        assert!(!worth_keeping("192.0.2.1", peer("192.0.2.1")));
        assert!(!worth_keeping("[2001:db8::1]", peer("2001:db8::1")));
        for here in ["127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1"] {
            assert!(!elsewhere(ip(here)), "{here}");
            assert!(!worth_keeping("relay.example", peer(here)), "{here}");
        }
        for there in ["104.21.39.2", "10.1.2.3", "2606:4700:3037::6815:2702"] {
            assert!(elsewhere(ip(there)), "{there}");
        }
    }
}
