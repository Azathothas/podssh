//! What this process remembers of where names were (T-344): the addresses
//! that carried a session, which the caller keeps between runs and gives
//! with [`set_remembered`] (podssh keeps them in a file of its cache), and the
//! source of the address of each connection that the dialer made lately,
//! which `podssh doctor` names and which tells the caller that TLS refused an
//! address of the cache.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::Source;

/// An address that carried a session to `host`, and when it last did, in
/// milliseconds since the epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remembered {
    pub host: String,
    pub ip: IpAddr,
    pub at_ms: i64,
}

/// A remembered address younger than this is asked before DNS over HTTPS;
/// an older one after it, last. The relay's names keep their addresses for
/// months, and a week lets a host that runs podssh weekly find its own.
pub const FRESH: Duration = Duration::from_secs(7 * 24 * 3600);

/// The connections of the dialer that [`dialed`] can name: a run reaches a
/// few hosts, and each new one pushes out the oldest.
const DIALED_KEPT: usize = 32;

static REMEMBERED: RwLock<Vec<Remembered>> = RwLock::new(Vec::new());
static DIALED: Mutex<VecDeque<(String, SocketAddr, Source)>> = Mutex::new(VecDeque::new());

/// A name as the tables keep it: lower case, no final dot.
fn key(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Replace the process-wide remembered addresses.
pub fn set_remembered(list: Vec<Remembered>) {
    let list = list.into_iter().map(|r| Remembered { host: key(&r.host), ..r }).collect();
    *REMEMBERED.write().unwrap_or_else(|e| e.into_inner()) = list;
}

/// The remembered addresses of `host`, the newest first.
pub fn remembered(host: &str) -> Vec<Remembered> {
    let host = key(host);
    let all = REMEMBERED.read().unwrap_or_else(|e| e.into_inner());
    let mut found: Vec<Remembered> = all.iter().filter(|r| r.host == host).cloned().collect();
    found.sort_by_key(|r| std::cmp::Reverse(r.at_ms));
    found
}

/// The fresh addresses and the old ones of `entries` at `now_ms`, each the
/// newest first and each address once. One from the future, of a clock that
/// moved, is old: DNS over HTTPS is asked before it.
pub fn split(entries: &[Remembered], now_ms: i64) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let window = FRESH.as_millis() as i64;
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|r| std::cmp::Reverse(r.at_ms));
    let (mut fresh, mut old) = (Vec::new(), Vec::new());
    for r in sorted {
        let list = if r.at_ms <= now_ms && now_ms - r.at_ms < window { &mut fresh } else { &mut old };
        if !list.contains(&r.ip) {
            list.push(r.ip);
        }
    }
    old.retain(|ip| !fresh.contains(ip));
    (fresh, old)
}

/// This host's clock, in milliseconds since the epoch.
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// The dialer connected to `addr` for `host`, from `source`.
pub(crate) fn note_dialed(host: &str, addr: SocketAddr, source: Source) {
    let mut dialed = DIALED.lock().unwrap_or_else(|e| e.into_inner());
    let host = key(host);
    dialed.retain(|(h, a, _)| !(*h == host && *a == addr));
    if dialed.len() == DIALED_KEPT {
        dialed.pop_front();
    }
    dialed.push_back((host, addr, source));
}

/// The source of `addr`, when the dialer connected to it for `host` lately.
pub fn dialed(host: &str, addr: SocketAddr) -> Option<Source> {
    let host = key(host);
    let dialed = DIALED.lock().unwrap_or_else(|e| e.into_inner());
    dialed.iter().rev().find(|(h, a, _)| *h == host && *a == addr).map(|(_, _, source)| *source)
}

/// The address of the last connection that the dialer made for `host`, and
/// its source.
pub fn last_dialed(host: &str) -> Option<(SocketAddr, Source)> {
    let host = key(host);
    let dialed = DIALED.lock().unwrap_or_else(|e| e.into_inner());
    dialed.iter().rev().find(|(h, _, _)| *h == host).map(|(_, addr, source)| (*addr, *source))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000_000;

    fn seen(ip: &str, ago_ms: i64) -> Remembered {
        Remembered { host: "relay.example".into(), ip: ip.parse().unwrap(), at_ms: NOW - ago_ms }
    }

    /// Fresh within the window, old past it and from the future; the newest
    /// first in each, and an address in one list only.
    #[test]
    fn addresses_are_fresh_for_a_week_and_old_after_it() {
        let week = FRESH.as_millis() as i64;
        let entries = [
            seen("192.0.2.1", week + 1),
            seen("192.0.2.2", 1000),
            seen("192.0.2.3", week - 1),
            seen("192.0.2.4", -60_000),
            seen("192.0.2.2", week * 2),
        ];
        let (fresh, old) = split(&entries, NOW);
        let ips = |list: &[&str]| list.iter().map(|s| s.parse::<IpAddr>().unwrap()).collect::<Vec<_>>();
        assert_eq!(fresh, ips(&["192.0.2.2", "192.0.2.3"]));
        assert_eq!(old, ips(&["192.0.2.4", "192.0.2.1"]), "the future's first, by its time; the old 192.0.2.2 gone");
        assert_eq!(split(&[], NOW), (Vec::new(), Vec::new()));
    }

    /// The dialer's record names the source of an address for its host only,
    /// the latest connection first, and keeps a bounded number.
    #[test]
    fn the_dialer_s_record_names_each_address_s_source() {
        let a: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let b: SocketAddr = "192.0.2.11:443".parse().unwrap();
        note_dialed("Memory-Test.example.", a, Source::System);
        note_dialed("memory-test.example", b, Source::Cache);
        assert_eq!(dialed("memory-test.example", a), Some(Source::System));
        assert_eq!(dialed("other.example", a), None);
        assert_eq!(last_dialed("MEMORY-TEST.example"), Some((b, Source::Cache)));
        for i in 0..DIALED_KEPT as u16 {
            note_dialed("filler.example", SocketAddr::from(([192, 0, 2, 200], i)), Source::Doh);
        }
        assert_eq!(dialed("memory-test.example", b), None, "pushed out by newer connections");
    }
}
