//! The relay hosts as the runs found them lately (T-059, T-563), kept across
//! runs, for each road apart. A host that failed with an error that another
//! host could repair, or that said nothing while a host after it opened, is
//! tried last for [`WINDOW`]; so is a host whose last [`STRIKES`] sessions
//! were cut on its side within [`SHORT`] of their open, for [`REST`]. A host
//! that opened within [`WINDOW`], with no failure since and its last session
//! not cut, is tried before the hosts that merely did not fail. This holds
//! in each run and in each mode of failover, also in a list that the user
//! named: its order is a preference, the record expires, and a note says
//! what moved a host last. No host is left out: each is still tried. The
//! record is a private file of the cache, [`FILE`], with one entry for each
//! road and host: when it failed, and why in a few words, never a target;
//! when it last opened, and how often; and its sessions cut short in a row.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use podssh_ws::dial::DialError;
use podssh_ws::ConnectError;
use serde::{Deserialize, Serialize};

use crate::open::OpenError;
use crate::relay::Relay;

/// The file of the record, in the cache.
pub const FILE: &str = "relay-failures.json";
/// How long a failure moves its host to the end of the list, and how long
/// an open moves it to the front.
pub const WINDOW: Duration = Duration::from_secs(600);
/// A session that its host's side cut within this of its open is a strike.
pub const SHORT: Duration = Duration::from_secs(300);
/// The strikes in a row that rest a host.
pub const STRIKES: u32 = 2;
/// How long a host rests, tried last, from its last strike.
pub const REST: Duration = Duration::from_secs(300);
/// The relay's forward road over WebSocket, `open`'s: its hosts are the
/// file's `hosts`, where each podssh before T-563 reads them.
pub const WEBSOCKET: &str = "websocket";

/// The hosts of each road, by name. Each field defaults, so that the file of
/// an older podssh reads, and an older podssh skips `roads`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Records {
    /// The WebSocket road's hosts.
    pub hosts: BTreeMap<String, Record>,
    /// Each other road's hosts, by the road's name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub roads: BTreeMap<String, BTreeMap<String, Record>>,
}

/// What the runs found of one host on one road. Each field defaults; each is
/// written, as an older podssh needs `at_ms` and `reason`, and reads a 0 as a
/// failure long ago.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    /// When it last failed; 0 once it opened since.
    pub at_ms: i64,
    /// Why, in a few words; empty once it opened since.
    pub reason: String,
    /// When it last opened a session; 0 for none.
    pub opened_ms: i64,
    /// The sessions that it opened while its entry held.
    pub opens: u32,
    /// Its sessions in a row that its side cut within [`SHORT`] of their open.
    pub strikes: u32,
    /// When its last strike came: a rest runs from it.
    pub struck_ms: i64,
}

/// Whether `at_ms` is within `span` before `now_ms`: never 0, which is none,
/// nor a time from the future, of a clock that moved.
fn within(at_ms: i64, now_ms: i64, span: Duration) -> bool {
    at_ms > 0 && at_ms <= now_ms && now_ms - at_ms < span.as_millis() as i64
}

impl Record {
    /// Whether it failed within the window.
    pub fn failed(&self, now_ms: i64) -> bool {
        within(self.at_ms, now_ms, WINDOW)
    }

    /// Whether it rests: [`STRIKES`] in a row, the last within [`REST`].
    pub fn resting(&self, now_ms: i64) -> bool {
        self.strikes >= STRIKES && within(self.struck_ms, now_ms, REST)
    }

    /// Whether it opened within the window, with no failure since and its
    /// last session not cut: a host that has worked, not merely not failed.
    pub fn proven(&self, now_ms: i64) -> bool {
        within(self.opened_ms, now_ms, WINDOW) && self.strikes == 0 && !self.failed(now_ms)
    }

    /// Whether anything of it still holds; else its entry goes.
    fn held(&self, now_ms: i64) -> bool {
        self.failed(now_ms)
            || within(self.opened_ms, now_ms, WINDOW)
            || (self.strikes > 0 && within(self.struck_ms, now_ms, WINDOW))
    }

    /// Why it goes last now: the time of its failure or of its last cut, and
    /// the words; a failure first.
    fn last(&self, now_ms: i64) -> Option<(i64, String, bool)> {
        if self.failed(now_ms) {
            return Some((self.at_ms, self.reason.clone(), true));
        }
        let rested = format!("its last {} sessions were cut within {} s of their open", self.strikes, SHORT.as_secs());
        self.resting(now_ms).then_some((self.struck_ms, rested, false))
    }
}

impl Records {
    /// The record of the cache; an empty one when there is none, or one that
    /// does not read.
    pub fn load() -> Records {
        Self::load_from(&crate::cache::candidate_dirs())
    }

    /// [`Records::load`] over explicit directories (for tests).
    pub fn load_from(dirs: &[PathBuf]) -> Records {
        crate::cache::load_file_from(dirs, FILE).and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    /// Keep the record in the cache. A record that cannot be kept costs the
    /// next run its order, nothing else: the failure is ignored.
    pub fn store(&self) {
        self.store_in(&crate::cache::candidate_dirs());
    }

    /// [`Records::store`] over explicit directories (for tests).
    pub fn store_in(&self, dirs: &[PathBuf]) {
        if let Ok(body) = serde_json::to_vec(self) {
            let _ = crate::cache::store_file_in_first(dirs, FILE, &body);
        }
    }

    /// The hosts of `road`.
    pub fn road(&self, road: &str) -> Option<&BTreeMap<String, Record>> {
        if road == WEBSOCKET {
            Some(&self.hosts)
        } else {
            self.roads.get(road)
        }
    }

    fn road_mut(&mut self, road: &str) -> &mut BTreeMap<String, Record> {
        if road == WEBSOCKET {
            &mut self.hosts
        } else {
            self.roads.entry(road.to_string()).or_default()
        }
    }

    /// The entry of `host` on `road`.
    pub fn get(&self, road: &str, host: &str) -> Option<&Record> {
        self.road(road)?.get(host)
    }

    /// The entry of `host` on `road` when it failed within the window at
    /// `now_ms`; one from the future, of a clock that moved, did not.
    pub fn fresh(&self, road: &str, host: &str, now_ms: i64) -> Option<&Record> {
        self.get(road, host).filter(|r| r.failed(now_ms))
    }

    /// After a round on `road`: each failure and each silent host recorded,
    /// the host that opened kept with its open and no failure, and each entry
    /// that holds nothing now dropped, on each road. Whether it changed.
    pub fn update(&mut self, road: &str, failed: &[(String, String)], opened: Option<&str>, now_ms: i64) -> bool {
        let before = self.clone();
        self.drop_stale(now_ms);
        if !failed.is_empty() || opened.is_some() {
            let hosts = self.road_mut(road);
            for (host, reason) in failed {
                let entry = hosts.entry(host.clone()).or_default();
                entry.at_ms = now_ms;
                entry.reason = reason.clone();
            }
            if let Some(host) = opened {
                // The host stays: that it works is what the order needs most.
                let entry = hosts.entry(host.to_string()).or_default();
                entry.at_ms = 0;
                entry.reason.clear();
                entry.opened_ms = now_ms;
                entry.opens = entry.opens.saturating_add(1);
            }
        }
        *self != before
    }

    /// A session that `host` carried on `road` ended after `lasted`; `cut`:
    /// its side ended it (the link lost, or the relay's close for its link
    /// to podssh). A cut within [`SHORT`] is a strike, one more in a row; any
    /// other end breaks the row. Whether the record changed.
    pub fn end(&mut self, road: &str, host: &str, lasted: Duration, cut: bool, now_ms: i64) -> bool {
        let strike = cut && lasted < SHORT;
        if !strike && self.get(road, host).is_none() {
            return false;
        }
        let before = self.clone();
        let entry = self.road_mut(road).entry(host.to_string()).or_default();
        if strike {
            entry.strikes = entry.strikes.saturating_add(1);
            entry.struck_ms = now_ms;
        } else {
            entry.strikes = 0;
            entry.struck_ms = 0;
        }
        *self != before
    }

    fn drop_stale(&mut self, now_ms: i64) {
        self.hosts.retain(|_, r| r.held(now_ms));
        for hosts in self.roads.values_mut() {
            hosts.retain(|_, r| r.held(now_ms));
        }
        self.roads.retain(|_, hosts| !hosts.is_empty());
    }
}

/// [`Records::end`] on the record of the cache, kept when it changed: what a
/// command calls once a session that `open` gave it is over.
pub fn ended(road: &str, host: &str, lasted: Duration, cut: bool) {
    let mut records = Records::load();
    if records.end(road, host, lasted, cut, crate::pool::now_ms()) {
        records.store();
    }
}

/// The order in which to try `hosts` on `road`: those that opened lately
/// first, then those that the record says nothing against, then those that
/// failed lately or rest, each group in the order of the list; and a note for
/// each host moved last. One host alone is never moved.
pub fn order(road: &str, hosts: &[Relay], records: &Records, now_ms: i64) -> (Vec<usize>, Vec<String>) {
    let (mut first, mut middle, mut last, mut notes) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (i, relay) in hosts.iter().enumerate() {
        let entry = records.get(road, &relay.host).filter(|_| hosts.len() > 1);
        match entry.and_then(|r| r.last(now_ms)) {
            Some((at_ms, why, failure)) => {
                let ago = (now_ms - at_ms) / 1000;
                notes.push(match failure {
                    true => format!("trying {} last: it failed {ago} s ago ({why})", relay.host),
                    false => format!("trying {} last: {why}, the last {ago} s ago", relay.host),
                });
                last.push(i);
            }
            None if entry.is_some_and(|r| r.proven(now_ms)) => first.push(i),
            None => middle.push(i),
        }
    }
    first.extend(middle);
    first.extend(last);
    (first, notes)
}

/// What the record says of one host on one road now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub road: String,
    pub host: String,
    /// Tried last now: the seconds since its failure or its last cut, and why.
    pub last: Option<(i64, String)>,
    /// It opened within the window: the seconds since, and its opens.
    pub opened: Option<(i64, u32)>,
}

/// Each host of each road that the record says something of now, the
/// WebSocket road's first, then the others by name: "failed 30 s ago"
/// beside "opened 4 s ago".
pub fn recent(records: &Records, now_ms: i64) -> Vec<Seen> {
    let others = records.roads.iter().map(|(name, hosts)| (name.as_str(), hosts));
    let mut seen = Vec::new();
    for (road, hosts) in std::iter::once((WEBSOCKET, &records.hosts)).chain(others) {
        for (host, r) in hosts {
            let last = r.last(now_ms).map(|(at_ms, why, _)| ((now_ms - at_ms) / 1000, why));
            let opened = within(r.opened_ms, now_ms, WINDOW).then(|| ((now_ms - r.opened_ms) / 1000, r.opens));
            if last.is_some() || opened.is_some() {
                seen.push(Seen { road: road.to_string(), host: host.clone(), last, opened });
            }
        }
    }
    seen
}

/// Why a host failed, in a few words, when the failure is the host's own:
/// none for an error that each host would give, nor for a target that the
/// relay could not reach (502), which says nothing of the host.
pub fn reason(e: &OpenError) -> Option<String> {
    if !e.another_host_may_help() {
        return None;
    }
    Some(match e {
        OpenError::Deadline => format!("no answer within {} s", crate::open::HOST_DEADLINE.as_secs()),
        OpenError::Token(_) => "no token from it".into(),
        OpenError::Connect { error, .. } => match error {
            ConnectError::Refused { status: 502, .. } => return None,
            ConnectError::Refused { status, .. } => format!("it answered {status}"),
            ConnectError::Dial(DialError::ProxyRefused { status, .. }) => format!("the proxy answered {status}"),
            ConnectError::Dial(_) => "no connection".into(),
            ConnectError::Tls(_) => "TLS failed".into(),
            ConnectError::Timeout { step, after } => format!("{step} timed out after {} s", after.as_secs()),
            ConnectError::Upgrade(_) | ConnectError::Http(_) => "no WebSocket".into(),
            ConnectError::Config(_) => return None,
        },
        // A host that this process's gate held was not tried (T-637).
        OpenError::Offline | OpenError::Held { .. } => return None,
    })
}

/// The words of a host that said nothing while a host after it opened.
pub const SILENT: &str = "it said nothing while another host opened";

#[cfg(test)]
#[path = "failures_tests.rs"]
mod tests;
