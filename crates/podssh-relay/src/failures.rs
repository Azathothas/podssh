//! The relay hosts that failed recently (T-059), kept across runs. A host
//! that failed with an error that another host could repair, or that said
//! nothing while a host after it opened, is tried last for [`WINDOW`], in
//! each run and in each mode of failover, also in a list that the user
//! named: its order is a preference, the record expires, and a note says
//! what changed. No host is left out: each is still tried. The record is a
//! private file of the cache, [`FILE`], with one entry for each host: when
//! it failed, and why in a few words, never a target; a host that opens
//! loses its entry.

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
/// How long a failure moves its host to the end of the list.
pub const WINDOW: Duration = Duration::from_secs(600);

/// The hosts that failed, by name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Records {
    pub hosts: BTreeMap<String, Record>,
}

/// When a host failed, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub at_ms: i64,
    pub reason: String,
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

    /// The record of `host` when it is within the window at `now_ms`; one
    /// from the future, of a clock that moved, is not.
    pub fn fresh(&self, host: &str, now_ms: i64) -> Option<&Record> {
        let window = WINDOW.as_millis() as i64;
        self.hosts.get(host).filter(|r| r.at_ms <= now_ms && now_ms - r.at_ms < window)
    }

    /// After a round: each failure and each silent host recorded, the host
    /// that opened cleared, and the stale entries dropped. Whether the
    /// record changed.
    pub fn update(&mut self, failed: &[(String, String)], opened: Option<&str>, now_ms: i64) -> bool {
        let before = self.clone();
        self.hosts.retain(|host, _| before.fresh(host, now_ms).is_some());
        for (host, reason) in failed {
            self.hosts.insert(host.clone(), Record { at_ms: now_ms, reason: reason.clone() });
        }
        if let Some(host) = opened {
            self.hosts.remove(host);
        }
        *self != before
    }
}

/// The order in which to try `hosts`: those with a fresh record last, each
/// group in the order of the list; and a note for each host moved.
pub fn order(hosts: &[Relay], records: &Records, now_ms: i64) -> (Vec<usize>, Vec<String>) {
    let (mut first, mut last, mut notes) = (Vec::new(), Vec::new(), Vec::new());
    for (i, relay) in hosts.iter().enumerate() {
        match records.fresh(&relay.host, now_ms) {
            Some(r) if hosts.len() > 1 => {
                let ago = (now_ms - r.at_ms) / 1000;
                notes.push(format!("trying {} last: it failed {ago} s ago ({})", relay.host, r.reason));
                last.push(i);
            }
            _ => first.push(i),
        }
    }
    first.extend(last);
    (first, notes)
}

/// The hosts that a run tries last now: each name, the seconds since its
/// failure, and why.
pub fn recent(records: &Records, now_ms: i64) -> Vec<(String, i64, String)> {
    let fresh = records.hosts.iter().filter(|(host, _)| records.fresh(host, now_ms).is_some());
    fresh.map(|(host, r)| (host.clone(), (now_ms - r.at_ms) / 1000, r.reason.clone())).collect()
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
        OpenError::Offline => return None,
    })
}

/// The words of a host that said nothing while a host after it opened.
pub const SILENT: &str = "it said nothing while another host opened";

#[cfg(test)]
#[path = "failures_tests.rs"]
mod tests;
