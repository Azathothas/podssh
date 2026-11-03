//! The default list of relay hosts takes the rank (T-607): the pool's hosts
//! in the order that a rank measured from this host gives, the default host
//! at its own place among them, and samples of each session's own race,
//! which order the pool where no rank holds. A list that the user named
//! keeps its order; the record of failures still moves hosts within any
//! list (`failures::order`). The samples cost no connection: they are the
//! times of the race's own attempts, so rule 2 of AGENTS.md holds.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::rank::{self, Figures, Probe, Rank};
use crate::relay::{Relay, RelayList};

/// The samples kept of each host.
pub const SAMPLES: usize = 8;
/// `PODSSH_RELAY_RANK=no` leaves the rank and the samples out of the order.
pub const ENV: &str = "PODSSH_RELAY_RANK";

/// The settings file's `RelayRank no`, which the binary sets as it starts.
static OFF_BY_SETTINGS: AtomicBool = AtomicBool::new(false);

/// What the settings file says of the rank: `false` for `RelayRank no`.
pub fn set_by_settings(on: bool) {
    OFF_BY_SETTINGS.store(!on, Ordering::Relaxed);
}

/// Whether the rank and the samples order the default list: not with
/// `PODSSH_RELAY_RANK=no` (or `off`, `0`), nor with `RelayRank no` where
/// the variable is unset or empty, as the file is below the variable.
pub fn enabled() -> bool {
    enabled_from(std::env::var(ENV).ok().as_deref(), !OFF_BY_SETTINGS.load(Ordering::Relaxed))
}

/// [`enabled`] with the variable and the settings file's word given.
pub fn enabled_from(var: Option<&str>, file_on: bool) -> bool {
    match var.map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty()) {
        Some(word) => !matches!(word.as_str(), "no" | "off" | "0"),
        None => file_on,
    }
}

/// One sample: a session of the race that opened, timed from its dial to
/// the upgrade, the token's time left out.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Sample {
    pub at_ms: i64,
    pub egress: String,
    pub open_ms: f64,
}

/// The samples of one run: each host that opened, and its time.
pub type Samples = Mutex<Vec<(String, f64)>>;

/// The egress of a run to `host`: the proxy that it goes through, by its
/// digest, or `direct`.
pub fn egress_for(host: &str) -> String {
    match podssh_ws::dial::proxy_from_env(host) {
        Ok(Some(proxy)) => rank::egress(Some((&proxy.host, proxy.port))),
        _ => rank::egress(None),
    }
}

/// `host` with its `:443` left out, as a pool names its hosts.
fn bare(host: &str) -> &str {
    host.strip_suffix(":443").unwrap_or(host)
}

/// A host's opened figures from its samples of `egress` within a day.
fn sampled(host: &str, samples: &[Sample], egress: &str, now_ms: i64) -> Option<Figures> {
    let day = rank::HOLDS.as_millis() as i64;
    let probes: Vec<Probe> = samples
        .iter()
        .filter(|s| s.egress == egress && s.at_ms <= now_ms && now_ms - s.at_ms < day)
        .map(|s| Probe { open_ms: Some(s.open_ms), ping_ms: None, why: None })
        .collect();
    (!probes.is_empty()).then(|| rank::figures(host, &probes))
}

/// Where `names` go, by the rank that holds, else by the samples: the
/// indexes of `names` in order; those that neither names keep their order,
/// after the others.
fn by_measure(names: &[&str], kept: Option<&Rank>, egress: &str, now_ms: i64, samples: bool) -> Vec<usize> {
    let rest = |taken: &[usize]| (0..names.len()).filter(|i| !taken.contains(i)).collect::<Vec<_>>();
    let Some(kept) = kept else { return (0..names.len()).collect() };
    if kept.holds(now_ms, egress) && !kept.named {
        let mut taken = Vec::new();
        for host in kept.hosts.iter().filter(|h| h.opened > 0) {
            if let Some(i) = names.iter().position(|n| n.eq_ignore_ascii_case(bare(&host.host))) {
                if !taken.contains(&i) {
                    taken.push(i);
                }
            }
        }
        let mut order = taken.clone();
        order.extend(rest(&taken));
        return order;
    }
    if !samples {
        return (0..names.len()).collect();
    }
    let figures: Vec<(usize, Figures)> = names
        .iter()
        .enumerate()
        .filter_map(|(i, n)| kept.samples.get(*n).and_then(|s| sampled(n, s, egress, now_ms)).map(|f| (i, f)))
        .collect();
    let ordered = rank::order(figures.iter().map(|(_, f)| f.clone()).collect());
    let mut taken: Vec<usize> = Vec::new();
    for f in ordered {
        if let Some((i, _)) = figures.iter().find(|(_, g)| g.host == f.host) {
            taken.push(*i);
        }
    }
    let mut order = taken.clone();
    order.extend(rest(&taken));
    order
}

/// The pool of the default list in the order that this host measured: by
/// the rank when one holds for this egress, else by the samples, else as
/// `/relays.json` gave it. The default list takes its first hosts.
pub fn alternates(pool: Vec<String>, kept: Option<&Rank>, egress: &str, now_ms: i64) -> Vec<String> {
    let names: Vec<&str> = pool.iter().map(String::as_str).collect();
    let order = by_measure(&names, kept, egress, now_ms, true);
    order.into_iter().map(|i| pool[i].clone()).collect()
}

/// The list as a run tries it: a list that the user named as it is; the
/// default list with each host at its place in the rank that holds, the
/// default host among them. Only a rank moves the default host: the
/// samples come from the hosts that a run tried, under its own conditions.
pub fn placed(list: &RelayList, kept: Option<&Rank>, egress: &str, now_ms: i64) -> Vec<Relay> {
    if list.explicit {
        return list.hosts.clone();
    }
    let named: Vec<String> = list.hosts.iter().map(crate::token::relay_name).collect();
    let names: Vec<&str> = named.iter().map(String::as_str).collect();
    by_measure(&names, kept, egress, now_ms, false).into_iter().map(|i| list.hosts[i].clone()).collect()
}

/// The list of a run, read from the cache: [`placed`] with the rank kept
/// when the rank is on, else the list as it is.
pub fn placed_now(list: &RelayList) -> Vec<Relay> {
    if !enabled() || list.explicit {
        return list.hosts.clone();
    }
    let egress = egress_for(&list.primary().host);
    placed(list, rank::load().as_ref(), &egress, crate::pool::now_ms())
}

/// A session of the race that opened, timed; by the host's name, with its
/// port when it is not 443, as a pool and a rank name it.
pub fn sample(samples: &Samples, relay: &Relay, took: Duration) {
    let mut kept = samples.lock().unwrap_or_else(|e| e.into_inner());
    kept.push((crate::token::relay_name(relay), took.as_secs_f64() * 1000.0));
}

/// Keep the samples of a run in the rank's file, the last [`SAMPLES`] of
/// each host, with when and the egress; with or without a rank, whether
/// the rank is on or off, as they cost nothing to keep.
pub fn keep(samples: &Samples) {
    let taken: Vec<(String, f64)> = std::mem::take(&mut *samples.lock().unwrap_or_else(|e| e.into_inner()));
    if taken.is_empty() {
        return;
    }
    let now = crate::pool::now_ms();
    let mut kept = rank::load().unwrap_or(Rank { schema: rank::SCHEMA, ..Rank::default() });
    // The egress of each host by its name alone: a port is no proxy's.
    let egress = |name: &str| egress_for(name.rsplit_once(':').map_or(name, |(host, _)| host));
    add(&mut kept.samples, &taken, &egress, now);
    let _ = rank::save(&kept);
}

/// `taken` into `samples`, each with the egress that `egress` names for
/// its host, each host's last [`SAMPLES`] kept.
pub fn add(
    samples: &mut BTreeMap<String, Vec<Sample>>,
    taken: &[(String, f64)],
    egress: &dyn Fn(&str) -> String,
    now_ms: i64,
) {
    for (host, open_ms) in taken {
        let each = samples.entry(host.clone()).or_default();
        each.push(Sample { at_ms: now_ms, egress: egress(host), open_ms: *open_ms });
        let over = each.len().saturating_sub(SAMPLES);
        each.drain(..over);
    }
}

/// Which order a run of the default list takes now, in a word, for
/// `status` and `doctor`: `rank`, `samples`, `pool`, or `off`.
pub fn order_now(primary: &str) -> &'static str {
    if !enabled() {
        return "off";
    }
    let Some(kept) = rank::load() else { return "pool" };
    let (egress, now) = (egress_for(primary), crate::pool::now_ms());
    if kept.holds(now, &egress) && !kept.named {
        return "rank";
    }
    let some = kept.samples.iter().any(|(host, s)| sampled(host, s, &egress, now).is_some());
    if some {
        "samples"
    } else {
        "pool"
    }
}

#[cfg(test)]
#[path = "rank_list_tests.rs"]
mod tests;
