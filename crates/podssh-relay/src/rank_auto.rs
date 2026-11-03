//! A rank that podssh makes unasked, in the background of a session (T-608):
//! only when the user asks for it, with `RelayRank auto` or
//! `PODSSH_RELAY_RANK=auto`, and within the bounds of the operator's ruling
//! Q89: once a day for each egress, [`MOST`] hosts, one probe each [`GAP`]
//! at most, after the session ran [`DELAY`], and never while a race of relay
//! hosts runs. Each probe names a target with `?dial=lazy` and sends no
//! byte, so the relay dials no target. This module holds the setting, the
//! count of races, the plan and the rank that each probe adds to; the probes
//! are the binary's, one at a time.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

use crate::rank::{self, Probe, Rank, BACKGROUND};
use crate::relay::DEFAULT_RELAY_HOST;

/// How long a session runs before its first probe: a short run, as a
/// command's, makes none.
pub const DELAY: Duration = Duration::from_secs(60);
/// The least time from one probe's start to the next one's.
pub const GAP: Duration = Duration::from_secs(10);
/// The most hosts of a day's rank, over each session that adds to it.
pub const MOST: usize = 8;
/// The WebSocket pings of each probe: a few KiB in all.
pub const PINGS: usize = 3;
/// The query of each probe: the relay dials on the client's first byte, and
/// a probe sends none.
pub const LAZY: &str = "?dial=lazy";
/// For tests only, `DELAY_MS,GAP_MS` in place of [`DELAY`] and [`GAP`]: read
/// by a build with debug assertions alone, so each release binary keeps
/// Q89's bounds.
pub const PACE_ENV: &str = "PODSSH_RELAY_RANK_PACE";
/// How often a probe that waits for the end of a race looks again.
const CALM_STEP: Duration = Duration::from_millis(250);

/// The settings file's `RelayRank auto`, which the binary sets as it reads it.
static AUTO_BY_SETTINGS: AtomicBool = AtomicBool::new(false);

/// What the settings file says: `true` for `RelayRank auto`.
pub fn set_by_settings(auto: bool) {
    AUTO_BY_SETTINGS.store(auto, Ordering::Relaxed);
}

/// What asks for a rank in the background, in the words that set it, or
/// none: never by default (Q89).
pub fn asked_by() -> Option<&'static str> {
    asked_from(std::env::var(crate::rank_list::ENV).ok().as_deref(), AUTO_BY_SETTINGS.load(Ordering::Relaxed))
}

/// Whether a session may rank in its background.
pub fn asked() -> bool {
    asked_by().is_some()
}

/// [`asked_by`] with the variable and the file's word given: the variable
/// when it is set and not empty, else the file, as for the rank itself.
pub fn asked_from(var: Option<&str>, file_auto: bool) -> Option<&'static str> {
    match var.map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty()) {
        Some(word) => (word == "auto").then_some("PODSSH_RELAY_RANK=auto"),
        None => file_auto.then_some("RelayRank auto"),
    }
}

/// The waits of a background run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pace {
    pub delay: Duration,
    pub gap: Duration,
}

/// Q89's waits, or in a build with debug assertions those of [`PACE_ENV`].
pub fn pace() -> Pace {
    let bounds = Pace { delay: DELAY, gap: GAP };
    if !cfg!(debug_assertions) {
        return bounds;
    }
    std::env::var(PACE_ENV).ok().as_deref().and_then(pace_of).unwrap_or(bounds)
}

/// `DELAY_MS,GAP_MS`, two whole numbers of milliseconds; else none.
pub fn pace_of(text: &str) -> Option<Pace> {
    let (delay, gap) = text.split_once(',')?;
    let ms = |t: &str| t.trim().parse::<u64>().ok().map(Duration::from_millis);
    Some(Pace { delay: ms(delay)?, gap: ms(gap)? })
}

/// The races of relay hosts in progress in this process, and the signal of
/// each one's start.
static RACES: AtomicUsize = AtomicUsize::new(0);
static RACE: Notify = Notify::const_new();

/// A race in progress, counted for as long as this lives.
pub struct Racing(());

/// Count a race that starts: a background probe waits for its end, and one
/// in flight is dropped, so the probe never runs beside a race.
pub fn racing() -> Racing {
    RACES.fetch_add(1, Ordering::SeqCst);
    RACE.notify_waiters();
    Racing(())
}

impl Drop for Racing {
    fn drop(&mut self) {
        RACES.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Whether a race runs now.
pub fn a_race_runs() -> bool {
    RACES.load(Ordering::SeqCst) > 0
}

/// Wait until no race runs.
pub async fn calm() {
    while a_race_runs() {
        tokio::time::sleep(CALM_STEP).await;
    }
}

/// `work`, unless a race runs or starts before it ends: then `None`, and
/// `work` is dropped with its connection.
pub async fn unless_a_race<F: Future>(work: F) -> Option<F::Output> {
    // Made before the check, so that a race that starts in between wakes it.
    let started = RACE.notified();
    if a_race_runs() {
        return None;
    }
    tokio::select! {
        out = work => Some(out),
        () = started => None,
    }
}

/// `host` with `:443` left out, as a pool names its hosts.
fn bare(host: &str) -> &str {
    host.strip_suffix(":443").unwrap_or(host)
}

/// Whether two names are of one host.
fn same(a: &str, b: &str) -> bool {
    bare(a).eq_ignore_ascii_case(bare(b))
}

/// The hosts of a day's rank, in order: the default host, then its pool as
/// `/relays.json` gave it, [`MOST`] at most.
pub fn hosts() -> Vec<String> {
    let pool = crate::pool::alternates(DEFAULT_RELAY_HOST);
    first_hosts(std::iter::once(DEFAULT_RELAY_HOST.to_string()).chain(pool))
}

/// The first [`MOST`] names of `names`, each once.
fn first_hosts(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        if out.len() < MOST && !out.iter().any(|h| same(h, &name)) {
            out.push(name);
        }
    }
    out
}

/// Whether `kept` is a background rank that a run of `egress` goes on with:
/// partial, and still holding.
fn goes_on(kept: &Rank, egress: &str, now_ms: i64) -> bool {
    kept.holds(now_ms, egress) && kept.background() && kept.partial && !kept.named
}

/// The hosts that a background run probes now, in order, or `None` when no
/// run is due: a rank that holds for `egress` blocks one, `relay rank`'s or
/// a whole background rank, but a partial background rank, which a run goes
/// on with, probing only the hosts that it lacks, so a day's rank never
/// holds more than [`MOST`].
pub fn plan(kept: Option<&Rank>, hosts: &[String], egress: &str, now_ms: i64) -> Option<Vec<String>> {
    let first = first_hosts(hosts.iter().cloned());
    let Some(kept) = kept.filter(|k| k.holds(now_ms, egress)) else { return Some(first) };
    if !goes_on(kept, egress, now_ms) {
        return None;
    }
    let room = MOST.saturating_sub(kept.hosts.len());
    let lacks = |h: &String| !kept.hosts.iter().any(|f| same(&f.host, h));
    Some(first.into_iter().filter(lacks).take(room).collect())
}

/// What a background run adds a probe to.
pub struct Run<'a> {
    pub egress: &'a str,
    /// `HOST:PORT` of the target that the probes name and never dial.
    pub target: &'a str,
    pub now_ms: i64,
}

/// The rank after one background probe of `host`: the partial background
/// rank that holds for the run's egress, with the host's figures in it, or
/// a new one, which keeps the samples of the file; the hosts in order, and
/// `partial` while `more` hosts of the plan wait.
pub fn with_probe(kept: Option<Rank>, run: &Run, host: &str, probe: Probe, more: bool) -> Rank {
    let mut made = match kept {
        Some(k) if goes_on(&k, run.egress, run.now_ms) => k,
        old => Rank {
            schema: rank::SCHEMA,
            made_ms: run.now_ms,
            egress: run.egress.to_string(),
            target: run.target.to_string(),
            rounds: 1,
            source: BACKGROUND.to_string(),
            background_ms: run.now_ms,
            samples: old.map(|o| o.samples).unwrap_or_default(),
            ..Rank::default()
        },
    };
    let name = if host.contains(':') { host.to_string() } else { format!("{host}:443") };
    made.hosts.retain(|f| !same(&f.host, &name));
    made.hosts.push(rank::figures(&name, &[probe]));
    made.hosts = rank::order(std::mem::take(&mut made.hosts));
    made.partial = more;
    made
}

#[cfg(test)]
#[path = "rank_auto_tests.rs"]
mod tests;
