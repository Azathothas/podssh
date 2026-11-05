//! What each key carried through the relay role (T-636, GitHub #134). A
//! token names no key and ends at a restart (`super::tokens`), so at each
//! mint for a key the role keeps the token's SHA-256, never the token, with
//! the key's fingerprint, in memory until the token ends: 64 live tokens a
//! key at most, the oldest forgotten first. Each session of the forward road
//! (`/connect/`, each link of the layer, a session of the HTTP road) counts
//! each way apart and charges its key once, at its end ([`Meter`]); an empty
//! keepalive frame is no byte. A key's totals for the day (UTC) and the day
//! before outlive a restart in the private file of `--usage`, written as the
//! pairs' file is, each 2 s while a count moved ([`Usage::keep`]).
//! `--quota MIB` is a key's budget for a day, both ways together: once its
//! key spent it, a token gets `403` before its target is dialed, until the
//! next day. A token minted for anyone counts against no key.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use podssh_ws::http::request::Request;
use serde::{Deserialize, Serialize};

use super::brake::Clock;
use super::Config;

/// The live tokens of one key that the role keeps; past them, the oldest is
/// forgotten.
pub const TOKENS_A_KEY: usize = 64;
/// How often the file of the counts is written while a count moved.
pub const WRITE_EVERY: Duration = Duration::from_secs(2);
/// A day of the budget, in UTC.
pub const DAY_MS: u64 = 24 * 3600 * 1000;
/// The keys that the role's lines name at SIGHUP, the most of today first.
pub const LINES_MOST: usize = 50;
const MIB: u64 = 1 << 20;
/// The refusal of a token that the role holds no more, under a budget.
pub const FORGOTTEN: &str = "this relay counts each token for its key, and holds this one no more; mint another";

/// Where the counts say a line.
pub type Say = Arc<dyn Fn(&str) + Send + Sync>;

/// One day's count of one key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Day {
    /// Days since the epoch, in UTC.
    pub day: u64,
    /// The client's bytes to its targets.
    pub up: u64,
    /// The targets' bytes to the client.
    pub down: u64,
    /// The sessions that ended.
    pub sessions: u64,
}

impl Day {
    /// Both ways together, as the budget counts them.
    pub fn bytes(&self) -> u64 {
        self.up.saturating_add(self.down)
    }
}

/// A key's totals: the day of its last session, and the day before it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub today: Day,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Day>,
}

impl Totals {
    /// The totals as of `day`: a count of the day before moves to `before`,
    /// an older one is forgotten; a clock that went back keeps them as they
    /// are, so that no step of it gives a key a new budget.
    pub fn on(self, day: u64) -> Totals {
        if day <= self.today.day {
            return self;
        }
        let before = (self.today.day + 1 == day && self.today.sessions > 0).then_some(self.today);
        Totals { today: Day { day, ..Day::default() }, before }
    }

    /// Whether it holds a count worth keeping.
    pub fn carried(&self) -> bool {
        self.today.sessions > 0 || self.before.is_some()
    }
}

// The tokens minted for keys, by digest (`usage_keyed.rs`).
#[path = "usage_keyed.rs"]
mod keyed;
use keyed::{digest, Keyed};

// The file of the counts (`usage_file.rs`).
#[path = "usage_file.rs"]
mod file;
use file::{load, File};
pub use file::FILE_MOST;

struct Ledger {
    /// Each key's budget for a day, in bytes, both ways together.
    quota: Option<u64>,
    file: Option<PathBuf>,
    /// Milliseconds since the epoch: the days of the budget are UTC's.
    clock: Clock,
    keyed: Mutex<Keyed>,
    totals: Mutex<HashMap<String, Totals>>,
    /// A count moved since the last write.
    dirty: AtomicBool,
    say: Mutex<Option<Say>>,
}

fn lock<T>(held: &Mutex<T>) -> MutexGuard<'_, T> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

/// A role's counts of each key, shared by its sessions.
#[derive(Clone)]
pub struct Usage(Arc<Ledger>);

impl Default for Usage {
    /// Counts in memory alone, with no budget: a role that names no file.
    fn default() -> Self {
        Usage::with(None, None, Arc::new(super::tokens::now_ms), HashMap::new())
    }
}

impl Usage {
    fn with(quota: Option<u64>, file: Option<PathBuf>, clock: Clock, totals: HashMap<String, Totals>) -> Usage {
        Usage(Arc::new(Ledger {
            quota,
            file,
            clock,
            keyed: Mutex::default(),
            totals: Mutex::new(totals),
            dirty: AtomicBool::new(false),
            say: Mutex::new(None),
        }))
    }

    /// The counts kept in `file`, when one is named, with a budget of `quota`
    /// bytes a day for each key: a missing file is the role's first run, and
    /// one that does not read, or that others may read, is refused, as the
    /// pairs' file is, so that no start forgets what a key spent.
    pub fn open(quota: Option<u64>, file: Option<PathBuf>) -> Result<Usage, String> {
        Usage::open_on(quota, file, Arc::new(super::tokens::now_ms))
    }

    /// [`Usage::open`] on `clock`, in ms since the epoch: a test's.
    pub fn open_on(quota: Option<u64>, file: Option<PathBuf>, clock: Clock) -> Result<Usage, String> {
        let day = clock() / DAY_MS;
        let totals = match &file {
            Some(path) => load(path, day)?,
            None => HashMap::new(),
        };
        Ok(Usage::with(quota, file, clock, totals))
    }

    /// Say each line of the counts to `say`: a key that spent its budget,
    /// and a write that failed.
    pub fn say_to(&self, say: Say) {
        *lock(&self.0.say) = Some(say);
    }

    pub fn quota(&self) -> Option<u64> {
        self.0.quota
    }

    pub fn file(&self) -> Option<&Path> {
        self.0.file.as_deref()
    }

    /// The keys whose counts it holds.
    pub fn keys(&self) -> usize {
        lock(&self.0.totals).len()
    }

    fn now(&self) -> u64 {
        (self.0.clock)()
    }

    fn day(&self) -> u64 {
        self.now() / DAY_MS
    }

    /// Keep `token`, minted for the key of the fingerprint `key` and ending
    /// at `ends`, so that its sessions count against that key; false when
    /// another key holds the same token, which two mints in one millisecond
    /// make: the caller mints another.
    pub fn minted(&self, token: &str, key: &str, ends: u64) -> bool {
        lock(&self.0.keyed).keep(digest(token), key, ends, self.now())
    }

    /// The fingerprint of the key that `token` was minted for, while the
    /// role holds it.
    pub fn key_of(&self, token: &str) -> Option<String> {
        lock(&self.0.keyed).key_of(&digest(token), self.now())
    }

    /// The bytes that `key` carried today, both ways.
    pub fn spent(&self, key: &str) -> u64 {
        self.totals(key).map_or(0, |t| t.today.bytes())
    }

    /// `key`'s totals as of today.
    pub fn totals(&self, key: &str) -> Option<Totals> {
        let day = self.day();
        lock(&self.0.totals).get(key).map(|t| t.on(day))
    }

    /// The meter of a session of `token`: its key's, or none for a token
    /// minted for anyone. `Err` holds the words of the `403` that its road
    /// answers before anything is dialed: a key whose budget for today is
    /// spent; and, where the role mints for keys (`keyed`) under a budget, a
    /// token that it holds no more (past a key's 64), which would else count
    /// against no key.
    pub fn meter(&self, token: &str, keyed: bool) -> Result<Meter, String> {
        let key = self.key_of(token);
        if let Some(quota) = self.0.quota {
            match &key {
                Some(key) if self.spent(key) >= quota => {
                    return Err(format!("this key's quota of {} for today is spent", quota_words(quota)));
                }
                None if keyed => return Err(FORGOTTEN.to_string()),
                _ => {}
            }
        }
        Ok(Meter::of(self.clone(), key))
    }

    /// Charge one session's bytes to `key`, and say the session that spent
    /// its budget for today, once.
    fn charge(&self, key: &str, up: u64, down: u64) {
        let day = self.day();
        let spent = {
            let mut totals = lock(&self.0.totals);
            let held = totals.entry(key.to_string()).or_default();
            *held = held.on(day);
            let before = held.today.bytes();
            held.today.up = held.today.up.saturating_add(up);
            held.today.down = held.today.down.saturating_add(down);
            held.today.sessions += 1;
            let now = held.today;
            self.0.quota.filter(|q| before < *q && now.bytes() >= *q).map(|q| (q, now))
        };
        self.0.dirty.store(true, Ordering::SeqCst);
        if let Some((quota, today)) = spent {
            let spent = format!("{} for today, {}", quota_words(quota), words(&today));
            self.say(&format!("usage: the key {key} spent its quota of {spent}"));
        }
    }

    fn say(&self, line: &str) {
        let say = lock(&self.0.say).clone();
        if let Some(say) = say {
            say(line);
        }
    }

    /// Each key's totals of today and the day before, the most of today
    /// first, [`LINES_MOST`] keys at most: what `relay serve` says at SIGHUP.
    pub fn lines(&self) -> Vec<String> {
        let day = self.day();
        let mut held: Vec<(String, Totals)> =
            lock(&self.0.totals).iter().map(|(k, t)| (k.clone(), t.on(day))).filter(|(_, t)| t.carried()).collect();
        if held.is_empty() {
            return vec!["usage: no key carried a byte today or the day before".to_string()];
        }
        held.sort_by(|a, b| b.1.today.bytes().cmp(&a.1.today.bytes()).then_with(|| a.0.cmp(&b.0)));
        let budget = self.0.quota.map(|q| format!(", of a quota of {} a day", quota_words(q))).unwrap_or_default();
        let mut lines: Vec<String> = held
            .iter()
            .take(LINES_MOST)
            .map(|(key, t)| {
                let before = t.before.map(|d| format!("; the day before, {}", words(&d))).unwrap_or_default();
                format!("usage: the key {key}: today, {}{budget}{before}", words(&t.today))
            })
            .collect();
        if held.len() > LINES_MOST {
            lines.push(format!("usage: and {} keys more", held.len() - LINES_MOST));
        }
        lines
    }

    /// Write the counts to the file, when one is named and a count moved
    /// since the last write: `Ok(true)` for a write. A write that fails
    /// leaves the file of before whole, and the next call tries again.
    pub fn save(&self) -> Result<bool, String> {
        let Some(path) = &self.0.file else { return Ok(false) };
        if !self.0.dirty.swap(false, Ordering::SeqCst) {
            return Ok(false);
        }
        let day = self.day();
        let keys: BTreeMap<String, Totals> = {
            let mut totals = lock(&self.0.totals);
            // A key with no count of today or the day before is forgotten.
            totals.retain(|_, t| {
                *t = t.on(day);
                t.carried()
            });
            totals.iter().map(|(k, t)| (k.clone(), *t)).collect()
        };
        let written = serde_json::to_vec(&File { keys })
            .map_err(|e| e.to_string())
            .and_then(|body| super::reverse::pairs::write_private(path, &body).map_err(|e| e.to_string()));
        written.map(|()| true).map_err(|why| {
            self.0.dirty.store(true, Ordering::SeqCst);
            format!("{}: {why}", path.display())
        })
    }

    /// Write the counts each [`WRITE_EVERY`] while a count moved, in the
    /// role's runtime, for as long as it runs: the first write that fails,
    /// and the first that works after it, are lines.
    pub async fn keep(self) {
        let mut failing = false;
        loop {
            tokio::time::sleep(WRITE_EVERY).await;
            match self.save() {
                Ok(_) if failing => {
                    failing = false;
                    self.say("usage: its file takes the counts again");
                }
                Ok(_) => {}
                Err(why) if !failing => {
                    failing = true;
                    self.say(&format!("usage: the counts were not written: {why}; tried again each 2 s"));
                }
                Err(_) => {}
            }
        }
    }
}

/// The meter of a session whose request is `head`, by its token's key and
/// the role's budget: `Err` holds the words of the `403` that its road
/// answers before anything is dialed.
pub fn meter_of(cfg: &Config, head: &Request) -> Result<Meter, String> {
    let token = head.header("x-relay-token").unwrap_or_default();
    cfg.usage.meter(token, super::keys::Whom::of(&cfg.mint).is_some())
}

/// One session's bytes, each way apart, charged to its key once, at its
/// end: at [`Meter::settle`], or when it is dropped, so that a session whose
/// task ends early is charged too. A request that never became a session
/// ([`Meter::start`] never called: a refusal, a target out of reach)
/// charges nothing.
pub struct Meter {
    usage: Usage,
    key: Option<String>,
    up: AtomicU64,
    down: AtomicU64,
    started: AtomicBool,
    settled: AtomicBool,
}

impl Meter {
    fn of(usage: Usage, key: Option<String>) -> Meter {
        let (up, down) = (AtomicU64::new(0), AtomicU64::new(0));
        Meter { usage, key, up, down, started: AtomicBool::new(false), settled: AtomicBool::new(false) }
    }

    /// The fingerprint of the key that it charges, if any.
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// The session began: its end charges its key.
    pub fn start(&self) {
        self.started.store(true, Ordering::SeqCst);
    }

    /// `n` bytes of the client's, written to its target.
    pub fn up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// `n` bytes of the target's, sent to its client.
    pub fn down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Charge the session to its key, once.
    pub fn settle(&self) {
        if self.settled.swap(true, Ordering::SeqCst) || !self.started.load(Ordering::SeqCst) {
            return;
        }
        if let Some(key) = &self.key {
            self.usage.charge(key, self.up.load(Ordering::SeqCst), self.down.load(Ordering::SeqCst));
        }
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        self.settle();
    }
}

/// A budget in the role's words: whole MiB as MiB, else bytes.
pub fn quota_words(bytes: u64) -> String {
    match bytes % MIB {
        0 => format!("{} MiB", bytes / MIB),
        _ => format!("{bytes} bytes"),
    }
}

/// An amount carried, in the role's words.
fn size(bytes: u64) -> String {
    if bytes < MIB {
        format!("{bytes} bytes")
    } else {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    }
}

/// One day's count, in the role's words.
fn words(day: &Day) -> String {
    let s = if day.sessions == 1 { "" } else { "s" };
    format!("{} up and {} down in {} session{s}", size(day.up), size(day.down), day.sessions)
}

#[cfg(test)]
#[path = "usage_tests.rs"]
mod tests;
