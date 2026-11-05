//! The lists of the names that ECH seals, kept in the process (T-642), so
//! that the record is read once for each name and TTL, never once for each
//! connection: a list for its record's TTL, 30 s at least, 300 s where the
//! answer gave none, and a day at most; a name that publishes none, or whose
//! read failed, for 30 s; and a name whose sealed hello failed is left alone
//! for 5 minutes, after which its record is read again, so that a list
//! published later is taken with no restart.
//!
//! The clock is a field, so that a test moves it and sleeps not at all. One
//! read of a name goes at a time: a run that opens its sessions at once asks
//! once. The maps are bounded, as their keys are names that a user or a peer
//! chooses.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::resolve::https::Published;

/// The least time that a list is kept, whatever its TTL says.
pub const FLOOR: Duration = Duration::from_secs(30);
/// The time that a list is kept when its answer gave no TTL.
pub const NO_TTL: Duration = Duration::from_secs(300);
/// The most time that a list is kept: a long-lived node reads it again.
pub const CEILING: Duration = Duration::from_secs(24 * 3600);
/// The time that a name with no list, or a failed read, is kept.
pub const MISS: Duration = Duration::from_secs(30);
/// The time that a name whose sealed hello failed is left alone.
pub const COOL: Duration = Duration::from_secs(300);
/// The names kept in each map.
pub const MOST: usize = 256;

/// What the cache reads the time from: the system's, or a test's.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// What a name gives a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The ECHConfigList to seal with.
    List(Vec<u8>),
    /// None, and why.
    None(Why),
}

/// Why a name gives no list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// Its record holds none.
    NotPublished,
    /// Its record could not be read.
    ReadFailed(String),
    /// Its sealed hello failed within [`COOL`].
    Cooled,
}

/// What a read gave, kept until its time ends.
struct Entry {
    found: Lookup,
    until: Instant,
}

#[derive(Default)]
struct State {
    names: HashMap<String, Entry>,
    /// Each name left alone, until when.
    cooled: HashMap<String, Instant>,
    /// One read at a time for each name.
    flights: HashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

/// The lists of names, by the clock of [`Cache::with_clock`].
pub struct Cache {
    clock: Box<dyn Clock>,
    state: Mutex<State>,
}

impl Default for Cache {
    fn default() -> Self {
        Cache::new()
    }
}

/// How long a list is kept for its record's `ttl`: [`FLOOR`] to
/// [`CEILING`], and [`NO_TTL`] for none.
pub fn kept_for(ttl: Option<u32>) -> Duration {
    match ttl {
        None => NO_TTL,
        Some(secs) => Duration::from_secs(u64::from(secs)).clamp(FLOOR, CEILING),
    }
}

impl Cache {
    /// A cache on the system's clock.
    pub fn new() -> Cache {
        Cache::with_clock(Box::new(SystemClock))
    }

    /// A cache on `clock`.
    pub fn with_clock(clock: Box<dyn Clock>) -> Cache {
        Cache { clock, state: Mutex::new(State::default()) }
    }

    /// What `name` gives a connection: what is kept for it, else what `ask`
    /// reads, which is then kept. A name left alone gets nothing, and `ask`
    /// is not called.
    pub async fn lookup<F, Fut>(&self, name: &str, ask: F) -> Lookup
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<Published>, String>>,
    {
        let name = super::key(name);
        if let Some(found) = self.kept(&name) {
            return found;
        }
        // A second lookup of the name waits for the first's read, then
        // takes what it kept.
        let flight = self.lock().flights.entry(name.clone()).or_default().clone();
        let _turn = flight.lock().await;
        if let Some(found) = self.kept(&name) {
            return found;
        }
        let (found, ttl) = match ask().await {
            Ok(Some(published)) => (Lookup::List(published.list), kept_for(published.ttl)),
            Ok(None) => (Lookup::None(Why::NotPublished), MISS),
            Err(why) => (Lookup::None(Why::ReadFailed(why)), MISS),
        };
        self.keep(&name, found.clone(), ttl);
        found
    }

    /// What is kept for `name` now, or nothing.
    fn kept(&self, name: &str) -> Option<Lookup> {
        let now = self.clock.now();
        let state = self.lock();
        if state.cooled.get(name).is_some_and(|until| now < *until) {
            return Some(Lookup::None(Why::Cooled));
        }
        state.names.get(name).filter(|entry| now < entry.until).map(|entry| entry.found.clone())
    }

    /// Keep `found` for `name` for `ttl`, within the bound of the map.
    fn keep(&self, name: &str, found: Lookup, ttl: Duration) {
        let now = self.clock.now();
        let mut state = self.lock();
        state.names.retain(|_, entry| now < entry.until);
        state.cooled.retain(|_, until| now < *until);
        // A flight that no lookup holds any more is done.
        state.flights.retain(|_, flight| Arc::strong_count(flight) > 1);
        if !state.names.contains_key(name) && state.names.len() >= MOST {
            let soonest = state.names.iter().min_by_key(|(_, entry)| entry.until).map(|(n, _)| n.clone());
            if let Some(soonest) = soonest {
                state.names.remove(&soonest);
            }
        }
        state.names.insert(name.to_string(), Entry { found, until: now + ttl });
    }

    /// Keep `list` for `name` for `ttl` ([`FLOOR`] to [`CEILING`]), and leave
    /// the name alone no more: a server's retry configs, which it proved
    /// with the certificate of the list's public name.
    pub fn remember(&self, name: &str, list: Vec<u8>, ttl: Duration) {
        let name = super::key(name);
        self.lock().cooled.remove(&name);
        self.keep(&name, Lookup::List(list), ttl.clamp(FLOOR, CEILING));
    }

    /// `name`'s sealed hello failed: its list goes, and the name is left
    /// alone for [`COOL`].
    pub fn refused(&self, name: &str) {
        let name = super::key(name);
        let now = self.clock.now();
        let mut state = self.lock();
        state.names.remove(&name);
        if !state.cooled.contains_key(&name) && state.cooled.len() >= MOST {
            let soonest = state.cooled.iter().min_by_key(|(_, until)| **until).map(|(n, _)| n.clone());
            if let Some(soonest) = soonest {
                state.cooled.remove(&soonest);
            }
        }
        state.cooled.insert(name, now + COOL);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The process's cache, on the system's clock.
pub fn process() -> &'static Cache {
    static PROCESS: OnceLock<Cache> = OnceLock::new();
    PROCESS.get_or_init(Cache::new)
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
