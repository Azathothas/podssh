//! E15 — ⛔ **the cache, bounded by age and with no sweeper thread.**
//!
//! ⛔ **READ**, `dropssh` `src/dns.c:27-31`, the sibling's reason for having a
//! cache at all: *"THE CACHE EXISTS BECAUSE A SESSION RECONNECTS. A relay client
//! that resolves on every attempt pays a full round trip on every reconnect, and
//! a reconnect is exactly when the operator is waiting. Entries are kept for a
//! bounded time and the bound is honoured by age, not by a sweeper thread: a
//! thread would need a working pthread, and a cage may not have one."*
//!
//! ⛔ **So: no thread, no sweeper, no `tokio::spawn`.** Expiry is checked on
//! lookup and a full table evicts the oldest entry, and ⛔ **that is the whole
//! implementation** — a background task that could not run on the target host
//! would be a capability gated on something unprobed, which `AGENTS.md` forbids.
//!
//! ⛔ **The numbers are the sibling's, not invented:** `src/dns.c:46`
//! `DNS_MAX_CACHE 32` and `src/dns.c:47` `DNS_TTL_SEC 300`.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// ⛔ **READ**, `src/dns.c:46`: 32 entries.
pub const MAX_ENTRIES: usize = 32;
/// ⛔ **READ**, `src/dns.c:47`: 300 seconds.
pub const TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
struct Entry {
    addrs: Vec<SocketAddr>,
    at: Instant,
}

#[derive(Debug)]
struct Inner {
    by_name: HashMap<String, Entry>,
    /// ⛔ **Insertion order, kept so eviction is oldest-first.** ⛔ A
    /// `HashMap` has no order and "evict something arbitrary" is a cache whose
    /// behaviour nobody can describe.
    order: Vec<String>,
}

/// ⛔ **The cache. Poisoning is not an error here**, and the reason is that a
/// `Mutex` that panicked mid-`insert` holds nothing worth recovering: every
/// entry is derivable by resolving again, ⛔ **which is exactly what the chain
/// does when the cache misses.** Taking the inner value is therefore the honest
/// response, and it is not a silent wrong answer.
#[derive(Debug)]
pub struct Cache {
    inner: Mutex<Inner>,
    ttl: Duration,
    max_entries: usize,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { by_name: HashMap::new(), order: Vec::new() }),
            ttl: TTL,
            max_entries: MAX_ENTRIES,
        }
    }

    /// ⛔ **A cache with a different bound, for a test and for an operator.** ⛔
    /// The bound is a parameter rather than a constant so a test can prove the
    /// TTL is honoured ⛔ **without waiting 300 seconds**, and a unit test that
    /// waited would be a unit test nobody runs.
    pub fn with_bounds(ttl: Duration, max_entries: usize) -> Self {
        Self { inner: Mutex::new(Inner { by_name: HashMap::new(), order: Vec::new() }), ttl, max_entries }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // ⛔ `unwrap_or_else(|e| e.into_inner())` — see the type's doc comment.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// ⛔ **A live answer, or `None`.** ⛔ **Age is checked here and nowhere
    /// else**, which is what makes a sweeper thread unnecessary.
    pub fn get(&self, name: &str) -> Option<Vec<SocketAddr>> {
        let now = Instant::now();
        let mut inner = self.lock();
        let expired = inner
            .by_name
            .get(name)
            .map(|e| now.duration_since(e.at) >= self.ttl)
            .unwrap_or(false);
        if expired {
            inner.by_name.remove(name);
            inner.order.retain(|k| k != name);
            return None;
        }
        inner.by_name.get(name).map(|e| e.addrs.clone())
    }

    /// ⛔ **Store an answer. ⛔ An empty list is not stored**, because a cache
    /// that remembers a failure as an answer would return it on the next lookup
    /// with no way to say it was a failure.
    pub fn put(&self, name: &str, addrs: &[SocketAddr]) {
        if addrs.is_empty() {
            return;
        }
        let mut inner = self.lock();
        if inner.by_name.contains_key(name) {
            inner.by_name.insert(name.to_string(), Entry { addrs: addrs.to_vec(), at: Instant::now() });
            return;
        }
        // ⛔ **Oldest-first eviction, and it happens here so the bound is a
        // property of the table rather than of whoever remembered to sweep.**
        while inner.order.len() >= self.max_entries && self.max_entries > 0 {
            let victim = inner.order.remove(0);
            inner.by_name.remove(&victim);
        }
        if self.max_entries == 0 {
            return;
        }
        inner.order.push(name.to_string());
        inner.by_name.insert(name.to_string(), Entry { addrs: addrs.to_vec(), at: Instant::now() });
    }

    pub fn len(&self) -> usize {
        self.lock().by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub const fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// ⛔ **Deduplicate and sort, so two runs of the chain on the same host produce
/// the same `Vec` in the same order.** ⛔ A `BTreeSet` is used rather than a
/// `Vec::dedup` because the input order comes from `getaddrinfo` and is
/// platform-defined, ⛔ **and a comparison a test can make is worth more here
/// than the resolver's own preference order, which nothing in this repository
/// has measured.**
pub fn normalise(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addrs.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}