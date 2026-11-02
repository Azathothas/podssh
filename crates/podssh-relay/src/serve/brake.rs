//! The relay role's brake of `/v1/mint` and `/v1/pair` (T-454): 120 requests
//! of one address in a sliding minute, the two paths together, as the
//! contract gives the default relay's ("Attempts with no token",
//! `docs/relay.md`); past them, `429` with a `Retry-After` of the seconds
//! until the oldest of them is a minute old, which podssh's client says
//! (`crate::token`, `crate::pair`). A mint costs the role a MAC and a pair a
//! place of the 4096 of its table, so one client could else fill the table
//! or spend the role's CPU. `/health`, the documents and the sockets of both
//! roads are not counted: a socket needs a token that the brake gave out.
//!
//! The counts are bounded: past [`ADDRESSES`], an address whose minute is
//! over is forgotten first, then the one heard from least lately. The clock
//! is the caller's, monotonic in the role, so that a test sets the time and
//! a step of the wall clock neither frees an address nor holds one.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The requests of one address in [`WINDOW_MS`], as T-169 promised.
pub const PER_MINUTE: usize = 120;
/// The sliding window.
pub const WINDOW_MS: u64 = 60_000;
/// The addresses counted at once: at most 120 times 8 bytes each, under
/// 4 MiB in all.
pub const ADDRESSES: usize = 4096;
/// The header in which Cloudflare's edge names the visitor to the origin.
pub const EDGE_VISITOR: &str = "cf-connecting-ip";

/// Milliseconds on a clock that never goes back.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The role's clock: milliseconds since its start, monotonic.
pub fn monotonic() -> Clock {
    let origin = Instant::now();
    Arc::new(move || u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX))
}

/// Whether a request of `method` to `path` is braked: each mint, and each
/// request to `/v1/pair`, as each is an attempt.
pub fn braked(method: &str, path: &str) -> bool {
    (method == "POST" && path == "/v1/mint") || path == "/v1/pair"
}

/// The visitor that Cloudflare's edge names in [`EDGE_VISITOR`], one address
/// ("the client IP address connecting to Cloudflare", Cloudflare's page of
/// HTTP headers), for a role behind the quick tunnel (T-428), whose peer is
/// the edge. Only a caller whose request came from the edge may take it: on
/// a listener, each client writes the header, and would count apart with
/// each value that it makes up.
pub fn edge_visitor(value: Option<&str>) -> Option<IpAddr> {
    value?.trim().parse().ok()
}

/// Whom a request counts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Who {
    V4(Ipv4Addr),
    /// The first 64 bits of an IPv6 address: a host is commonly given a /64,
    /// whose 2^64 addresses would else each count apart.
    V6([u8; 8]),
    /// A request whose caller gave no address. Such requests share one
    /// count, so that a road that loses the address is braked as a whole,
    /// never not at all.
    Unknown,
}

impl Who {
    pub fn of(address: Option<IpAddr>) -> Who {
        match address {
            Some(IpAddr::V4(v4)) => Who::V4(v4),
            Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
                // An IPv4 client of a socket of both families.
                Some(v4) => Who::V4(v4),
                None => {
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&v6.octets()[..8]);
                    Who::V6(prefix)
                }
            },
            None => Who::Unknown,
        }
    }
}

/// A request that waits: the seconds of its `Retry-After`, and whether it is
/// the first refusal since the address was last let through, so that a role
/// says one line for each address that it brakes, not one for each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Braked {
    pub wait_s: u64,
    pub first: bool,
}

/// The requests of one address that were let through in the window, oldest
/// first, and whether a refusal was said since the last.
#[derive(Default)]
struct Count {
    stamps: VecDeque<u64>,
    said: bool,
}

/// The counts of a role.
pub struct Brake {
    limit: usize,
    window_ms: u64,
    capacity: usize,
    clock: Clock,
    seen: Mutex<HashMap<Who, Count>>,
}

impl Default for Brake {
    fn default() -> Self {
        Brake::new(PER_MINUTE, WINDOW_MS, ADDRESSES, monotonic())
    }
}

impl Brake {
    /// `limit` requests of an address in `window_ms` of `clock`, for
    /// `capacity` addresses at once.
    pub fn new(limit: usize, window_ms: u64, capacity: usize, clock: Clock) -> Brake {
        Brake {
            limit: limit.max(1),
            window_ms: window_ms.max(1),
            capacity: capacity.max(1),
            clock,
            seen: Mutex::default(),
        }
    }

    /// Whether a request of `who` may go on now.
    pub fn take(&self, who: Who) -> Result<(), Braked> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // Read under the lock, so that the times of an address stay in order.
        let now_ms = (self.clock)();
        self.decide(&mut seen, who, now_ms)
    }

    /// [`Brake::take`] at `now_ms`.
    pub fn take_at(&self, who: Who, now_ms: u64) -> Result<(), Braked> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        self.decide(&mut seen, who, now_ms)
    }

    /// The requests of an address that its window lets through.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// How many addresses are counted.
    pub fn len(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Only a request let through counts, so that the wait said is the wait:
    /// a client that asks again too soon is told the same end.
    fn decide(&self, seen: &mut HashMap<Who, Count>, who: Who, now_ms: u64) -> Result<(), Braked> {
        let window = self.window_ms;
        if !seen.contains_key(&who) && seen.len() >= self.capacity {
            make_room(seen, self.capacity, now_ms, window);
        }
        let count = seen.entry(who).or_default();
        while count.stamps.front().is_some_and(|t| now_ms.saturating_sub(*t) >= window) {
            count.stamps.pop_front();
        }
        if count.stamps.len() >= self.limit {
            let oldest = count.stamps.front().copied().unwrap_or(now_ms);
            let wait_ms = oldest.saturating_add(window).saturating_sub(now_ms);
            let first = !std::mem::replace(&mut count.said, true);
            return Err(Braked { wait_s: wait_ms.div_ceil(1000).max(1), first });
        }
        count.stamps.push_back(now_ms);
        count.said = false;
        Ok(())
    }
}

/// Room for one address more among `capacity`: first each whose window is
/// over, as it holds nothing to remember; then the one heard from least
/// lately.
fn make_room(seen: &mut HashMap<Who, Count>, capacity: usize, now_ms: u64, window: u64) {
    seen.retain(|_, c| c.stamps.back().is_some_and(|t| now_ms.saturating_sub(*t) < window));
    while seen.len() >= capacity {
        let least = seen.iter().min_by_key(|(_, c)| c.stamps.back().copied().unwrap_or(0)).map(|(who, _)| *who);
        let Some(least) = least else { break };
        seen.remove(&least);
    }
}

#[cfg(test)]
#[path = "brake_tests.rs"]
mod tests;
