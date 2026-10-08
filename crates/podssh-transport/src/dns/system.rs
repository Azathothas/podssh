//! E15 — ⛔ **the system resolver, on a blocking thread under a watchdog.**
//!
//! ⛔ **This is the stage that hangs, and the reason the whole module is built
//! this way.** `AGENTS.md`: ⛔ *"Never gate startup on a capability that has not
//! been probed"*, and `dns.md`: *"Every wait is bounded, per-stage, not
//! per-call. The system resolver is the one that hangs: `getaddrinfo` on a host
//! whose `resolv.conf` names an unreachable nameserver blocks past any timeout
//! set around it."*
//!
//! ⛔ **podssh runs the system stage on a blocking thread with a watchdog, not
//! on the async runtime's timeout** — a future cancelled by
//! `tokio::time::timeout` does not stop a thread already inside libc. ⛔ **The
//! sibling calls `getaddrinfo` inline** (**READ**, `src/dns.c:336-356`) ⛔ **and
//! inherits whatever the platform does**, which is the defect this module does
//! not copy.
//!
//! ⛔ **The watchdog is pure arithmetic and needs no network to prove.** The
//! test calls [`watchdog`] directly with a closure that never returns and
//! asserts `Unknown` comes back ⛔ **inside a bound far below any real
//! `getaddrinfo`**, so the guarantee is measured on every run rather than only
//! on a host that happens to hang.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::cache::normalise;
use super::{StageOutcome, StageReport};
use super::Stage;

/// ⛔ **The system-resolver budget.** ⛔ **Four seconds, and it is a named
/// constant rather than a literal** so `dns.md`'s plant ⛔ — *"a `resolv.conf`
/// pointing at an unreachable nameserver. `System` must report `FAIL` after its
/// watchdog fires, not hang"* ⛔ — has a number to name. ⚠ **This is a
/// client-side bound and not a measurement of any host's resolver latency.**
pub const SYSTEM_BUDGET: Duration = Duration::from_secs(4);

/// ⛔ **`getaddrinfo`, as a plain function, so the watchdog can be tested without
/// libc and without a network.**
pub trait SystemLookup: Send + Sync + 'static {
    fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, (Option<i32>, String)>;
}

/// ⛔ **The real one.** ⛔ `ToSocketAddrs` is `std`'s wrapper over the platform's
/// resolver — `getaddrinfo(3)` on Linux, `getaddrinfo` again on macOS, and
/// `GetAddrInfoW` on Windows ⛔ **and podssh inherits whichever it is, because
/// there is no other option that is a resolver.**
#[derive(Debug, Default)]
pub struct SystemResolver;

impl SystemResolver {
    pub const fn new() -> Self {
        Self
    }
}

impl SystemLookup for SystemResolver {
    fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, (Option<i32>, String)> {
        use std::net::ToSocketAddrs;
        // ⛔ `Ok` with nothing in it is **not** a resolution. An empty iterator is
        // what a resolver returns for a name with no records, and handing it on
        // as a success is how a caller ends up dialling nothing.
        match (host, port).to_socket_addrs() {
            Ok(it) => {
                let addrs = normalise(it);
                if addrs.is_empty() {
                    Err((None, "the system resolver returned no addresses".into()))
                } else {
                    Ok(addrs)
                }
            }
            Err(e) => {
                // ⛔ `raw_os_error` is the `errno`, and `dns.md` writes `FAIL
                // <errno>`.
                Err((e.raw_os_error(), e.to_string()))
            }
        }
    }
}

/// ⛔ **What the watchdog produced.** ⛔ `Abandoned` is ⛔ **not** `Failed`, and
/// that distinction is the whole point: a future cancelled around `getaddrinfo`
/// leaves a thread inside libc that may yet answer, so podssh cannot say the
/// lookup failed ⛔ **it can only say it did not answer in time.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Watchdog<T> {
    Answered(T),
    /// ⛔ The budget expired. ⛔ The thread was signalled to stop and may not
    /// have; it was **not** joined, because joining would block past the very
    /// budget that exists to bound it.
    Abandoned,
}

struct Slot<T> {
    value: Option<T>,
    filled: bool,
    stop: Arc<AtomicBool>,
}

/// ⛔ **Run `lookup` with a watchdog. ⛔ This is the mechanism, and it is the one
/// `dns.md` names:** a blocking thread, a budget, and a signal the worker
/// checks ⛔ **between attempts**, never inside libc.
pub fn watchdog<T, F>(budget: Duration, lookup: F) -> Watchdog<T>
where
    T: Send + 'static,
    F: FnOnce(&AtomicBool) -> T + Send + 'static,
{
    let slot = Arc::new((Mutex::new(Slot::<T> { value: None, filled: false, stop: Arc::new(AtomicBool::new(false)) }), Condvar::new()));
    // ⛔ **The worker's own view of the slot.** ⛔ **It takes the lock three
    // times and holds it for the duration of `lookup` exactly zero times** ⛔ —
    // ⛔ **holding it across `lookup` is what deadlocks a watchdog whose whole
    // ⛔ job is to time the call**, ⛔ and ⛔ **that is the first bug
    // ⛔ this function had** ⛔ (MEASURED 2026-10-02: every lookup
    // ⛔ reported `????` with the budget as its reason, ⛔ and the
    // ⛔ hanging plant passed ⛔ **for the wrong reason**).
    let worker: JoinHandle<()> = {
        let slot = Arc::clone(&slot);
        std::thread::spawn(move || {
            let stop = {
                let (lock, _) = &*slot;
                lock.lock().unwrap_or_else(|e| e.into_inner()).stop.clone()
            };
            // ⛔ **The signal is checked before the call, ⛔ and ⛔ checking it
            // inside `libc` is impossible** ⛔ — ⛔ which is the whole reason the
            // caller signals rather than cancels.
            let stop_was_set = stop.load(Ordering::SeqCst);
            let value = if stop_was_set { None } else { Some(lookup(&stop)) };
            if let Some(value) = value {
                let (lock, cvar) = &*slot;
                let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                guard.value = Some(value);
                guard.filled = true;
                drop(guard);
                // ⛔ **Notify after the lock is released**, ⛔ **because
                // `Condvar::notify_all` while holding the lock makes the woken
                // ⛔ thread immediately block again**.
                cvar.notify_all();
            }
        })
    };

    let deadline = Instant::now() + budget;
    let (lock, cvar) = &*slot;
    let answered = {
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !guard.filled {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (next, timed_out) = cvar
                .wait_timeout(guard, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            guard = next;
            if timed_out.timed_out() && !guard.filled {
                break;
            }
        }
        if guard.filled {
            guard.value.take()
        } else {
            // ⛔ **Signal, do not join.** Joining is the bug: it would make the
            // watchdog wait for the very call the watchdog exists to bound.
            let _ = &mut guard;
            guard.stop.store(true, Ordering::SeqCst);
            None
        }
    };
    cvar.notify_all();
    drop(worker);

    match answered {
        Some(value) => Watchdog::Answered(value),
        None => Watchdog::Abandoned,
    }
}

/// ⛔ **The result of one `System` stage run.** ⛔ A type, ⛔ **not a bare
/// `Result`**, because the third value ⛔ — *abandoned* ⛔ — is not an error and
/// collapsing it into one is exactly the conflation `????` exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemResult {
    Answered(Vec<SocketAddr>),
    Failed { errno: Option<i32>, detail: String },
    Abandoned { budget: Duration },
}

impl SystemResult {
    pub fn outcome(&self) -> StageOutcome {
        match self {
            SystemResult::Answered(a) => StageOutcome::Ok { addresses: a.clone() },
            SystemResult::Failed { errno, detail } => {
                StageOutcome::Failed { errno: *errno, detail: detail.clone() }
            }
            SystemResult::Abandoned { budget } => StageOutcome::Unknown {
                why: format!(
                    "the call is still inside getaddrinfo after {:?}; a future cancelled \
                     around it would not have stopped it",
                    budget
                ),
            },
        }
    }

    pub fn report(&self) -> StageReport {
        StageReport { stage: Stage::System, outcome: self.outcome(), consulted: true }
    }
}

/// ⛔ **Run the `System` stage once.** ⛔ The budget is a parameter ⛔ **and not a
/// constant at the call site**, because `relay-hostname.md`'s plant needs a
/// resolver that hangs against a budget short enough for a test suite.
pub fn run(lookup: Arc<dyn SystemLookup>, host: &str, port: u16, budget: Duration) -> SystemResult {
    let name = host.to_string();
    match watchdog::<SystemResult, _>(budget, move |_stop| {
        match lookup.lookup(&name, port) {
            Ok(addrs) => SystemResult::Answered(addrs),
            Err((errno, detail)) => SystemResult::Failed { errno, detail },
        }
    }) {
        Watchdog::Answered(result) => result,
        Watchdog::Abandoned => SystemResult::Abandoned { budget },
    }
}