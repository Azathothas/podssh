//! A gate for each relay origin in the process (T-637, GitHub #135): the
//! sessions of one process that open against one host share what each
//! learns of it. While the host gave no failure, up to [`MOST_AT_ONCE`]
//! attempts run at once. A failure that is the host's closes the gate: none
//! passes for [`FIRST_WAIT`], then one probe at a time, and each probe that
//! fails doubles the wait up to [`LONGEST_WAIT`]; an answer that shows the
//! host alive opens it again (a session, a policy's refusal, the relay's 502
//! of a target). Each admission takes the gate's epoch, so the failures of
//! one wave move the ladder once, and a verdict of an older epoch lengthens a
//! wait and never shortens it. A mint's `Retry-After` lengthens a wait, up to
//! [`RETRY_AFTER_MOST`].
//!
//! The wait sits outside the attempt's deadline ([`guarded`]), so that a
//! wait that ends is never read as a host that timed out. An attempt held at
//! a host with a successor in its list goes on at once ([`OpenError::Held`]);
//! at its last host it waits, bounded by its caller's own limit. The gates
//! live in the process and start open, as each new command does; the record
//! of failures (`failures.rs`) carries what one run learns to the next.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use podssh_ws::ConnectError;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::open::OpenError;
use crate::relay::Relay;
use crate::token::TokenError;

/// The attempts that run at once at a host that gave no failure.
pub const MOST_AT_ONCE: usize = 8;
/// The first wait after a failure: the first backoff between rounds, so a
/// lone session waits no longer than its own backoff made it wait.
pub const FIRST_WAIT: Duration = crate::open::BACKOFF_FIRST;
/// The longest wait of the ladder: the longest backoff between rounds, which
/// the resumable layer's new links take too.
pub const LONGEST_WAIT: Duration = crate::open::BACKOFF_MAX;
/// The longest that a mint's `Retry-After` holds a gate: the record's rest
/// of a host (T-563).
pub const RETRY_AFTER_MOST: Duration = crate::failures::REST;

/// What an attempt's end says of its host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// It answered: a session, or a refusal that is the relay's own word.
    Alive,
    /// It failed, as another host might not; with the wait that it asked for.
    Failed(Option<Duration>),
    /// Nothing of the host: an error of this side, or of every host.
    Neither,
}

/// The verdict of an attempt's `result`: a failure where the record of
/// failures would keep one, else an answer of the relay's, else neither.
pub fn verdict<T>(result: &Result<T, OpenError>) -> Verdict {
    let e = match result {
        Ok(_) => return Verdict::Alive,
        Err(e) => e,
    };
    if crate::failures::reason(e).is_some() {
        return Verdict::Failed(retry_after(e));
    }
    match e {
        OpenError::Connect { error: ConnectError::Refused { .. }, .. } | OpenError::Token(TokenError::NotIssued) => {
            Verdict::Alive
        }
        _ => Verdict::Neither,
    }
}

/// A mint's `Retry-After`, in seconds; an HTTP date is not read.
fn retry_after(e: &OpenError) -> Option<Duration> {
    match e {
        OpenError::Token(TokenError::RateLimited { retry_after: Some(text) }) => {
            text.trim().parse::<u64>().ok().map(Duration::from_secs)
        }
        _ => None,
    }
}

/// The words of a host that the gate holds: the wait left, or `None` while
/// another session's probe runs.
pub fn words(left: Option<Duration>) -> String {
    match left {
        Some(left) => format!("waits {} s after a failure of this process", left.as_millis().div_ceil(1000)),
        None => "waits for the probe of this process after a failure".to_string(),
    }
}

/// A closed gate: the ladder's wait, when the next probe may go, and
/// whether one runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Closed {
    wait: Duration,
    until: Instant,
    probing: bool,
}

/// What the gate knows of one origin.
#[derive(Debug, Default)]
struct State {
    /// Attempts admitted and not ended.
    running: usize,
    /// One more at each change: a failure that closed the gate or moved its
    /// ladder, and an answer that opened it.
    epoch: u64,
    /// `None` while open.
    closed: Option<Closed>,
}

/// What the gate says of an attempt now.
enum Decision {
    /// Admitted, at this epoch; whether as the probe.
    Go(u64, bool),
    /// Closed until then.
    Closed(Instant),
    /// Closed, and a probe runs.
    Probing,
    /// Open, and each slot taken.
    Full,
}

struct Inner {
    states: Mutex<HashMap<(String, u16), State>>,
    /// One more at each verdict and each slot freed: each waiter looks again.
    changes: watch::Sender<u64>,
}

/// The gates of a process, or of a test, by origin.
#[derive(Clone)]
pub struct Gates(Arc<Inner>);

impl Default for Gates {
    fn default() -> Self {
        Gates(Arc::new(Inner { states: Mutex::default(), changes: watch::channel(0).0 }))
    }
}

/// The process's gates, which each run of [`crate::open::open`] shares. A
/// test on a paused clock takes [`Gates`] of its own: the times that a gate
/// keeps are its runtime's clock's.
pub fn process() -> &'static Gates {
    static GATES: OnceLock<Gates> = OnceLock::new();
    GATES.get_or_init(Gates::default)
}

/// The origin of `relay`: its host, of any case, and its port.
fn key(relay: &Relay) -> (String, u16) {
    (relay.host.to_ascii_lowercase(), relay.port)
}

impl Gates {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, u16), State>> {
        self.0.states.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn decide(&self, key: &(String, u16), now: Instant) -> Decision {
        let mut states = self.lock();
        let state = states.entry(key.clone()).or_default();
        match &mut state.closed {
            None if state.running < MOST_AT_ONCE => {
                state.running += 1;
                Decision::Go(state.epoch, false)
            }
            None => Decision::Full,
            Some(closed) if now < closed.until => Decision::Closed(closed.until),
            Some(closed) if closed.probing => Decision::Probing,
            Some(closed) => {
                closed.probing = true;
                state.running += 1;
                Decision::Go(state.epoch, true)
            }
        }
    }

    /// An attempt at `relay`: admitted at once while the gate is open and
    /// has a slot; else, with `successor`, refused at once with the wait
    /// left, so that the session goes on to its next host; else after the
    /// wait, as the probe, or when the gate opened.
    pub async fn admit(&self, relay: &Relay, successor: bool) -> Result<Lease, OpenError> {
        let key = key(relay);
        // Seen before the look, so that no change after it is missed.
        let mut changes = self.0.changes.subscribe();
        loop {
            let now = Instant::now();
            let until = match self.decide(&key, now) {
                Decision::Go(epoch, probe) => {
                    return Ok(Lease { gates: self.clone(), key, epoch, probe, settled: false });
                }
                Decision::Closed(until) if successor => return Err(OpenError::Held { left: Some(until - now) }),
                Decision::Probing if successor => return Err(OpenError::Held { left: None }),
                Decision::Closed(until) => Some(until),
                Decision::Probing | Decision::Full => None,
            };
            match until {
                Some(until) => tokio::select! {
                    _ = changes.changed() => {}
                    () = tokio::time::sleep_until(until) => {}
                },
                None => {
                    let _ = changes.changed().await;
                }
            }
        }
    }

    /// The end of an admitted attempt: its slot freed, and its verdict, if
    /// it has one, given to the gate.
    fn settle(&self, key: &(String, u16), epoch: u64, probe: bool, verdict: Option<Verdict>) {
        {
            let now = Instant::now();
            let mut states = self.lock();
            let state = states.entry(key.clone()).or_default();
            state.running = state.running.saturating_sub(1);
            if let (true, Some(closed)) = (probe, &mut state.closed) {
                closed.probing = false;
            }
            let current = epoch == state.epoch;
            match verdict {
                // An answer of this epoch opens the gate; one of an older
                // epoch would shorten a wait, and never does.
                Some(Verdict::Alive) if current && state.closed.is_some() => {
                    state.closed = None;
                    state.epoch += 1;
                }
                Some(Verdict::Failed(asked)) => failed(state, current, asked, now),
                _ => {}
            }
        }
        self.0.changes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// What the gate of `relay` holds now: the ladder's wait, the time left,
    /// whether a probe runs, and the epoch; `None` while it is open.
    pub fn held(&self, relay: &Relay) -> Option<(Duration, Duration, bool, u64)> {
        let now = Instant::now();
        let states = self.lock();
        let state = states.get(&key(relay))?;
        let closed = state.closed?;
        Some((closed.wait, closed.until.saturating_duration_since(now), closed.probing, state.epoch))
    }

    /// The line of a run whose every host the gates hold now: it waits at
    /// its last host, which the line names.
    pub fn all_held(&self, hosts: &[Relay]) -> Option<String> {
        let mut last = None;
        for relay in hosts {
            let (_, left, probing, _) = self.held(relay)?;
            // A probe may go now: nothing holds this host.
            if left.is_zero() && !probing {
                return None;
            }
            last = Some((relay, (!left.is_zero()).then_some(left)));
        }
        let (relay, left) = last?;
        Some(format!("{}: {}", relay.host, words(left)))
    }
}

/// A failure of the host: of this epoch, it closes an open gate or moves
/// the ladder once; of an older one, it lengthens the wait from now.
fn failed(state: &mut State, current: bool, asked: Option<Duration>, now: Instant) {
    let asked = asked.map_or(Duration::ZERO, |a| a.min(RETRY_AFTER_MOST));
    match &mut state.closed {
        None if current => {
            let until = now + FIRST_WAIT.max(asked);
            state.closed = Some(Closed { wait: FIRST_WAIT, until, probing: false });
            state.epoch += 1;
        }
        Some(closed) if current => {
            closed.wait = (closed.wait * 2).min(LONGEST_WAIT);
            closed.until = closed.until.max(now + closed.wait.max(asked));
            state.epoch += 1;
        }
        Some(closed) => closed.until = closed.until.max(now + closed.wait.max(asked)),
        // Open again since this attempt began: the newer answer holds.
        None => {}
    }
}

/// An admitted attempt: its slot, until its verdict or its drop. A lease
/// dropped with no verdict, as by a race that kept another host, frees its
/// slot and says nothing of the host.
pub struct Lease {
    gates: Gates,
    key: (String, u16),
    epoch: u64,
    probe: bool,
    settled: bool,
}

impl Lease {
    /// The attempt's verdict.
    pub fn settle(mut self, verdict: Verdict) {
        self.settled = true;
        self.gates.settle(&self.key, self.epoch, self.probe, Some(verdict));
    }

    /// Whether it was admitted as the probe of a closed gate.
    pub fn probe(&self) -> bool {
        self.probe
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.settled {
            self.gates.settle(&self.key, self.epoch, self.probe, None);
        }
    }
}

/// One attempt at `relay` under `gates`: admitted first, its wait outside
/// `deadline`; then `attempt` within `deadline`, and its verdict given.
pub async fn guarded<T, F>(
    gates: &Gates,
    relay: &Relay,
    successor: bool,
    deadline: Duration,
    attempt: F,
) -> Result<T, OpenError>
where
    F: Future<Output = Result<T, OpenError>>,
{
    let lease = gates.admit(relay, successor).await?;
    let result = tokio::time::timeout(deadline, attempt).await.unwrap_or(Err(OpenError::Deadline));
    lease.settle(verdict(&result));
    result
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;
