//! A warning before the relay's idle cut (T-463, GitHub #98): the relay ends
//! a session after its idle limit (180 s) with no payload either way, and the
//! user heard of it only once the session was gone. Once nothing has crossed
//! for the cut less the lead (30 s), one warning, and none again until a
//! payload crossed: a key, or a keepalive, keeps the session.
//!
//! Where a session shows T-302's notice in the window's title, the warning
//! goes there ([`super::Silence::set_idle`]) and comes down with the next
//! payload; else it is one line on stderr, also into a pipe, as an agent that
//! reads stderr loses the session too. The warning keeps nothing alive: a
//! user who turned keepalives off gets none from it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

// tokio's clock, which a test can pause.
use tokio::time::Instant;

/// The lead when none is asked: the warning comes 30 s before the cut, or a
/// sixth of a shorter cut before it, as a relay's limits may give one.
pub const LEAD: Duration = Duration::from_secs(30);

/// How often a watch that warned looks for the payload that ends the
/// warning: the title comes down within it.
const POLL: Duration = Duration::from_secs(1);

/// When payload last crossed a relay session, either way: the relay's idle
/// cut counts from it. Clones share it.
#[derive(Clone, Debug)]
pub struct Crossed {
    base: Instant,
    /// Milliseconds after `base`.
    after: Arc<AtomicU64>,
}

impl Default for Crossed {
    fn default() -> Self {
        Crossed { base: Instant::now(), after: Arc::default() }
    }
}

impl Crossed {
    /// Payload crossed now.
    pub fn mark(&self) {
        let ms = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.after.fetch_max(ms, Ordering::Relaxed);
    }

    /// When payload last crossed; the start, before any did.
    pub fn last(&self) -> Instant {
        self.base + Duration::from_millis(self.after.load(Ordering::Relaxed))
    }
}

/// The lead for a cut of `cut`: `asked` (`--idle-warn`), else [`LEAD`] or a
/// sixth of a shorter cut; `None` for no warning (`--idle-warn 0`). Never at
/// or past the cut, where each payload would be warned of at once.
pub fn lead(cut: Duration, asked: Option<Duration>) -> Option<Duration> {
    let lead = asked.unwrap_or_else(|| LEAD.min(cut / 6));
    let room = cut.checked_sub(Duration::from_secs(1)).filter(|d| !d.is_zero())?;
    (!lead.is_zero()).then(|| lead.min(room))
}

/// What a watch does at one look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Nothing until then.
    Wait(Instant),
    /// The warning: the cut comes in `ends_in`, after `quiet` with nothing.
    Warn { ends_in: Duration, quiet: Duration },
    /// A payload crossed after the warning: it is past.
    Crossed,
}

/// The watch of one session's silence against the relay's cut.
#[derive(Debug, Clone)]
pub struct Idle {
    cut: Duration,
    lead: Duration,
    /// The last payload that the warning was about, once it was given.
    warned: Option<Instant>,
}

impl Idle {
    pub fn new(cut: Duration, lead: Duration) -> Idle {
        Idle { cut, lead, warned: None }
    }

    pub fn cut(&self) -> Duration {
        self.cut
    }

    /// The step at `now`, payload having last crossed at `last`.
    pub fn at(&mut self, last: Instant, now: Instant) -> Step {
        if let Some(warned) = self.warned {
            if last > warned {
                self.warned = None;
                return Step::Crossed;
            }
            return Step::Wait(now + POLL);
        }
        let due = last + self.cut.saturating_sub(self.lead);
        if now < due {
            return Step::Wait(due);
        }
        self.warned = Some(last);
        let quiet = now.saturating_duration_since(last);
        Step::Warn { ends_in: self.cut.saturating_sub(quiet), quiet }
    }
}

/// The line on stderr.
pub fn line(ends_in: Duration, quiet: Duration, cut: Duration) -> String {
    format!(
        "the relay ends this session in {} s, as nothing crossed it for {} s: a key, or -o ServerAliveInterval below \
         {}, keeps it",
        ends_in.as_secs(),
        quiet.as_secs(),
        cut.as_secs()
    )
}

/// The words in the window's title.
pub fn title(ends_in: Duration) -> String {
    format!("podssh: the relay ends this session in {} s, a key keeps it", ends_in.as_secs())
}

/// Watch a session until it ends: `last` gives when payload last crossed,
/// and `None` once the session ended; `act` takes each warning, and each
/// payload after one.
pub async fn watch(last: impl Fn() -> Option<Instant>, mut idle: Idle, mut act: impl FnMut(&Step)) {
    loop {
        let Some(at) = last() else { return };
        match idle.at(at, Instant::now()) {
            Step::Wait(until) => tokio::time::sleep_until(until).await,
            step => act(&step),
        }
    }
}

#[cfg(test)]
#[path = "idle_tests.rs"]
mod tests;
