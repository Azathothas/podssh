//! The budget of a far end's replay buffers, and its words (T-586).
//!
//! A far end charges each session that it keeps against one budget: a whole
//! buffer for a session whose buffer can still fill, with a link or waiting
//! for its client; for a session whose target ended and whose `CLOSE` went
//! out, only the bytes that it still keeps, as its buffer can only empty;
//! nothing for a session whose client was not let in yet (T-300), or that
//! ended and keeps its id alone. A run of short logins whose client went away
//! before it answered the `CLOSE` then holds nothing, where it held a whole
//! buffer each for the deadline and filled the budget (GitHub #112).
//!
//! A new session that the budget has no room for is refused with what holds
//! the budget and when room comes back. The node says the same on stderr,
//! once a minute at most, and once when the budget passes three quarters:
//! the refusal reaches only the client, and the node's own log must say why
//! its sessions are refused.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::time::Instant;

/// How often a refusal is said on the far end's lines, at most: a client
/// that tries again each second must not fill the node's log.
pub const SAY_EVERY: Duration = Duration::from_secs(60);

/// What holds a far end's budget at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Census {
    /// The bytes charged.
    pub held: usize,
    /// The sessions charged that a link carries.
    pub live: usize,
    /// The sessions charged that wait for their client.
    pub waiting: usize,
    /// How long until the first of those is forgotten.
    pub first_free: Option<Duration>,
}

impl Census {
    /// The sessions charged.
    pub fn sessions(&self) -> usize {
        self.live + self.waiting
    }

    /// This census with one more session that a link carries, charged
    /// `each`: the one that comes in.
    pub fn with_one_more(self, each: usize) -> Census {
        Census { held: self.held.saturating_add(each), live: self.live + 1, ..self }
    }
}

/// When a far end last said its budget's lines.
#[derive(Debug, Default)]
pub struct Told {
    refused: Option<Instant>,
    high: bool,
}

impl Told {
    /// Whether a refusal at `now` is said: the first, then one each
    /// [`SAY_EVERY`] at most.
    pub fn refusal(&mut self, now: Instant) -> bool {
        if self.refused.is_some_and(|at| now.saturating_duration_since(at) < SAY_EVERY) {
            return false;
        }
        self.refused = Some(now);
        true
    }

    /// Whether `held` bytes of `budget` are said: once when they pass three
    /// quarters, and again only after they fell to half, so that a budget
    /// that hovers at the mark says it once.
    pub fn level(&mut self, held: usize, budget: usize) -> bool {
        let (high, half) = (budget / 4 * 3, budget / 2);
        if held > high {
            let first = !self.high;
            self.high = true;
            return first;
        }
        if held <= half {
            self.high = false;
        }
        false
    }
}

type Say = Box<dyn Fn(&str) + Send + Sync>;

/// Where the budget's lines go. A process runs one node, so one place: set
/// by the node's command, and with none, a far end says nothing (a test, a
/// far end of `podssh serve`).
static SAY: OnceLock<Say> = OnceLock::new();

/// Send the budget's lines to `say` from now on: a node's stderr, which a
/// detached node's log keeps. The first call holds.
pub fn tell(say: impl Fn(&str) + Send + Sync + 'static) {
    let _ = SAY.set(Box::new(say));
}

/// Say `line` where [`tell`] sends the budget's lines, if anywhere.
pub fn say(line: &str) {
    if let Some(say) = SAY.get() {
        say(line);
    }
}

/// The refusal of a new session that `budget` bytes have no room for, with
/// what holds them and when room comes back.
pub fn refusal(census: &Census, budget: usize) -> String {
    let n = census.sessions();
    format!(
        "this node keeps {n} resumable session{} ({} MiB of replay buffers): {}; --resume-deadline and \
         PODSSH_REPLAY_BUFFER of the node change its budget",
        if n == 1 { "" } else { "s" },
        budget >> 20,
        holders(census)
    )
}

/// The line of a budget that passed three quarters.
pub fn filling(census: &Census, budget: usize) -> String {
    format!(
        "the resumable sessions hold {} MiB of this node's {} MiB of replay buffers: {}; a new session past the \
         budget is refused (--resume-deadline and PODSSH_REPLAY_BUFFER of the node change it)",
        census.held.div_ceil(1 << 20),
        budget >> 20,
        holders(census)
    )
}

/// The sessions that hold the budget, in words; the relay role's refusal
/// names them too (T-173).
pub(crate) fn holders(census: &Census) -> String {
    let waiting = match (census.waiting, census.first_free) {
        (0, _) => "none waiting for its client".to_string(),
        (1, Some(left)) => format!("1 waiting for its client, for {} more", left_words(left)),
        (1, None) => "1 waiting for its client".to_string(),
        (n, Some(left)) => format!("{n} waiting for their client, the first of them for {} more", left_words(left)),
        (n, None) => format!("{n} waiting for their client"),
    };
    format!("{} with a link, {waiting}", census.live)
}

/// A time left, to the second above it: `40 s`, `4 min 10 s`, `3 h 5 min`.
pub fn left_words(left: Duration) -> String {
    let s = left.as_secs() + u64::from(left.subsec_nanos() > 0);
    match s {
        0..=59 => format!("{s} s"),
        60..=3599 if s.is_multiple_of(60) => format!("{} min", s / 60),
        60..=3599 => format!("{} min {} s", s / 60, s % 60),
        _ => super::deadline::span(Duration::from_secs(s)),
    }
}
