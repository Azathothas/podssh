//! **The pace of a transfer's lines** (T-275), by a clock that the caller
//! gives: this crate reads no clock.
//!
//! A sender that writes each chunk as soon as the last one is acknowledged
//! writes dozens of lines a second on a short path. ngircd 27 and ergo
//! 2.18.0 slow such a client down (fake lag), and so does InspIRCd 4.11.0 by
//! default; InspIRCd with `fakelag="no"` closes it instead, within a second
//! at 10 commands a second (measured 2026-10-10 in the build image). So each
//! line of a transfer, a chunk or an acknowledgement, waits its turn: a
//! burst, then a steady rate.

use std::time::{Duration, Instant};

/// Lines a second by default: half the rate at which InspIRCd closed a
/// sender, measured.
pub const DEFAULT_LINES_PER_SECOND: u32 = 5;

/// Lines that may go at once by default, before the rate holds.
pub const DEFAULT_BURST: u32 = 5;

/// A burst, then a rate: the time at which the next line may go is the
/// last line's turn plus one line's time, less the burst's allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pace {
    per_line: Duration,
    burst: u32,
    /// The turn after the last line sent; `None` before the first.
    next_turn: Option<Instant>,
}

impl Default for Pace {
    fn default() -> Self {
        Pace::new(DEFAULT_LINES_PER_SECOND, DEFAULT_BURST)
    }
}

impl Pace {
    /// `lines_per_second` and `burst`, each at least 1.
    pub fn new(lines_per_second: u32, burst: u32) -> Pace {
        Pace { per_line: Duration::from_secs(1) / lines_per_second.max(1), burst: burst.max(1), next_turn: None }
    }

    /// How long the caller waits, at `now`, before the next line may go.
    pub fn wait(&self, now: Instant) -> Duration {
        let Some(turn) = self.next_turn else { return Duration::ZERO };
        let allowance = self.per_line * (self.burst - 1);
        turn.checked_sub(allowance).map_or(Duration::ZERO, |at| at.saturating_duration_since(now))
    }

    /// A line went at `now`.
    pub fn sent(&mut self, now: Instant) {
        let from = self.next_turn.map_or(now, |turn| turn.max(now));
        self.next_turn = Some(from + self.per_line);
    }
}
