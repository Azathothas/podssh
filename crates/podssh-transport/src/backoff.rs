//! Retry with backoff: **1 s → ×2 → cap 30 s, no jitter.** E02's Decision.
//!
//! ⛔ **The sibling's documentation claims jitter and its code has none**, and
//! podssh follows the code — `relay-transport.md:75-80` records the decision and
//! says so in those words. A verifier corrected the cap from 30 to **32** for the
//! *code* path; ⛔ **the documented intent is 30 s and podssh implements the
//! intent**, because a client has one thing to retry and a documented cap is the
//! one a reader can check.
//!
//! ⛔ **Pure, and that is the whole point.** A backoff whose arithmetic lives
//! behind a `tokio::time::sleep` can only be tested by waiting, so a test suite
//! that skips four 30-second sleeps is a suite that never ran. Every delay here
//! is a number this module returns.

/// ⛔ **1 second, doubling, capped at 30 s.** `relay-transport.md:75-80`.
pub const BASE_DELAY_MS: u64 = 1_000;
pub const MAX_DELAY_MS: u64 = 30_000;

/// ⛔ **The backoff schedule.** ⛔ **No jitter field, because there is no jitter**,
/// and adding one would be a change the Decision forbids without naming it here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    next_ms: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    /// ⛔ **The first delay is the base**, not zero: a reconnect that fires
    /// immediately after a `1011 socket error` meets the same socket.
    pub const fn new() -> Self {
        Self { next_ms: BASE_DELAY_MS }
    }

    /// ⛔ **The delay for the attempt *about to be made***, without consuming it.
    pub const fn peek_ms(&self) -> u64 {
        self.next_ms
    }

    /// ⛔ **Take the next delay and advance.**
    ///
    /// ⛔ **The cap is applied after the multiply, and the multiply cannot
    /// overflow** because both operands are already bounded: doubling a value
    /// that is at most `MAX_DELAY_MS` cannot exceed `2 * 30_000`, which fits in a
    /// `u64` with six orders of magnitude to spare. A `saturating_mul` on a
    /// `u64` here would be a comment pretending to be a guard.
    pub fn next_ms(&mut self) -> u64 {
        let delay = self.next_ms;
        self.next_ms = (self.next_ms * 2).min(MAX_DELAY_MS);
        delay
    }

    /// ⛔ **Reset to the base delay.** Called after a successful connect, so a
    /// connection that flapped once does not inherit the tenth attempt's 30 s.
    pub fn reset(&mut self) {
        self.next_ms = BASE_DELAY_MS;
    }

    /// ⛔ **The whole schedule, for a test and for a diagnostic.** ⛔ Twelve
    /// attempts is where the sequence has provably settled on the cap, and a test
    /// that asserts the list is shorter than that has not checked the cap.
    pub fn schedule(attempts: usize) -> Vec<u64> {
        let mut backoff = Self::new();
        (0..attempts).map(|_| backoff.next_ms()).collect()
    }
}