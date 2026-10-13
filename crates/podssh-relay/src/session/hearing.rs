//! What the client has heard from the far end, across the links of a
//! session (T-302): when its last bytes came, and since when a question of
//! this side has waited for an answer. A notice in the terminal reads it.
//!
//! A question is what the far end answers at once: `DATA` that it
//! acknowledges within 200 ms (both named `replay.v1`), a `PING` that it
//! answers with a `PONG`, and a resume after a lost link. Any bytes from the
//! far end answer each question, as they show that it is there. So a program
//! that echoes nothing (a password's prompt) is no silence, and neither is an
//! idle session: each side's `PING` each 10 s is answered.

use std::sync::Mutex;
use std::time::Duration;

// tokio's clock, which a test can pause.
use tokio::time::Instant;

/// How long a question waits for its answer before the far end counts as
/// silent: a few round trips and the 200 ms of an `ACK`. UNVERIFIED: the
/// value waits for the measurement of T-302 with the stand-in proxy's
/// `--pause`.
pub const WAIT: Duration = Duration::from_secs(5);

/// The last word of the far end, and the oldest question that waits.
#[derive(Debug)]
pub struct Hearing {
    heard: Mutex<Instant>,
    asked: Mutex<Option<Instant>>,
}

impl Default for Hearing {
    fn default() -> Self {
        Hearing { heard: Mutex::new(Instant::now()), asked: Mutex::new(None) }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Hearing {
    /// Bytes came from the far end: it is there, and each question is
    /// answered.
    pub fn heard(&self) {
        *lock(&self.heard) = Instant::now();
        *lock(&self.asked) = None;
    }

    /// This side asked something that the far end answers at once; the
    /// first question since its last bytes starts the wait.
    pub fn asked(&self) {
        let mut asked = lock(&self.asked);
        if asked.is_none() {
            *asked = Some(Instant::now());
        }
    }

    /// How long the far end has said nothing, at `now`, when a question has
    /// waited `wait` or more for its answer; `None` while it answers.
    pub fn silent(&self, now: Instant, wait: Duration) -> Option<Duration> {
        let asked = (*lock(&self.asked))?;
        if now.saturating_duration_since(asked) < wait {
            return None;
        }
        Some(now.saturating_duration_since(*lock(&self.heard)))
    }

    /// How long the far end has said nothing at `now`, asked or not.
    pub fn quiet(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.heard_at())
    }

    /// When the far end's last bytes came.
    pub fn heard_at(&self) -> Instant {
        *lock(&self.heard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_question_that_waits_makes_the_far_end_silent_until_it_answers() {
        let hearing = Hearing::default();
        let wait = Duration::from_secs(5);
        assert_eq!(hearing.silent(Instant::now(), wait), None, "nothing asked: no silence");
        tokio::time::sleep(Duration::from_secs(3)).await;
        hearing.asked();
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(hearing.silent(Instant::now(), wait), None, "asked 4 s ago");
        // A second question does not start the wait again.
        hearing.asked();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(hearing.silent(Instant::now(), wait), Some(Duration::from_secs(8)), "silent since the start");
        hearing.heard();
        assert_eq!(hearing.silent(Instant::now(), wait), None, "the far end answered");
    }
}
