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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::Notify;
// tokio's clock, which a test can pause.
use tokio::time::Instant;

/// How long a question waits for its answer before the far end counts as
/// silent: a few round trips and the 200 ms of an `ACK`. Through the
/// stand-in proxy's `--pause` of 20 s, the notice came 5 to 6 s after the
/// key that waited (T-302).
pub const WAIT: Duration = Duration::from_secs(5);

/// The last word of the far end, and the oldest question that waits.
#[derive(Debug)]
pub struct Hearing {
    heard: Mutex<Instant>,
    asked: Mutex<Option<Instant>>,
    /// How many times bytes came: a mark that two reads at the same instant
    /// of the clock still tell apart.
    words: AtomicU64,
    /// Woken by each read, for a wait for the far end's next bytes.
    spoke: Notify,
}

impl Default for Hearing {
    fn default() -> Self {
        Hearing {
            heard: Mutex::new(Instant::now()),
            asked: Mutex::new(None),
            words: AtomicU64::new(0),
            spoke: Notify::new(),
        }
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
        self.words.fetch_add(1, Ordering::SeqCst);
        self.spoke.notify_waiters();
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

    /// The mark of the far end's bytes so far, for [`Hearing::spoke_after`].
    pub fn words(&self) -> u64 {
        self.words.load(Ordering::SeqCst)
    }

    /// Until bytes came from the far end after the mark `words`, at once
    /// when they came already. The read itself wakes it, so that the old
    /// link's first bytes close a spare link before the spare can greet
    /// (T-305); a look each few hundred ms would let the spare win.
    pub async fn spoke_after(&self, words: u64) {
        loop {
            // Registered before the look: bytes between the two still wake it.
            let spoke = self.spoke.notified();
            tokio::pin!(spoke);
            spoke.as_mut().enable();
            if self.words() != words {
                return;
            }
            spoke.await;
        }
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

    #[tokio::test(start_paused = true)]
    async fn a_wait_for_the_next_bytes_ends_when_they_come_at_the_same_instant() {
        let hearing = std::sync::Arc::new(Hearing::default());
        let mark = hearing.words();
        let waiting = tokio::spawn({
            let hearing = hearing.clone();
            async move { hearing.spoke_after(mark).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "nothing came yet");
        // The paused clock stands still: the bytes come at the mark's instant.
        hearing.heard();
        tokio::time::timeout(Duration::from_millis(1), waiting).await.expect("the bytes woke the wait").unwrap();
        // Bytes that came before the wait end it at once.
        tokio::time::timeout(Duration::from_millis(1), hearing.spoke_after(mark)).await.expect("at once");
    }
}
