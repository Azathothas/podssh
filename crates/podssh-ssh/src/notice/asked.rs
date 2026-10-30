//! The far end's silence as SSH itself tells it (T-332), for a road that
//! tells none (`--direct`): with a key, while no question waits, the
//! session sends a keepalive that asks for a reply (`keepalive@openssh.com`,
//! which a server answers, with a failure when it knows no such request),
//! and the reply, or any message of the session's channel, answers it. A
//! program that echoes nothing is then no silence.

use std::sync::Mutex;
use std::time::Duration;

// tokio's clock, which a test can pause.
use tokio::time::Instant;

/// How long a question waits for its answer before the far end counts as
/// silent: the wait of the layer's notice and of the relay's (T-302,
/// T-307), as the notice is one on each road.
pub const WAIT: Duration = Duration::from_secs(5);

/// The server's last word, and the question that waits.
#[derive(Debug)]
pub struct Asked {
    heard: Mutex<Instant>,
    asked: Mutex<Option<Instant>>,
}

impl Default for Asked {
    fn default() -> Self {
        Asked { heard: Mutex::new(Instant::now()), asked: Mutex::new(None) }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Asked {
    /// The server said something: it is there, and the question is answered.
    pub fn heard(&self) {
        *lock(&self.heard) = Instant::now();
        *lock(&self.asked) = None;
    }

    /// A key went out: whether it asks, as no question waited.
    pub fn ask(&self) -> bool {
        let mut asked = lock(&self.asked);
        if asked.is_some() {
            return false;
        }
        *asked = Some(Instant::now());
        true
    }

    /// A key went out: its question is marked when none waits, and the
    /// answer says whether a keepalive goes with it. A keepalive that still
    /// waits for its reply asks the new question too, so a reply that never
    /// comes counts, though the far end's bytes answered the last question.
    pub fn key(&self, keepalive_waits: bool) -> bool {
        self.ask() && !keepalive_waits
    }

    /// How long the server has said nothing, at `now`, when a question has
    /// waited `wait` or more for its answer; `None` while it answers.
    pub fn silent(&self, now: Instant, wait: Duration) -> Option<Duration> {
        let asked = (*lock(&self.asked))?;
        if now.saturating_duration_since(asked) < wait {
            return None;
        }
        Some(now.saturating_duration_since(*lock(&self.heard)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each time is given, so the test needs no clock of its own.
    #[test]
    fn a_question_waits_its_wait_then_the_silence_counts_from_the_last_word() {
        let asked = Asked::default();
        let start = Instant::now();
        assert_eq!(asked.silent(start + Duration::from_secs(60), WAIT), None, "no question yet");
        assert!(asked.ask(), "the first key asks");
        assert!(!asked.ask(), "a second key while one waits asks nothing");
        let later = Instant::now();
        assert_eq!(asked.silent(later + Duration::from_secs(4), WAIT), None, "not yet: 4 s of 5");
        let silent = asked.silent(later + Duration::from_secs(5), WAIT).expect("silent once it waited");
        assert!(silent >= Duration::from_secs(5), "counted from the last word: {silent:?}");
        asked.heard();
        assert_eq!(asked.silent(Instant::now() + Duration::from_secs(60), WAIT), None, "answered");
        assert!(asked.ask(), "the next key asks again");
    }

    /// The far end's bytes answer a question before the keepalive's reply,
    /// and then the link dies: the next key's question must still count.
    #[test]
    fn a_keepalive_that_waits_asks_the_next_question_too() {
        let asked = Asked::default();
        assert!(asked.key(false), "the first key asks, with a keepalive");
        asked.heard();
        assert!(!asked.key(true), "no second keepalive while the first waits");
        let later = Instant::now();
        assert!(asked.silent(later + WAIT, WAIT).is_some(), "the question counts though no keepalive went with it");
        asked.heard();
        assert!(asked.key(false), "once the reply came, the next key sends a keepalive again");
    }
}
