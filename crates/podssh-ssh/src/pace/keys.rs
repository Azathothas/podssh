//! The user's keys (T-661): when the last one was typed, and whether one
//! waits for its echo. One for the process: a key typed in any session of
//! it holds each connection's bulk, as one user waits for it.
//!
//! A key is a byte that a session with a pty sends from its input; its echo
//! is the next output of such a session. A server that echoes nothing (a
//! password's prompt) holds podssh's senders for [`HOLD_MAX`] at most.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

/// A key typed within this long: the windows of bulk channels are held.
pub const TYPING: Duration = Duration::from_secs(2);

/// The longest that podssh's senders wait for a key's echo.
pub const HOLD_MAX: Duration = Duration::from_secs(1);

/// How often a held sender looks again: an echo ends the hold at once.
const STEP: Duration = Duration::from_millis(10);

/// When the last key was typed, and since when one waits for its echo.
#[derive(Debug, Default)]
pub struct Keys {
    /// Times as milliseconds since `epoch`, plus one; 0 for none.
    typed: AtomicU64,
    waiting: AtomicU64,
    epoch: OnceLock<Instant>,
}

static KEYS: Keys = Keys::new();

/// The process's keys.
pub fn keys() -> &'static Keys {
    &KEYS
}

/// A key went out now, in the process's keys.
pub fn key() {
    KEYS.key(Instant::now());
}

/// A session with a pty wrote: a key that waited has its echo.
pub fn echo() {
    KEYS.echo();
}

impl Keys {
    pub const fn new() -> Self {
        Keys { typed: AtomicU64::new(0), waiting: AtomicU64::new(0), epoch: OnceLock::new() }
    }

    fn stamp(&self, now: Instant) -> u64 {
        let epoch = *self.epoch.get_or_init(|| now);
        u64::try_from(now.saturating_duration_since(epoch).as_millis()).unwrap_or(u64::MAX - 1) + 1
    }

    /// How long ago `stamp` was, or `None` for no stamp or one after now.
    fn age(&self, stamp: u64, now: Instant) -> Option<Duration> {
        let now = self.stamp(now);
        (stamp != 0 && stamp <= now).then(|| Duration::from_millis(now - stamp))
    }

    /// A key went out at `now`. It waits for its echo unless one that waits
    /// is younger than [`HOLD_MAX`]: the hold runs from the first key.
    pub fn key(&self, now: Instant) {
        let stamp = self.stamp(now);
        self.typed.store(stamp, Relaxed);
        let waiting = self.waiting.load(Relaxed);
        if self.age(waiting, now).is_none_or(|age| age >= HOLD_MAX) {
            self.waiting.store(stamp, Relaxed);
        }
    }

    /// Output came: no key waits.
    pub fn echo(&self) {
        self.waiting.store(0, Relaxed);
    }

    /// A key was typed within [`TYPING`] of `now`.
    pub fn typing(&self, now: Instant) -> bool {
        self.age(self.typed.load(Relaxed), now).is_some_and(|age| age < TYPING)
    }

    /// How much longer a sender holds its writes at `now`: `None` when no
    /// key waits for its echo, or it waited [`HOLD_MAX`].
    pub fn held(&self, now: Instant) -> Option<Duration> {
        let age = self.age(self.waiting.load(Relaxed), now)?;
        HOLD_MAX.checked_sub(age).filter(|left| !left.is_zero())
    }
}

/// A sender's turn: ready once no key of the process waits for its echo.
/// Kept in a stream's state, as a read may be polled again.
#[derive(Default)]
pub struct Turn {
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl std::fmt::Debug for Turn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Turn").field("held", &self.sleep.is_some()).finish()
    }
}

impl Turn {
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_with(keys(), cx)
    }

    pub(crate) fn poll_with(&mut self, keys: &Keys, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if let Some(sleep) = self.sleep.as_mut() {
                ready!(sleep.as_mut().poll(cx));
                self.sleep = None;
            }
            match keys.held(Instant::now()) {
                None => return Poll::Ready(()),
                Some(left) => self.sleep = Some(Box::pin(tokio::time::sleep(left.min(STEP)))),
            }
        }
    }
}

/// Wait for a sender's turn: at once when no key waits.
pub async fn turn() {
    if KEYS.held(Instant::now()).is_none() {
        return;
    }
    let mut turn = Turn::default();
    std::future::poll_fn(|cx| turn.poll(cx)).await;
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
