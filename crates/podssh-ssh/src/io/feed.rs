//! Input that the caller gives a session in place of stdin, and the
//! `signal INT` requests that it asks for (`podssh each --interactive`,
//! T-185). The caller puts bytes in, and can take back each byte that the
//! session has not read yet: the broadcast's emergency stop clears them at
//! once. The session takes one piece at a time, when it can send it, so
//! that what waits for a slow host waits here, where the caller sees it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;

/// One feed, shared by the caller and the session: a clone is the same feed.
#[derive(Clone, Default)]
pub struct Feed(Arc<Shared>);

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    /// Bytes or the end, for the session's input.
    bytes: Notify,
    /// A `signal INT` for the session's channel.
    asked: Notify,
}

#[derive(Default)]
struct State {
    pieces: VecDeque<Vec<u8>>,
    /// The bytes of `pieces`.
    held: usize,
    ended: bool,
    /// The `signal INT` requests not sent yet.
    interrupts: usize,
    /// Whether the session has asked for its input: its shell runs.
    reading: bool,
}

impl Feed {
    pub fn new() -> Self {
        Feed::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Put `bytes` after what waits; the bytes that wait then. Nothing goes
    /// in after [`Feed::end`].
    pub fn put(&self, bytes: &[u8]) -> usize {
        let mut state = self.state();
        if !state.ended && !bytes.is_empty() {
            state.pieces.push_back(bytes.to_vec());
            state.held += bytes.len();
            self.0.bytes.notify_one();
        }
        state.held
    }

    /// The bytes that wait for the session.
    pub fn held(&self) -> usize {
        self.state().held
    }

    /// Take back each byte that waits, in its order, and drop each
    /// `signal INT` not sent yet.
    pub fn take(&self) -> Vec<u8> {
        let pieces = {
            let mut state = self.state();
            state.held = 0;
            state.interrupts = 0;
            std::mem::take(&mut state.pieces)
        };
        pieces.into_iter().flatten().collect()
    }

    /// The end of the input: the session reads what waits, then its end.
    pub fn end(&self) {
        self.state().ended = true;
        self.0.bytes.notify_one();
    }

    /// Ask the session to send `signal INT` on its channel; a session that
    /// has not started sends it as it starts.
    pub fn interrupt(&self) {
        self.state().interrupts += 1;
        self.0.asked.notify_one();
    }

    /// Whether the session has asked for its input: its shell or its
    /// command runs.
    pub fn reading(&self) -> bool {
        self.state().reading
    }

    /// The next piece, or `None` at the end. A wake with nothing to take
    /// looks again: `notify_one` keeps one wake for a reader that comes
    /// later, and passes on one that a dropped wait had.
    pub(crate) async fn next(&self) -> Option<Vec<u8>> {
        loop {
            {
                let mut state = self.state();
                state.reading = true;
                if let Some(piece) = state.pieces.pop_front() {
                    state.held -= piece.len();
                    return Some(piece);
                }
                if state.ended {
                    return None;
                }
            }
            self.0.bytes.notified().await;
        }
    }

    /// The next `signal INT` that the caller asked for.
    pub(crate) async fn interrupted(&self) {
        loop {
            {
                let mut state = self.state();
                if state.interrupts > 0 {
                    state.interrupts -= 1;
                    return;
                }
            }
            self.0.asked.notified().await;
        }
    }
}

impl std::fmt::Debug for Feed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Feed(..)")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::io::Input;

    /// Whether `future` ends within 50 ms of the test's time.
    async fn soon<T>(future: impl std::future::Future<Output = T>) -> Option<T> {
        tokio::time::timeout(Duration::from_millis(50), future).await.ok()
    }

    #[tokio::test]
    async fn pieces_come_in_order_then_the_end() {
        let feed = Feed::new();
        assert_eq!(feed.put(b"ls\n"), 3);
        assert_eq!(feed.put(b"pwd\n"), 7);
        assert_eq!(feed.put(b""), 7, "nothing is no piece");
        assert!(!feed.reading());
        assert_eq!(feed.next().await, Some(b"ls\n".to_vec()));
        assert!(feed.reading(), "a read says that the session runs");
        assert_eq!(feed.held(), 4);
        feed.end();
        assert_eq!(feed.put(b"late\n"), 4, "nothing goes in after the end");
        assert_eq!(feed.next().await, Some(b"pwd\n".to_vec()), "what waited comes before the end");
        assert_eq!(feed.next().await, None);
        assert_eq!(feed.next().await, None);
    }

    #[tokio::test]
    async fn a_reader_waits_for_a_piece_that_comes_later() {
        let feed = Feed::new();
        assert_eq!(soon(feed.next()).await, None, "nothing waits");
        let (got, ()) = tokio::join!(feed.next(), async {
            tokio::task::yield_now().await;
            feed.put(b"late\n");
        });
        assert_eq!(got, Some(b"late\n".to_vec()));
    }

    #[tokio::test]
    async fn take_gives_back_what_waits_and_the_signals_not_sent() {
        let feed = Feed::new();
        feed.put(b"rm -rf build\n");
        feed.put(b"make\n");
        feed.interrupt();
        assert_eq!(feed.take(), b"rm -rf build\nmake\n");
        assert_eq!((feed.held(), feed.take()), (0, Vec::new()));
        assert_eq!(soon(feed.interrupted()).await, None, "the signal was taken back too");
        assert_eq!(soon(feed.next()).await, None, "nothing waits for the session");
        feed.put(b"echo after\n");
        assert_eq!(feed.next().await, Some(b"echo after\n".to_vec()), "a feed goes on after a take");
    }

    #[tokio::test]
    async fn each_signal_asked_for_comes_once() {
        let feed = Feed::new();
        feed.interrupt();
        feed.interrupt();
        assert_eq!(soon(feed.interrupted()).await, Some(()));
        assert_eq!(soon(feed.interrupted()).await, Some(()));
        assert_eq!(soon(feed.interrupted()).await, None);
    }

    /// A session's input that is fed reads the feed and its end, and stdin
    /// never: the test's own stdin would hold nothing here.
    #[tokio::test]
    async fn an_input_that_is_fed_reads_the_feed_to_its_end() {
        let feed = Feed::new();
        let mut input = Input::fed(feed.clone());
        assert!(input.open());
        assert!(input.feed().is_some());
        feed.put(b"uptime\n");
        feed.end();
        assert_eq!(crate::io::input::next(&mut input, true).await, Some(b"uptime\n".to_vec()));
        assert_eq!(crate::io::input::next(&mut input, true).await, None);
        assert!(!input.open(), "an input that ended is closed");
        assert!(Input::new(false).feed().is_none());
    }
}
