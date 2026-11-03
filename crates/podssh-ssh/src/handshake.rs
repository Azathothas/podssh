//! The record of one SSH handshake (T-588, GitHub #114): what came from the
//! far end and what went to it, as they pass between russh and the road,
//! and whether the host key's question waits for its answer. A handshake
//! that does not finish within ConnectTimeout names what it saw: no byte, a
//! line of another service, or SSH's version line and the last message of
//! the key exchange each way; on a node's road, what the layer and the
//! end-to-end channel carried. 10 s in, a handshake that has not finished
//! says where it is, once, so that a long ConnectTimeout is no long
//! silence.
//!
//! The question of a new host key runs inside the handshake. Its time does
//! not count against ConnectTimeout, which bounds the far end: the question
//! has its own bound, as each prompt of the login has, and a person who reads
//! a fingerprint must not lose the connection for it. On Windows it waited
//! on a console that nobody saw, with no bound, as long as ConnectTimeout:
//! the line of #114.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use crate::log::Log;

#[path = "handshake_flow.rs"]
mod flow;
#[path = "handshake_side.rs"]
mod side;

pub use flow::{Counted, Flow, Road};
use side::{message, Side};

/// When a handshake that has not finished says where it is: the node's own
/// bound on its TARGET's answer, so a sshd that a node reached has spoken.
pub const FIRST_WORD: Duration = Duration::from_secs(10);
/// How often the wait looks again while a question waits past the limit.
const QUESTION_POLL: Duration = Duration::from_millis(250);
/// The far end of a road that names none.
const SERVER: &str = "the server";

/// What one handshake saw, shared by its stream, its handler and its wait.
#[derive(Clone, Default)]
pub struct Record(Arc<Inner>);

#[derive(Default)]
struct Inner {
    seen: Mutex<Seen>,
    /// The handshake ended, or each way is encrypted: nothing more to read.
    done: AtomicBool,
}

#[derive(Default)]
struct Seen {
    came: Side,
    went: Side,
    /// Since when the host key's question waits for its answer.
    asking: Option<Instant>,
    /// How long the questions that were answered waited.
    asked: Duration,
}

impl Record {
    /// `inner`, the stream of the handshake, read into this record.
    pub(crate) fn watch<S>(&self, inner: S) -> Watched<S> {
        Watched { inner, record: self.clone() }
    }

    fn lock(&self) -> MutexGuard<'_, Seen> {
        self.0.seen.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn feed(&self, came: bool, data: &[u8]) {
        if data.is_empty() || self.0.done.load(Ordering::Relaxed) {
            return;
        }
        let mut seen = self.lock();
        if came {
            seen.came.feed(data);
        } else {
            seen.went.feed(data);
        }
        if seen.came.sealed() && seen.went.sealed() {
            self.0.done.store(true, Ordering::Relaxed);
        }
    }

    fn finished(&self) {
        self.0.done.store(true, Ordering::Relaxed);
    }

    /// The host key's question asks, or has its answer.
    fn question(&self, on: bool) {
        let mut seen = self.lock();
        if on {
            seen.asking.get_or_insert_with(Instant::now);
        } else if let Some(since) = seen.asking.take() {
            seen.asked += since.elapsed();
        }
    }

    fn asking(&self) -> bool {
        self.lock().asking.is_some()
    }

    /// How long the host key's questions waited, until `now`.
    fn asked_for(&self, now: Instant) -> Duration {
        let seen = self.lock();
        seen.asked + seen.asking.map_or(Duration::ZERO, |since| now.saturating_duration_since(since))
    }
}

impl Seen {
    /// What came, one form for each case; `far` names the far end.
    fn words(&self, far: &str) -> String {
        if self.asking.is_some() {
            return "the question of the host key waits for its answer on the terminal".to_string();
        }
        let came = &self.came;
        let Some(version) = &came.version else {
            return match (came.bytes, &came.other) {
                (0, _) => format!("no byte came from {far}"),
                (n, Some(line)) => {
                    format!("{n} bytes came from {far}, with no SSH version line: the first line was {line:?}")
                }
                (n, None) => format!("{n} bytes came from {far}, with no end of a line and no SSH version line"),
            };
        };
        match came.last {
            None => format!("{version} came, then nothing after this side's {}", self.went.step()),
            Some(last) => format!(
                "{version} came; the last messages were the server's {} and this side's {}",
                message(last),
                self.went.step()
            ),
        }
    }
}

thread_local! {
    /// The handshake whose host key this thread checks.
    static CHECKING: RefCell<Option<Record>> = const { RefCell::new(None) };
}

/// `check`, the check of a host key, with `record` as its handshake on this
/// thread: its question is marked there, by [`asking`].
pub(crate) fn checking<T>(record: &Record, check: impl FnOnce() -> T) -> T {
    CHECKING.with(|slot| *slot.borrow_mut() = Some(record.clone()));
    let out = check();
    CHECKING.with(|slot| *slot.borrow_mut() = None);
    out
}

/// `ask`, the host key's question, marked on this thread's handshake while
/// it waits for its answer.
pub(crate) fn asking<T>(ask: impl FnOnce() -> T) -> T {
    let _asked = CHECKING.with(|slot| slot.borrow().clone()).map(Asked::start);
    ask()
}

/// A question that asks until it is dropped.
struct Asked(Record);

impl Asked {
    fn start(record: Record) -> Asked {
        record.question(true);
        Asked(record)
    }
}

impl Drop for Asked {
    fn drop(&mut self) {
        self.0.question(false);
    }
}

/// What the wait of one handshake needs: the hop's name in the lines, its
/// ConnectTimeout, the road under it, and where the first word goes.
pub(crate) struct Wait<'a> {
    pub label: &'a str,
    pub limit: Duration,
    pub road: Option<&'a Road>,
    pub log: &'a Log,
}

impl Wait<'_> {
    /// `handshake` within the limit, with the time of the host key's question
    /// left out; else the line that says what came.
    pub(crate) async fn run<F: Future>(&self, record: &Record, handshake: F) -> Result<F::Output, String> {
        let start = Instant::now();
        let first = self.first_word(record, start);
        tokio::pin!(handshake, first);
        let mut spoke = false;
        loop {
            let now = Instant::now();
            let deadline = start + self.limit + record.asked_for(now);
            if deadline <= now && !record.asking() {
                return Err(self.timed_out(record));
            }
            let wake = if deadline > now { deadline } else { now + QUESTION_POLL };
            tokio::select! {
                out = &mut handshake => {
                    record.finished();
                    return Ok(out);
                }
                () = &mut first, if !spoke => spoke = true,
                () = tokio::time::sleep_until(wake) => {}
            }
        }
    }

    /// The line of a handshake that did not finish within the limit.
    pub(crate) fn timed_out(&self, record: &Record) -> String {
        format!(
            "{}: the SSH handshake did not finish within {} s: {}",
            self.label,
            self.limit.as_secs(),
            self.seen(record)
        )
    }

    /// One line, [`FIRST_WORD`] after the start, or on a node's road after
    /// its layer opened, when the handshake has not finished by then; none
    /// when the limit came first, as the wait then ended with this future. A
    /// shorter limit that a question outlasts still gets the line.
    async fn first_word(&self, record: &Record, start: Instant) {
        tokio::time::sleep_until(start + FIRST_WORD).await;
        if let Some(opened) = self.road.and_then(|road| road.flow.opened()) {
            tokio::time::sleep_until(opened + FIRST_WORD).await;
        }
        // The limit at the same time: its own line says it.
        let now = Instant::now();
        if now >= start + self.limit + record.asked_for(now) && !record.asking() {
            return;
        }
        if let Some(line) = self.early(record, crate::terminal::prompt_limit().is_some()) {
            self.log.info(&line);
        }
    }

    /// The first word: where the handshake is, or that its question waits
    /// with nobody to see it; none while a person sees the question, whose
    /// terminal a line would write into.
    pub(crate) fn early(&self, record: &Record, unwatched: bool) -> Option<String> {
        if record.asking() {
            return unwatched.then(|| {
                format!(
                    "{}: the SSH handshake waits for the answer to the question of the host key on the terminal, \
                     and none of stdin, stdout and stderr is a terminal: with no answer within {} s, the key is \
                     refused; -o StrictHostKeyChecking=accept-new takes a new key",
                    self.label,
                    crate::terminal::UNWATCHED_PROMPT.as_secs()
                )
            });
        }
        Some(format!(
            "{}: the SSH handshake has not finished after {} s: {}; it waits until ConnectTimeout, {} s",
            self.label,
            FIRST_WORD.as_secs(),
            self.seen(record),
            self.limit.as_secs()
        ))
    }

    /// What came, and on a node's road what its layer and its channel
    /// carried each way.
    fn seen(&self, record: &Record) -> String {
        let seen = record.lock();
        let Some(road) = self.road else { return seen.words(SERVER) };
        if road.flow.opened().is_none() {
            return format!("the resumable layer to {} did not open", road.end);
        }
        let (from, to) = road.flow.carried();
        let mut words = format!(
            "{} (through the layer: {from} bytes from {}, {to} to it",
            seen.words(&format!("{} after the layer opened", road.far)),
            road.end
        );
        if road.channel {
            let (came, went) = (seen.came.bytes, seen.went.bytes);
            words.push_str(&format!("; through the end-to-end channel: {came} from it, {went} to it"));
        }
        words.push(')');
        words
    }
}

/// The stream of a handshake, read into its [`Record`] as it passes.
pub(crate) struct Watched<S> {
    inner: S,
    record: Record,
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.record.feed(true, &buf.filled()[before..]);
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &polled {
            self.record.feed(false, &data[..*n]);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod tests;
