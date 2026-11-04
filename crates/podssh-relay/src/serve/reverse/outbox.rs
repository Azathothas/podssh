//! One reverse socket's writer (T-427): the only task that writes to the
//! socket, so that frames keep their order and a `ready` goes before the
//! session's first byte. What waits for it is counted against the contract's
//! bound for a slow receiver, 1 MiB (its row `1011 relay backpressure`): a
//! sender to an operator gets a refusal past it, a sender to a node waits for
//! room (`super::node`, `super::operator`). Text goes first; binary frames
//! wait in a line for each session, a turn each, so that one session's
//! backlog to a node delays no other session's bytes (T-648,
//! `crate::reverse::fair`), and a session's `close` goes after its bytes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::frame::{self, Frame};
use podssh_ws::session::RelaySession;
use podssh_ws::SessionError;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;

use crate::reverse::fair::{Fair, Refused, Turn};
use crate::reverse::framing::SessionId;

/// The contract's bound for a slow receiver: past it, `1011 relay
/// backpressure`, and the frame that would pass it is dropped.
pub const BOUND: usize = 1 << 20;

/// A queued write ahead of the sessions' lines: a text frame, or the Close,
/// which goes once each line has gone out.
enum Item {
    Text(String),
    Close(u16, String),
}

/// A piece of a session's line: a binary frame, which holds its room until
/// it is written, or the text that ends the session after its bytes.
enum Piece {
    Binary(Vec<u8>),
    Text(String),
}

/// A session's line: its id on a node's socket; an operator's socket
/// carries one session, in one line.
type Line = Option<SessionId>;

/// What the writer takes next.
enum Next {
    Abort,
    Item(Option<Item>),
    Turn(Option<Turn<Line, Piece>>),
}

/// A Close that goes before what waits: the frames queued are dropped.
#[derive(Default)]
struct Abort {
    with: Mutex<Option<(u16, String)>>,
    now: Notify,
}

impl Abort {
    fn take(&self) -> Option<(u16, String)> {
        self.with.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// The frame did not fit: the receiver is slow, or its socket ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

/// The socket ended: nothing more is written to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gone;

/// How many writers run, so that a planned stop waits for each Close to go
/// out (T-255); a second count, of the sockets' own tasks, waits for each
/// peer's answer to it ([`Writers::counted`]).
#[derive(Default)]
pub struct Writers {
    running: AtomicUsize,
    idle: Notify,
}

/// One task counted in its [`Writers`] while it lives.
pub struct Counted(Arc<Writers>);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.leave();
    }
}

impl Writers {
    fn join(&self) {
        self.running.fetch_add(1, Ordering::SeqCst);
    }

    fn leave(&self) {
        if self.running.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.idle.notify_waiters();
        }
    }

    /// Count the caller's task until the guard ends: a socket's, which
    /// ends at its peer's Close, or [`super::CLOSE_WAIT`] after its own.
    pub fn counted(self: &Arc<Self>) -> Counted {
        self.join();
        Counted(self.clone())
    }

    /// Until no writer runs, or `limit`: whether each ended.
    pub async fn settled(&self, limit: Duration) -> bool {
        let wait = async {
            loop {
                let idle = self.idle.notified();
                if self.running.load(Ordering::SeqCst) == 0 {
                    return;
                }
                idle.await;
            }
        };
        tokio::time::timeout(limit, wait).await.is_ok()
    }
}

/// The writer of one socket, cheap to clone.
#[derive(Clone)]
pub struct Outbox {
    tx: mpsc::UnboundedSender<Item>,
    lines: Fair<Line, Piece>,
    abort: Arc<Abort>,
    done: watch::Receiver<bool>,
}

impl Outbox {
    /// Start the writer of `session`, counted in `writers`.
    pub fn start<S>(session: Arc<RelaySession<S>>, writers: Arc<Writers>) -> Outbox
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (tx, mut rx) = mpsc::unbounded_channel::<Item>();
        // Each line may hold the whole bound, as one session did before;
        // a line that holds nothing takes one frame past it.
        let lines = Fair::new(BOUND, BOUND);
        let abort = Arc::new(Abort::default());
        let (ended, done) = watch::channel(false);
        writers.join();
        let (task_lines, task_abort) = (lines.clone(), abort.clone());
        tokio::spawn(async move {
            // The Close asked for, which goes once each line went out; `None`
            // inside when each sender is gone, which ends with no Close.
            let mut closing: Option<Option<(u16, String)>> = None;
            loop {
                let next = tokio::select! {
                    biased;
                    () = task_abort.now.notified() => Next::Abort,
                    item = rx.recv(), if closing.is_none() => Next::Item(item),
                    turn = task_lines.next() => Next::Turn(turn),
                };
                // An abort that came while a frame went out goes now.
                if let Some((code, why)) = task_abort.take() {
                    let _ = session.send_close(code, &why).await;
                    break;
                }
                let sent = match next {
                    Next::Abort => break,
                    Next::Item(Some(Item::Text(text))) => session.send_text(&text).await,
                    // No frame joins a line now; what they hold goes first.
                    Next::Item(Some(Item::Close(code, why))) => {
                        closing = Some(Some((code, why)));
                        task_lines.shut();
                        continue;
                    }
                    Next::Item(None) => {
                        closing = Some(None);
                        task_lines.shut();
                        continue;
                    }
                    Next::Turn(Some(turn)) => {
                        let sent = match turn.piece {
                            Piece::Binary(frame) => session.send_binary(&frame).await,
                            Piece::Text(text) => session.send_text(&text).await,
                        };
                        drop(turn.slot);
                        sent
                    }
                    Next::Turn(None) => {
                        if let Some(Some((code, why))) = closing.take() {
                            let _ = session.send_close(code, &why).await;
                        }
                        break;
                    }
                };
                if sent.is_err() {
                    break;
                }
            }
            // A sender that waits for room learns that none comes.
            task_lines.shut();
            rx.close();
            let _ = ended.send(true);
            writers.leave();
        });
        Outbox { tx, lines, abort, done }
    }

    /// A text frame, before the sessions' bytes that wait; control is small
    /// and never waits.
    pub fn text(&self, text: String) {
        let _ = self.tx.send(Item::Text(text));
    }

    /// A text frame that ends session `id`, after the bytes of `id` that
    /// wait, and before the Close: a node hears a session's last bytes before
    /// its `close` (T-648).
    pub fn text_after(&self, id: SessionId, text: String) {
        let _ = self.lines.push_last(Some(id), Piece::Text(text));
    }

    /// A binary frame of session `id` for a receiver that its senders wait
    /// for: the node, whose one socket carries each session, a turn each.
    pub async fn binary_waiting(&self, id: SessionId, frame: Vec<u8>) -> Result<(), Gone> {
        let cost = cost(frame.len());
        self.lines.push(Some(id), Piece::Binary(frame), cost).await.map_err(|_| Gone)
    }

    /// A binary frame, or [`Full`] when it would put more than [`BOUND`] in
    /// the queue: the contract's `1011 relay backpressure`. A socket that
    /// ends, after its Close was asked for, takes it as each frame after a
    /// Close: it is never written.
    pub fn binary_or_full(&self, frame: Vec<u8>) -> Result<(), Full> {
        let cost = cost(frame.len());
        match self.lines.try_push(None, Piece::Binary(frame), cost) {
            Ok(()) | Err(Refused::Shut) => Ok(()),
            Err(Refused::Full) => Err(Full),
        }
    }

    /// The bytes that wait to be written.
    pub fn waiting(&self) -> usize {
        self.lines.used()
    }

    /// Drop the frames that wait for session `id`, which its receiver ended:
    /// they would reach it for an id that it forgot.
    pub fn drop_session(&self, id: &SessionId) {
        self.lines.drop_line(&Some(*id));
    }

    /// A Close after what waits: the receiver gets each byte before it.
    pub fn close(&self, code: u16, why: &str) {
        let _ = self.tx.send(Item::Close(code, why.to_string()));
    }

    /// A Close before what waits, which is dropped, as for a receiver that
    /// fell behind.
    pub fn abort(&self, code: u16, why: &str) {
        *self.abort.with.lock().unwrap_or_else(|e| e.into_inner()) = Some((code, why.to_string()));
        self.abort.now.notify_one();
    }

    /// Until the writer ended: after its Close, or a write that failed.
    pub async fn ended(&self) {
        let mut done = self.done.clone();
        let _ = done.wait_for(|ended| *ended).await;
    }
}

/// The room that a frame of `len` bytes takes; an empty one takes one.
fn cost(len: usize) -> usize {
    len.clamp(1, BOUND)
}

/// The socket's messages, read by a task of its own: a read that a `select!`
/// dropped could stop in the middle of the Pong that it writes. The last is
/// the Close, or the error that ended the socket.
pub fn frames_of<S>(session: Arc<RelaySession<S>>) -> (mpsc::Receiver<Result<Frame, SessionError>>, JoinHandle<()>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (tx, rx) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        loop {
            let read = session.read_frame().await;
            let last = !matches!(&read, Ok(f) if f.opcode != frame::OPCODE_CLOSE);
            if tx.send(read).await.is_err() || last {
                return;
            }
        }
    });
    (rx, task)
}

#[cfg(test)]
#[path = "outbox_tests.rs"]
mod tests;
