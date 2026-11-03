//! One reverse socket's writer (T-427): the only task that writes to the
//! socket, so that frames keep their order and a `ready` goes before the
//! session's first byte. What waits for it is counted against the contract's
//! bound for a slow receiver, 1 MiB (its row `1011 relay backpressure`): a
//! sender to an operator gets a refusal past it, a sender to a node waits for
//! room (`super::node`, `super::operator`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::frame::{self, Frame};
use podssh_ws::session::RelaySession;
use podssh_ws::SessionError;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

/// The contract's bound for a slow receiver: past it, `1011 relay
/// backpressure`, and the frame that would pass it is dropped.
pub const BOUND: usize = 1 << 20;

/// A queued write. A binary frame holds its room until it is written.
enum Item {
    Text(String),
    Binary(Vec<u8>, OwnedSemaphorePermit),
    Close(u16, String),
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
    room: Arc<Semaphore>,
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
        let room = Arc::new(Semaphore::new(BOUND));
        let abort = Arc::new(Abort::default());
        let (ended, done) = watch::channel(false);
        writers.join();
        let (task_room, task_abort) = (room.clone(), abort.clone());
        tokio::spawn(async move {
            loop {
                let item = tokio::select! {
                    biased;
                    () = task_abort.now.notified() => None,
                    item = rx.recv() => item,
                };
                // An abort that came while a frame went out goes now.
                if let Some((code, why)) = task_abort.take() {
                    let _ = session.send_close(code, &why).await;
                    break;
                }
                let sent = match item {
                    None => break,
                    Some(Item::Text(text)) => session.send_text(&text).await,
                    Some(Item::Binary(frame, room)) => {
                        let sent = session.send_binary(&frame).await;
                        drop(room);
                        sent
                    }
                    Some(Item::Close(code, why)) => {
                        let _ = session.send_close(code, &why).await;
                        break;
                    }
                };
                if sent.is_err() {
                    break;
                }
            }
            // A sender that waits for room learns that none comes.
            task_room.close();
            rx.close();
            let _ = ended.send(true);
            writers.leave();
        });
        Outbox { tx, room, abort, done }
    }

    /// A text frame, after what waits; control is small and never waits.
    pub fn text(&self, text: String) {
        let _ = self.tx.send(Item::Text(text));
    }

    /// A binary frame for a receiver that its senders wait for: the node,
    /// whose one socket carries each session.
    pub async fn binary_waiting(&self, frame: Vec<u8>) -> Result<(), Gone> {
        let room = self.room.clone().acquire_many_owned(permits(frame.len())).await.map_err(|_| Gone)?;
        self.tx.send(Item::Binary(frame, room)).map_err(|_| Gone)
    }

    /// A binary frame, or [`Full`] when it would put more than [`BOUND`] in
    /// the queue: the contract's `1011 relay backpressure`.
    pub fn binary_or_full(&self, frame: Vec<u8>) -> Result<(), Full> {
        let room = self.room.clone().try_acquire_many_owned(permits(frame.len())).map_err(|_| Full)?;
        self.tx.send(Item::Binary(frame, room)).map_err(|_| Full)
    }

    /// The bytes that wait to be written.
    pub fn waiting(&self) -> usize {
        BOUND.saturating_sub(self.room.available_permits())
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
fn permits(len: usize) -> u32 {
    u32::try_from(len.clamp(1, BOUND)).unwrap_or(u32::MAX)
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
mod tests {
    use super::*;

    #[test]
    fn a_frame_takes_its_length_in_room_and_one_at_least() {
        assert_eq!(permits(0), 1);
        assert_eq!(permits(65568), 65568);
        assert_eq!(permits(usize::MAX), BOUND as u32);
    }

    #[tokio::test]
    async fn a_queue_for_a_slow_receiver_refuses_what_passes_the_bound() {
        // The writer's socket is never read: what is queued stays queued
        // once the pipe's own buffer is full.
        let (ours, _theirs) = tokio::io::duplex(1024);
        let session = Arc::new(podssh_ws::server::session(ours, Vec::new(), None));
        let writers = Arc::new(Writers::default());
        let outbox = Outbox::start(session, writers.clone());
        let mut queued = 0;
        while outbox.binary_or_full(vec![7u8; 64 * 1024]).is_ok() {
            queued += 64 * 1024;
            assert!(queued <= BOUND + 64 * 1024, "the bound held nothing back");
        }
        assert!(queued >= BOUND - 128 * 1024, "only {queued} bytes were queued");
        assert!(outbox.waiting() <= BOUND, "{} bytes wait", outbox.waiting());
    }
}
