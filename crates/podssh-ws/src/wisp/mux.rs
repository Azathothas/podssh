//! The streams of one Wisp connection over its WebSocket. One task reads
//! the WebSocket and gives each packet to its stream. Each stream has two
//! tasks: one sends the caller's bytes as DATA, never past the server's
//! credit, and one writes the server's DATA into the caller's pipe. A
//! stream's end is said (its word, its hook) before its pipe ends, so that
//! the caller who reads the end of its bytes finds why.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::handshake::Opened;
use super::packet::{self, Packet, Reason};
use super::{End, OnEnd, WispError};
use crate::forwarder::Note;
use crate::frame;
use crate::session::{close_code_and_reason, RelaySession};
use crate::url::Stream;

/// The WebSocket of a connection.
pub(super) type Session = RelaySession<Stream>;

/// The pipe in memory between a stream and its caller, each way.
const PIPE: usize = 256 * 1024;
/// The server's DATA kept for a stream whose caller reads slowly, before
/// the reader of the WebSocket waits for it: Wisp gives no credit to this
/// side, so past these a stream that is not read holds up the others.
const DOWN_PACKETS: usize = 64;
/// How long the server has to answer this side's Close of the WebSocket.
const CLOSE_WAIT: Duration = Duration::from_secs(5);

/// A stream's state, as its caller and its tasks wait on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Word {
    /// The CONNECT went; the server said nothing of the stream.
    Waiting,
    /// The server's DATA or CONTINUE came.
    Open,
    Ended(End),
}

/// A stream's place in the connection.
struct Slot {
    /// The latest CONTINUE's count, for the task that sends.
    credit: watch::Sender<u32>,
    word: watch::Sender<Word>,
    /// The server's DATA, for the task that writes the pipe; dropped with
    /// the slot, which ends the pipe once what came before is written.
    down: mpsc::Sender<Vec<u8>>,
    on_end: Option<OnEnd>,
}

impl Slot {
    fn open(&self) {
        self.word.send_if_modified(|w| match w {
            Word::Waiting => {
                *w = Word::Open;
                true
            }
            _ => false,
        });
    }

    /// The first end wins: its word, then its hook.
    fn settle(&self, end: End) {
        let first = self.word.send_if_modified(|w| match w {
            Word::Ended(_) => false,
            _ => {
                *w = Word::Ended(end.clone());
                true
            }
        });
        if let (true, Some(hook)) = (first, &self.on_end) {
            hook(&end);
        }
    }
}

/// The open streams, and the connection's end once it came: under one lock,
/// so that no stream opens after the end that would never end it.
#[derive(Default)]
struct Streams {
    open: HashMap<u32, Arc<Slot>>,
    gone: Option<End>,
}

/// A stream just opened, for [`super::WispStream`].
pub(super) struct Opening {
    pub id: u32,
    pub pipe: DuplexStream,
    pub word: watch::Receiver<Word>,
    pub tasks: Vec<JoinHandle<()>>,
}

/// What the connection's tasks and handles share.
pub(super) struct Shared {
    session: Session,
    pub(super) opened: Opened,
    streams: Mutex<Streams>,
    next: AtomicU32,
    /// Whether a [`super::Wisp`] handle is held.
    held: AtomicBool,
    /// A stream ended or the handle went: the reader closes the WebSocket
    /// when neither is left.
    idle: Notify,
    note: Note,
}

impl Shared {
    pub(super) fn new(session: Session, opened: Opened, note: Note) -> Shared {
        Shared {
            session,
            opened,
            streams: Mutex::default(),
            next: AtomicU32::new(1),
            held: AtomicBool::new(true),
            idle: Notify::new(),
            note,
        }
    }

    fn streams(&self) -> MutexGuard<'_, Streams> {
        self.streams.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The handle is gone.
    pub(super) fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
        self.idle.notify_one();
    }

    fn unused(&self) -> bool {
        !self.held.load(Ordering::SeqCst) && self.streams().open.is_empty()
    }

    fn slot(&self, id: u32) -> Option<Arc<Slot>> {
        self.streams().open.get(&id).cloned()
    }

    /// End stream `id` with `end`; false when it had ended.
    fn finish(&self, id: u32, end: End) -> bool {
        let slot = self.streams().open.remove(&id);
        let Some(slot) = slot else { return false };
        slot.settle(end);
        drop(slot);
        self.idle.notify_one();
        true
    }

    /// This side's CLOSE of stream `id`, unless it ended already.
    pub(super) async fn close_here(&self, id: u32, reason: Reason) {
        if self.finish(id, End::ClosedHere) {
            let _ = self.session.send_binary(&packet::encode(id, &Packet::Close(reason))).await;
        }
    }

    /// The connection ended: each stream with it.
    fn end_all(&self, end: End) {
        let slots: Vec<Arc<Slot>> = {
            let mut streams = self.streams();
            if streams.gone.is_none() {
                streams.gone = Some(end.clone());
            }
            streams.open.drain().map(|(_, slot)| slot).collect()
        };
        for slot in slots {
            slot.settle(end.clone());
        }
        self.idle.notify_one();
    }

    /// The next stream id: never 0, the connection's own.
    fn next_id(&self) -> u32 {
        loop {
            let id = self.next.fetch_add(1, Ordering::SeqCst);
            if id != 0 {
                return id;
            }
        }
    }

    /// A stream to `host:port`: its slot, its CONNECT, its two tasks.
    pub(super) async fn open(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        close_at_end: bool,
        on_end: Option<OnEnd>,
    ) -> Result<Opening, WispError> {
        crate::names::check_target(host)
            .map_err(|why| WispError::Failed(format!("the target cannot go to a Wisp server: {why}")))?;
        if port == 0 {
            return Err(WispError::Failed("the target cannot go to a Wisp server: port 0 is not a port".into()));
        }
        let id = self.next_id();
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let (from_local, to_local) = tokio::io::split(theirs);
        let (credit, credit_rx) = watch::channel(self.opened.buffer);
        let (word, word_rx) = watch::channel(Word::Waiting);
        let (down, down_rx) = mpsc::channel(DOWN_PACKETS);
        {
            let mut streams = self.streams();
            if let Some(end) = &streams.gone {
                return Err(end.clone().into_error());
            }
            // In before its CONNECT goes, so that a CLOSE at once finds it.
            streams.open.insert(id, Arc::new(Slot { credit, word, down, on_end }));
        }
        let connect = Packet::Connect { kind: packet::TCP, port, host: host.to_string() };
        if let Err(e) = self.session.send_binary(&packet::encode(id, &connect)).await {
            let why = format!("sending the CONNECT to the Wisp server failed: {e}");
            self.finish(id, End::Failed(why.clone()));
            return Err(WispError::Failed(why));
        }
        let up = tokio::spawn(up(self.clone(), id, from_local, credit_rx, word_rx.clone(), close_at_end));
        let down = tokio::spawn(down_task(self.clone(), id, down_rx, to_local));
        Ok(Opening { id, pipe: ours, word: word_rx, tasks: vec![up, down] })
    }
}

/// Until the stream's word is its end, or no word can come.
async fn ended(word: &mut watch::Receiver<Word>) {
    let _ = word.wait_for(|w| matches!(w, Word::Ended(_))).await;
}

/// The caller's bytes to the server, as DATA of 32 KiB at most, within the
/// server's credit: the count of its latest CONTINUE, less one for each
/// DATA since, and none at zero until a CONTINUE gives more (the protocol's
/// rule, which keeps the server's buffer of each stream bounded).
async fn up(
    shared: Arc<Shared>,
    id: u32,
    mut from_local: ReadHalf<DuplexStream>,
    mut credit: watch::Receiver<u32>,
    mut word: watch::Receiver<Word>,
    close_at_end: bool,
) {
    let mut left = *credit.borrow_and_update();
    let mut buf = vec![0u8; super::CHUNK];
    loop {
        let read = tokio::select! {
            read = from_local.read(&mut buf) => read,
            () = ended(&mut word) => return,
        };
        let n = match read {
            Ok(n) if n > 0 => n,
            // Wisp has no half-close: a pipe waits for the server's end.
            _ => {
                match close_at_end {
                    true => shared.close_here(id, Reason::VOLUNTARY).await,
                    false => ended(&mut word).await,
                }
                return;
            }
        };
        if credit.has_changed().unwrap_or(false) {
            left = *credit.borrow_and_update();
        }
        while left == 0 {
            tokio::select! {
                changed = credit.changed() => match changed {
                    Ok(()) => left = *credit.borrow_and_update(),
                    Err(_) => return,
                },
                () = ended(&mut word) => return,
            }
        }
        if let Err(e) = shared.session.send_binary(&packet::data(id, &buf[..n])).await {
            shared.end_all(End::Failed(format!("sending to the Wisp server failed: {e}")));
            return;
        }
        left -= 1;
    }
}

/// The server's DATA into the caller's pipe; the pipe's end once the slot
/// is gone and each DATA before it is written.
async fn down_task(
    shared: Arc<Shared>,
    id: u32,
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut to_local: WriteHalf<DuplexStream>,
) {
    while let Some(bytes) = rx.recv().await {
        if to_local.write_all(&bytes).await.is_err() {
            // The caller dropped its end, and takes nothing more.
            shared.close_here(id, Reason::VOLUNTARY).await;
            break;
        }
    }
    let _ = to_local.shutdown().await;
}

/// Until `at`, or never.
async fn until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// The reader of the WebSocket, until its end, which ends each stream. It
/// pings as each forwarder's session does, and closes the WebSocket once no
/// handle and no stream is left.
pub(super) async fn read(shared: Arc<Shared>) {
    let session = &shared.session;
    let liveness = session.watch_liveness(crate::LIVENESS_EVERY, crate::LIVENESS_ALLOWED);
    tokio::pin!(liveness);
    let mut closing: Option<Instant> = None;
    let end = loop {
        let read = tokio::select! {
            read = session.read_frame() => read,
            why = &mut liveness => break End::Failed(why.to_string()),
            () = shared.idle.notified(), if closing.is_none() => {
                if shared.unused() {
                    let _ = session.send_close(1000, "").await;
                    closing = Some(Instant::now() + CLOSE_WAIT);
                }
                continue;
            }
            () = until(closing) => break End::Gone { code: Some(1000), reason: String::new() },
        };
        let f = match read {
            Ok(f) => f,
            Err(e) => break End::Failed(e.to_string()),
        };
        match f.opcode {
            frame::OPCODE_CLOSE => {
                let (code, reason) = close_code_and_reason(&f.payload);
                break End::Gone { code, reason };
            }
            frame::OPCODE_BINARY => match packet::decode(&f.payload) {
                Ok((id, packet)) => {
                    if let Some(end) = dispatch(&shared, id, packet).await {
                        let _ = session.send_close(1000, "").await;
                        break end;
                    }
                }
                Err(why) => {
                    let _ = session.send_close(1002, "").await;
                    break End::Failed(format!("the Wisp server sent {why}"));
                }
            },
            frame::OPCODE_TEXT => (shared.note)(&format!("the Wisp server says: {}", super::note_text(&f.payload))),
            _ => {}
        }
    };
    shared.end_all(end);
}

/// One packet of the server's to its stream; the connection's end when the
/// server closed the connection itself.
async fn dispatch(shared: &Shared, id: u32, packet: Packet) -> Option<End> {
    match (id, packet) {
        (0, Packet::Close(reason)) => return Some(End::Closed(reason)),
        // A later INFO or CONTINUE of the connection's own changes nothing.
        (0, _) => {}
        (id, Packet::Data(bytes)) => {
            if let Some(slot) = shared.slot(id) {
                slot.open();
                if !bytes.is_empty() {
                    let _ = slot.down.send(bytes).await;
                }
            }
        }
        (id, Packet::Continue(left)) => {
            if let Some(slot) = shared.slot(id) {
                slot.open();
                slot.credit.send_replace(left);
            }
        }
        (id, Packet::Close(reason)) => {
            shared.finish(id, End::Closed(reason));
        }
        (_, other) => (shared.note)(&format!("the Wisp server sent {}, which a client does not take", other.name())),
    }
    None
}
