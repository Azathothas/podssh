//! One link of a session over tokio streams: the application's bytes out as
//! `DATA`, the peer's records in, both ways at once.
//!
//! With a replay buffer, the application's bytes go out only while the
//! buffer has room: a full buffer makes the writer wait for an `ACK`, so SSH
//! waits and its window stops the far side (T-152). The peer's bytes are
//! acknowledged each 64 KiB, and 200 ms after any that are not.
//!
//! One writer owns the link's write side, and the reader never waits for it
//! ([`outbox`], T-262). A link whose writes fail still gives what it carried
//! before: the reader goes on for a short time, so the far end's last bytes
//! and its `CLOSE`, which a relay delivers before it closes the link, are
//! not lost.
//!
//! The session ends when a `CLOSE` is answered: the side whose application
//! ended sends `CLOSE` after its last bytes, and the peer answers with its
//! own. A link that ends before the answer leaves the session to a resume,
//! which sends the `CLOSE` again (T-262).
//!
//! A link can end at any await: the application stays open, and what the
//! session needs for the next link (its offsets, its buffer, the bytes not
//! yet written to the application) is in the [`Carry`] that the caller
//! keeps (T-153).

mod down;
mod outbox;

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use super::decode::Decoder;
use super::link::{Link, LinkError};
use super::record::MAX_DATA;
use outbox::{Finish, Outbox, Written};

/// How much of the application's bytes one read takes: a `DATA` record that
/// fits a frame of the reverse road with its id.
const CHUNK: usize = 32 * 1024;
/// How long this side waits for the peer's answer to its `CLOSE`.
const LINGER: Duration = Duration::from_secs(10);
/// How long the reader goes on after the link's writes failed: what came
/// before waits in the transport's buffers, so it takes little time.
const DRAIN: Duration = Duration::from_secs(5);
/// How long the writer may take to finish its record before a last `CLOSE`
/// or `RETIRE`: a link that cannot take a record in that time gets neither.
const FINISH: Duration = Duration::from_secs(2);
/// How long bytes wait for their acknowledgement when fewer than 64 KiB came.
pub const ACK_DELAY: Duration = Duration::from_millis(200);
/// A `PING` goes out when this side sent nothing for this long (T-154).
pub const PING_EVERY: Duration = Duration::from_secs(10);
/// A link that carried nothing from the far end for three intervals is
/// dead, and a resume replaces it.
pub const DEAD_AFTER: Duration = Duration::from_secs(30);

/// How a link of the session ended.
#[derive(Debug)]
pub enum End {
    /// The session ended at this side: its application ended its bytes and
    /// the peer answered its `CLOSE`, or its application stopped reading.
    LocalEnd,
    /// The peer ended the session with `CLOSE` and this reason; this side
    /// answered it when it could.
    Closed(String),
    /// This side's `CLOSE` went out, but the link ended before the peer's
    /// answer came: a resume sends the `CLOSE` again (T-262).
    Closing,
    /// The link ended with no `CLOSE`: a loss, which a resume can carry over
    /// (T-153).
    Lost(Option<std::io::Error>),
    /// The link carried what ends it: a gap, bytes that are not records, a
    /// `REFUSE`.
    Broken(LinkError),
    /// This side was told to stop: the session went on to a newer link.
    Stopped,
    /// The peer retired this link: the session goes on over another one
    /// (T-155).
    Retired,
    /// This link nears the relay's limits, and the session moves: what the
    /// resume driver gives its caller when it asks for a new link (T-155);
    /// no link ends so.
    Moving,
    /// No new link carried the session on, for this reason: the far end did
    /// not resume it, the transport said not to come back, or the deadline
    /// passed (T-153).
    GaveUp(String),
}

impl End {
    /// Whether a new link can carry the session on: each end but the
    /// session's own (a `CLOSE` either way, a `REFUSE`).
    pub fn resumable(&self) -> bool {
        match self {
            End::Lost(_) | End::Closing | End::Stopped | End::Retired | End::Moving => true,
            End::Broken(LinkError::Refused { .. }) => false,
            End::Broken(_) => true,
            End::LocalEnd | End::Closed(_) | End::GaveUp(_) => false,
        }
    }
}

/// The end of a link, and the offsets of the session at that moment.
#[derive(Debug)]
pub struct Ended {
    pub end: End,
    /// The count of the bytes received, which is where a resume asks the
    /// peer to send from.
    pub received: u64,
    pub sent: u64,
}

/// What a session carries from one link to the next.
#[derive(Debug)]
pub struct Carry {
    /// The offsets, the replay buffer and the acknowledgements.
    pub state: Arc<Mutex<Link>>,
    /// Bytes received and counted, not yet written to the application: a link
    /// that ends while it writes them leaves the rest here, for the next.
    undelivered: Vec<u8>,
    /// The `DATA` records of a resume, which the next link sends before the
    /// application's new bytes.
    again: Vec<u8>,
    /// Whether this side's application ended its bytes: from then on, each
    /// link of the session sends `CLOSE` after the last of them.
    app_ended: bool,
}

impl Carry {
    pub fn new(link: Link) -> Carry {
        Carry { state: Arc::new(Mutex::new(link)), undelivered: Vec::new(), again: Vec::new(), app_ended: false }
    }

    /// Whether this side's application ended its bytes, on this link or an
    /// earlier one: a far end that then no longer knows the session had its
    /// `CLOSE` (T-262).
    pub fn app_ended(&self) -> bool {
        self.app_ended
    }

    /// The bytes received that the application has not taken yet.
    pub fn undelivered(&self) -> usize {
        self.undelivered.len()
    }

    /// The `DATA` records that the peer lacks, from [`Link::resume`]: the
    /// next link's writer sends them first, while its reader reads, so two
    /// ends that send again at once do not wait on each other (T-262).
    pub fn send_again(&mut self, records: Vec<u8>) {
        self.again = records;
    }
}

/// What the caller of one link watches and steers.
#[derive(Debug, Default)]
pub struct Watch {
    /// Ends the link at a record boundary, with [`End::Stopped`].
    pub stop: Notify,
    /// Whether a stopped link sends `RETIRE` first: the client moved the
    /// session to another link (T-155).
    pub retire: AtomicBool,
    /// The bytes that the link carried, both ways, the records included:
    /// what the relay counts against its cap.
    pub bytes: AtomicU64,
    /// The count of bytes at which `due` is told, once (T-155); 0 is never.
    pub move_at: AtomicU64,
    /// Told when the link's bytes pass `move_at`.
    pub due: Notify,
    /// Set when this side's application ended its bytes on this link: the
    /// session is closing, and a move would only delay its `CLOSE`.
    pub app_ended: AtomicBool,
}

impl Watch {
    /// A watch that tells `due` when the link passes `move_at` bytes.
    pub fn moving_at(move_at: u64) -> Watch {
        let watch = Watch::default();
        watch.move_at.store(move_at, Ordering::Relaxed);
        watch
    }

    /// Count `n` more bytes of the link, and tell `due` when they pass the
    /// mark.
    fn count(&self, n: u64) {
        let before = self.bytes.fetch_add(n, Ordering::Relaxed);
        let at = self.move_at.load(Ordering::Relaxed);
        if at > 0 && before < at && before + n >= at {
            self.due.notify_one();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Carry the session between `app` and `link` until the link or the session
/// ends, or `watch` stops it. `decoder` holds what the handshake read past
/// its last record. The application is not shut: the caller does that when
/// the session ends, and keeps it open for the next link when it does not.
pub async fn run<A, L>(app: &mut A, link: L, decoder: Decoder, carry: &mut Carry, watch: &Watch) -> Ended
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    L: AsyncRead + AsyncWrite + Send,
{
    let (mut app_r, mut app_w) = tokio::io::split(app);
    let (link_r, mut link_w) = tokio::io::split(link);
    let Carry { state, undelivered, again, app_ended: app_ended_before } = carry;
    let again = std::mem::take(again);
    let heartbeat = lock(state).heartbeat();
    let outbox = Outbox::new();
    let heard = Mutex::new(Instant::now());
    let room = Notify::new();
    // One batch of `DATA` waits while the writer sends the one before.
    let (data_tx, mut data_rx) = mpsc::channel(1);

    let end = {
        let up = up(&mut app_r, again, data_tx, state, &room);
        let down = down::run(&mut app_w, link_r, decoder, &outbox, state, &room, undelivered, &heard, watch);
        let writer = outbox::write(&mut link_w, &mut data_rx, &outbox, state, watch);
        let beat = async {
            if heartbeat {
                beat(&outbox, &heard).await
            } else {
                std::future::pending().await
            }
        };
        tokio::pin!(up, down, writer, beat);
        let mut app_ended = false;
        loop {
            tokio::select! {
                end = &mut down => break match end {
                    // The peer's `CLOSE`: answered. When this side's own
                    // `CLOSE` is on its way, it is the answer, and the
                    // writer finishes it.
                    End::Closed(reason) => {
                        if outbox.closed() {
                            let _ = tokio::time::timeout(FINISH, writer.as_mut()).await;
                        } else {
                            finish(&outbox, Finish::Close, writer.as_mut()).await;
                        }
                        End::Closed(reason)
                    }
                    // An application that stopped reading ended the session
                    // too, and `CLOSE` says so.
                    End::LocalEnd => {
                        finish(&outbox, Finish::Close, writer.as_mut()).await;
                        End::LocalEnd
                    }
                    other => other,
                },
                failed = &mut up, if !app_ended => {
                    app_ended = true;
                    if let Some(end) = failed {
                        break end;
                    }
                    *app_ended_before = true;
                    watch.app_ended.store(true, Ordering::SeqCst);
                    // The application ended its bytes: the writer sends the
                    // rest, then `CLOSE`.
                }
                written = &mut writer => break match written {
                    // `CLOSE` is out: the peer answers it with its own. A
                    // stop (a resume on a newer link) cuts the wait short.
                    Written::Closed => tokio::select! {
                        end = tokio::time::timeout(LINGER, &mut down) => match end {
                            Ok(End::Closed(_)) => End::LocalEnd,
                            Ok(end @ (End::Broken(LinkError::Refused { .. }) | End::LocalEnd)) => end,
                            // No answer: a resume sends the `CLOSE` again.
                            _ => End::Closing,
                        },
                        _ = watch.stop.notified() => End::Closing,
                    },
                    // The write side failed, but what came before it still
                    // waits to be read: the peer's last bytes, its `CLOSE`.
                    Written::Failed(e) => tokio::select! {
                        end = tokio::time::timeout(DRAIN, &mut down) => match end {
                            Ok(end @ (End::Closed(_) | End::Retired | End::Broken(_) | End::LocalEnd)) => end,
                            _ => End::Lost(Some(e)),
                        },
                        _ = watch.stop.notified() => End::Stopped,
                    },
                    // Only `finish` asks the writer to stop.
                    Written::Finished => End::Stopped,
                },
                _ = watch.stop.notified() => {
                    // A moved session's old link says that it ends, so the
                    // far end does not wait for it.
                    if watch.retire.load(Ordering::SeqCst) {
                        finish(&outbox, Finish::Retire, writer.as_mut()).await;
                    }
                    break End::Stopped;
                }
                end = &mut beat => break end,
            }
        }
    };
    let state = lock(state);
    Ended { end, received: state.received(), sent: state.sent() }
}

/// Ask the writer to stop at its next record boundary with `last`, and wait
/// a short time for it: a link that cannot take a record in that time gets
/// nothing more.
async fn finish<F: Future<Output = Written> + Unpin>(outbox: &Outbox, last: Finish, writer: F) {
    outbox.finish(last);
    let _ = tokio::time::timeout(FINISH, writer).await;
}

/// A `PING` after [`PING_EVERY`] with nothing sent, and the end of the link
/// after [`DEAD_AFTER`] with nothing heard from the far end (T-154). Each
/// record is payload to the relay, so the pings also keep its idle cut away;
/// the far end's `PONG` carries its received offset, an acknowledgement.
async fn beat(outbox: &Outbox, heard: &Mutex<Instant>) -> End {
    loop {
        let now = Instant::now();
        let last_heard = *lock(heard);
        if now.duration_since(last_heard) >= DEAD_AFTER {
            let why = format!("nothing came from the far end for {} s", DEAD_AFTER.as_secs());
            return End::Lost(Some(std::io::Error::new(std::io::ErrorKind::TimedOut, why)));
        }
        if now.duration_since(outbox.quiet_since()) >= PING_EVERY {
            outbox.ping();
        }
        let next = (outbox.quiet_since() + PING_EVERY).min(last_heard + DEAD_AFTER);
        // Never a wait of nothing: a clock that stands still would spin.
        tokio::time::sleep_until(next.max(Instant::now() + Duration::from_millis(10))).await;
    }
}

/// The end of the first record in `records`: a type byte, a 32-bit length,
/// the body.
fn first_record(records: &[u8]) -> usize {
    match records.get(1..5) {
        Some(len) => (5 + u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize).min(records.len()),
        None => records.len(),
    }
}

/// The application's bytes out, as `DATA` for the writer: first the records
/// of a resume (`again`), a record at a time, then the application's new
/// bytes. `None` when the application ended them, which `CLOSE` then says,
/// else why the session cannot go on. It reads only what the replay buffer
/// has room for, and waits for an acknowledgement when it has none. A byte
/// read is in the buffer before any await, so a link that ends loses none.
async fn up<R>(
    app: &mut R,
    again: Vec<u8>,
    data: mpsc::Sender<Vec<u8>>,
    state: &Mutex<Link>,
    room: &Notify,
) -> Option<End>
where
    R: AsyncRead + Unpin,
{
    // The records of a resume are in the replay buffer already: a link that
    // ends before they go out loses none, and the next resume sends them.
    let mut rest = &again[..];
    while !rest.is_empty() {
        let end = first_record(rest);
        if data.send(rest[..end].to_vec()).await.is_err() {
            return std::future::pending().await;
        }
        rest = &rest[end..];
    }
    let mut buf = vec![0u8; CHUNK.min(MAX_DATA)];
    loop {
        let space = loop {
            // Asked for before the check, so that an `ACK` between the two is
            // not missed.
            let freed = room.notified();
            let space = lock(state).room();
            if space > 0 {
                break space;
            }
            freed.await;
        };
        let want = buf.len().min(space);
        let n = match app.read(&mut buf[..want]).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        let mut records = Vec::with_capacity(n + 16);
        if let Err(e) = lock(state).send(&buf[..n], &mut records) {
            return Some(End::Broken(e));
        }
        if data.send(records).await.is_err() {
            // The writer is gone, and its own end ends the link.
            return std::future::pending().await;
        }
    }
}
