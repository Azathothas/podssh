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
//! which sends the `CLOSE` again (T-262). Where both sides name `end.v1`, the
//! first side's end is `END`, which ends its direction alone, and the second
//! side's is the `CLOSE` (T-632, `super::half_close`).
//!
//! A link can end at any await: the application stays open, and what the
//! session needs for the next link (its offsets, its buffer, the bytes not
//! yet written to the application) is in the [`Carry`] that the caller
//! keeps (T-153).

mod down;
mod outbox;
mod up;

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use super::decode::Decoder;
use super::hearing::Hearing;
use super::link::{Link, LinkError};
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
/// How long a retired link is held for its far end to end it: more than the
/// far end's 30 s for a handshake, after which it drops each link (T-388).
const LINGER_RETIRED: Duration = Duration::from_secs(35);

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
    /// This link nears the relay's limits, and the session moves, or it
    /// went silent, and a spare link opens beside it: what the resume driver
    /// gives its caller when it asks for a new link beside the one that
    /// goes on (T-155, T-305); no link ends so.
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

    /// A loss, in words: the client's line of a loss before its resume, and
    /// of the end of a session that ends with its link (T-612).
    pub fn loss(&self) -> String {
        match self {
            End::Lost(Some(e)) => format!("the link failed: {e}"),
            End::Lost(None) => "the link ended with no word from the far end".to_string(),
            End::Broken(e) => format!("the link broke: {e}"),
            End::Closing => "the link ended before the far end answered this side's CLOSE".to_string(),
            End::Stopped | End::Retired => "the link was replaced".to_string(),
            End::Moving => "the link nears the relay's limits".to_string(),
            End::LocalEnd | End::Closed(_) | End::GaveUp(_) => "the session ended".to_string(),
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
    /// link of the session sends `CLOSE`, or `END` (T-632), after the last of
    /// them.
    app_ended: bool,
    /// What this side heard from the far end, across links (T-302).
    hearing: Arc<Hearing>,
    /// Whether the application's write side is shut: the peer's `END` came,
    /// and the application took each byte before it (T-632).
    app_shut: bool,
}

impl Carry {
    pub fn new(link: Link) -> Carry {
        Carry {
            state: Arc::new(Mutex::new(link)),
            undelivered: Vec::new(),
            again: Vec::new(),
            app_ended: false,
            hearing: Arc::default(),
            app_shut: false,
        }
    }

    /// The session's hearing is `hearing`, which a notice in the terminal
    /// reads (T-302).
    pub fn with_hearing(mut self, hearing: Arc<Hearing>) -> Carry {
        self.hearing = hearing;
        self
    }

    /// What this side heard from the far end.
    pub fn hearing(&self) -> &Hearing {
        &self.hearing
    }

    /// Whether this side's application ended its bytes, on this link or an
    /// earlier one: a far end that then no longer knows the session had its
    /// `CLOSE` (T-262).
    pub fn app_ended(&self) -> bool {
        self.app_ended
    }

    /// Whether this side's `CLOSE` is due or went: its application ended its
    /// bytes, and no `END` keeps the session open for the peer's (T-632). A
    /// far end that then no longer knows the session had the `CLOSE`.
    pub fn closing(&self) -> bool {
        self.app_ended && lock(&self.state).closes_at_end()
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
    /// Set when this side's application ended its bytes on this link and
    /// its `CLOSE` is due, not at an `END` (T-632): the session is closing,
    /// and a move would only delay its `CLOSE`.
    pub app_ended: AtomicBool,
    /// Whether this side ends a retired link (the far end, a node's): after
    /// its last bytes it closes its side, and on a node's road the node's
    /// `close` then follows its data. The client never does: an end of its
    /// side is the operator leg's end, whose Close would cross the node's
    /// bytes still on their way, and the relay ends the node's whole socket
    /// for a frame of an id that it forgot (T-410).
    pub ends_links: bool,
    /// The most bytes that this link carries with no acknowledgement, from
    /// the settings of its road (T-443); `None` leaves it to the buffer.
    pub window: Option<usize>,
}

impl Watch {
    /// The far end's watch: it ends the links that it retires or that are
    /// retired under it.
    pub fn far_end() -> Watch {
        Watch { ends_links: true, ..Watch::default() }
    }

    /// This watch, for a link whose bytes in flight stay within `window`.
    pub fn within(mut self, window: Option<usize>) -> Watch {
        self.window = window;
        self
    }

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
    L: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut app_r, mut app_w) = tokio::io::split(app);
    let (mut link_r, mut link_w) = tokio::io::split(link);
    let Carry { state, undelivered, again, app_ended: app_ended_before, hearing, app_shut } = carry;
    let hearing: &Hearing = hearing;
    let again = std::mem::take(again);
    let ended_before = *app_ended_before;
    let heartbeat = lock(state).heartbeat();
    let outbox = Outbox::new();
    let heard = Mutex::new(Instant::now());
    let room = Notify::new();
    // One batch of `DATA` waits while the writer sends the one before.
    let (data_tx, mut data_rx) = mpsc::channel(1);

    let mut retired = false;
    let end = {
        let up = up::run(&mut app_r, again, data_tx, state, &room, watch.window, ended_before);
        let down = down::run(
            &mut app_w,
            &mut link_r,
            decoder,
            &outbox,
            state,
            &room,
            undelivered,
            &heard,
            hearing,
            watch,
            app_shut,
        );
        let writer = outbox::write(&mut link_w, &mut data_rx, &outbox, state, watch, hearing);
        let beat = async {
            if heartbeat {
                beat(&outbox, &heard, hearing).await
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
                    // The application ended its bytes: the writer sends the
                    // rest, then `CLOSE`; or `END`, and the session is not
                    // closing until the peer's own end (T-632).
                    if lock(state).closes_at_end() {
                        watch.app_ended.store(true, Ordering::SeqCst);
                    }
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
                        retired = true;
                    }
                    break End::Stopped;
                }
                end = &mut beat => break end,
            }
        }
    };
    // The far end ends a retired link itself, after the last of its bytes
    // on it: a node's road then closes the leg after its data, where a leg
    // that this side dropped first would be closed under the node's data
    // still on its way, and the relay ends the node's whole socket for a
    // frame of an id it forgot (T-388). Its bytes are no longer the
    // session's: the new link carries them again.
    // The far end's own `RETIRE` is followed by its end of the link the same
    // way, once its last bytes are out.
    if retired || matches!(end, End::Retired) {
        tokio::spawn(linger(link_r, link_w, watch.ends_links));
    }
    let state = lock(state);
    Ended { end, received: state.received(), sent: state.sent() }
}

/// Hold a retired link until the other side ends it, or [`LINGER_RETIRED`]
/// passes, reading and dropping what still comes on it; the side that
/// `ends` it first closes its own (`Watch::ends_links`).
async fn linger<L: AsyncRead + AsyncWrite>(mut read: ReadHalf<L>, mut write: WriteHalf<L>, ends: bool) {
    if ends {
        let _ = tokio::time::timeout(FINISH, write.shutdown()).await;
    }
    let mut buf = vec![0u8; 64 * 1024];
    let _ = tokio::time::timeout(LINGER_RETIRED, async {
        while let Ok(n) = read.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    })
    .await;
    drop(write);
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
///
/// A `PING` goes at once too when the hearing asks for one (a spare link
/// opened beside this one), and when a tick of the clocks comes late, as
/// after a sleep of the host, which the monotonic clock of the bounds above
/// does not count: the far end's answer, or its silence, then tells within
/// the bound of a spare link whether the link outlived the sleep (T-663).
async fn beat(outbox: &Outbox, heard: &Mutex<Instant>, hearing: &Hearing) -> End {
    use podssh_ws::wake::{Reading, Wake};
    let mut wake = Wake::new(Reading::now());
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
        if now >= wake.due() && wake.tick(Reading::now()).is_some() {
            outbox.ping();
        }
        let next = (outbox.quiet_since() + PING_EVERY).min(last_heard + DEAD_AFTER).min(wake.due());
        // Never a wait of nothing: a clock that stands still would spin.
        let next = next.max(Instant::now() + Duration::from_millis(10));
        tokio::select! {
            () = tokio::time::sleep_until(next) => {}
            () = hearing.asking() => outbox.ping(),
        }
    }
}
