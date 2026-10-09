//! The link's one writer, and the records that wait for it (T-262).
//!
//! The reader and the heartbeat never write: they leave an `ACK`, a `PONG`
//! or a `PING` here, and the writer sends it before the next `DATA`. A
//! reader that waited for the writer, stalled on a full link, would stop
//! reading; the peer would then stall in the same way, and neither link
//! would move again. `DATA` comes from the application's side through a
//! channel that holds one batch, so that side waits while the link is full,
//! and holds nothing that the reader needs.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use super::super::link::Link;
use super::super::record::Record;
use super::{lock, Watch};

/// The last record that the pump asks the writer for, at a record boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Finish {
    /// `CLOSE`: the session ends at this side, and the peer learns it.
    Close,
    /// `RETIRE`: this link ends, and the session goes on over another
    /// (T-155).
    Retire,
}

/// How the writer stopped.
#[derive(Debug)]
pub(super) enum Written {
    /// The application ended its bytes, and `CLOSE` went out after the last
    /// of them. The link stays open for the peer's answer.
    Closed,
    /// The pump's last record went out, and the write side is shut.
    Finished,
    /// A write failed: the link carries nothing more from this side.
    Failed(std::io::Error),
}

/// What waits for the writer, and when it last wrote.
pub(super) struct Outbox {
    /// When the writer last wrote a record.
    sent: Mutex<Instant>,
    /// When the heartbeat last asked for a `PING`.
    pinged: Mutex<Instant>,
    /// The bytes received are due for an `ACK`; the writer takes the offset
    /// when it writes it, so the newest goes out.
    ack: AtomicBool,
    /// The `PONG` that answers the last `PING`.
    pong: Mutex<Option<Record>>,
    /// The value of a `PING` to send; 0 is none.
    ping: AtomicU64,
    /// The values of the `PING`s asked for so far.
    pings: AtomicU64,
    finish: Mutex<Option<Finish>>,
    /// Whether this side's `CLOSE` went out on this link.
    closed: AtomicBool,
    /// Wakes the writer for each of the above.
    wake: Notify,
}

impl Outbox {
    pub(super) fn new() -> Outbox {
        let now = Instant::now();
        Outbox {
            sent: Mutex::new(now),
            pinged: Mutex::new(now),
            ack: AtomicBool::new(false),
            pong: Mutex::new(None),
            ping: AtomicU64::new(0),
            pings: AtomicU64::new(0),
            finish: Mutex::new(None),
            closed: AtomicBool::new(false),
            wake: Notify::new(),
        }
    }

    /// When the writer last wrote, or the heartbeat last asked for a `PING`:
    /// the start of the quiet that the next `PING` waits for.
    pub(super) fn quiet_since(&self) -> Instant {
        (*lock(&self.sent)).max(*lock(&self.pinged))
    }

    /// An `ACK` of each byte received, at the writer's next turn.
    pub(super) fn ack(&self) {
        self.ack.store(true, Ordering::SeqCst);
        self.wake.notify_one();
    }

    /// Whether an `ACK` waits for the writer.
    pub(super) fn acking(&self) -> bool {
        self.ack.load(Ordering::SeqCst)
    }

    /// A `PONG` to send; a newer one replaces one that still waits.
    pub(super) fn reply(&self, record: Record) {
        *lock(&self.pong) = Some(record);
        self.wake.notify_one();
    }

    /// A `PING`, with the next value.
    pub(super) fn ping(&self) {
        let value = self.pings.fetch_add(1, Ordering::SeqCst) + 1;
        self.ping.store(value, Ordering::SeqCst);
        *lock(&self.pinged) = Instant::now();
        self.wake.notify_one();
    }

    /// Stop at the next record boundary, after `last`.
    pub(super) fn finish(&self, last: Finish) {
        *lock(&self.finish) = Some(last);
        self.wake.notify_one();
    }

    /// Whether this side's `CLOSE` went out on this link.
    pub(super) fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// The next small record that waits: a `PONG` first, as the peer's
    /// heartbeat waits for it, then an `ACK`, then a `PING`.
    fn next(&self, state: &Mutex<Link>) -> Option<Record> {
        if let Some(pong) = lock(&self.pong).take() {
            return Some(pong);
        }
        if self.ack.swap(false, Ordering::SeqCst) {
            let mut state = lock(state);
            if state.ack_pending() {
                return Some(state.ack());
            }
        }
        match self.ping.swap(0, Ordering::SeqCst) {
            0 => None,
            value => Some(Record::Ping { value }),
        }
    }
}

/// Write one record's bytes, and note when, and how many.
async fn put<W: AsyncWrite + Unpin>(link: &mut W, bytes: &[u8], outbox: &Outbox, watch: &Watch) -> std::io::Result<()> {
    link.write_all(bytes).await?;
    *lock(&outbox.sent) = Instant::now();
    watch.count(bytes.len() as u64);
    Ok(())
}

fn bytes_of(record: &Record) -> Vec<u8> {
    // The records that the writer makes have small bodies, which always fit.
    record.to_bytes().unwrap_or_default()
}

/// The writer: the pump's last record when it asks for one, else the small
/// records that wait, else the application's next `DATA`; at the end of the
/// application's bytes, `CLOSE`.
pub(super) async fn write<W>(
    link: &mut W,
    data: &mut mpsc::Receiver<Vec<u8>>,
    outbox: &Outbox,
    state: &Mutex<Link>,
    watch: &Watch,
) -> Written
where
    W: AsyncWrite + Unpin,
{
    loop {
        // Asked for before the checks, so that a record left between the
        // two wakes the writer.
        let woken = outbox.wake.notified();
        let last = lock(&outbox.finish).take();
        if let Some(last) = last {
            let record = match last {
                Finish::Close => Record::Close { reason: String::new() },
                Finish::Retire => Record::Retire,
            };
            if last == Finish::Close {
                outbox.closed.store(true, Ordering::SeqCst);
            }
            let written = async {
                put(link, &bytes_of(&record), outbox, watch).await?;
                link.shutdown().await
            };
            return match written.await {
                Ok(()) => Written::Finished,
                Err(e) => Written::Failed(e),
            };
        }
        if let Some(record) = outbox.next(state) {
            if let Err(e) = put(link, &bytes_of(&record), outbox, watch).await {
                return Written::Failed(e);
            }
            continue;
        }
        tokio::select! {
            biased;
            _ = woken => {}
            batch = data.recv() => match batch {
                Some(bytes) => {
                    if let Err(e) = put(link, &bytes, outbox, watch).await {
                        return Written::Failed(e);
                    }
                }
                // The application ended its bytes: `CLOSE` after the last.
                None => {
                    outbox.closed.store(true, Ordering::SeqCst);
                    let close = Record::Close { reason: String::new() };
                    return match put(link, &bytes_of(&close), outbox, watch).await {
                        Ok(()) => Written::Closed,
                        Err(e) => Written::Failed(e),
                    };
                }
            },
        }
    }
}
