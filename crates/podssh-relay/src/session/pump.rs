//! One link of a session over tokio streams: the application's bytes out as
//! `DATA`, the peer's records in, both ways at once.
//!
//! With a replay buffer, the application's bytes go out only while the
//! buffer has room: a full buffer makes the writer wait for an `ACK`, so SSH
//! waits and its window stops the far side (T-152). The peer's bytes are
//! acknowledged each 64 KiB, and 200 ms after any that are not.
//!
//! A link can end at any await: the application stays open, and what the
//! session needs for the next link (its offsets, its buffer, the bytes not
//! yet written to the application) is in the [`Carry`] that the caller
//! keeps (T-153).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::decode::Decoder;
use super::link::{Event, Link, LinkError};
use super::record::{Record, MAX_DATA};

/// How much of the application's bytes one read takes: a `DATA` record that
/// fits a frame of the reverse road with its id.
const CHUNK: usize = 32 * 1024;
/// How long the link may take to end after this side's `CLOSE`.
const LINGER: Duration = Duration::from_secs(10);
/// How long bytes wait for their acknowledgement when fewer than 64 KiB came.
pub const ACK_DELAY: Duration = Duration::from_millis(200);

/// How a link of the session ended.
#[derive(Debug)]
pub enum End {
    /// This side's application ended its bytes, and `CLOSE` went out.
    LocalEnd,
    /// The peer ended the session with `CLOSE` and this reason.
    Closed(String),
    /// The link ended with no `CLOSE`: a loss, which a resume can carry over
    /// (T-153).
    Lost(Option<std::io::Error>),
    /// The link carried what ends it: a gap, bytes that are not records, a
    /// `REFUSE`.
    Broken(LinkError),
    /// This side was told to stop: the session went on to a newer link.
    Stopped,
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
            End::Lost(_) | End::Stopped => true,
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
}

impl Carry {
    pub fn new(link: Link) -> Carry {
        Carry { state: Arc::new(Mutex::new(link)), undelivered: Vec::new() }
    }

    /// The bytes received that the application has not taken yet.
    pub fn undelivered(&self) -> usize {
        self.undelivered.len()
    }
}

/// Carry the session between `app` and `link` until the link or the session
/// ends, or `stop` is notified. `decoder` holds what the handshake read past
/// its last record. The application is not shut: the caller does that when
/// the session ends, and keeps it open for the next link when it does not.
pub async fn run<A, L>(app: &mut A, link: L, decoder: Decoder, carry: &mut Carry, stop: Option<&Notify>) -> Ended
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    L: AsyncRead + AsyncWrite + Send,
{
    let (mut app_r, mut app_w) = tokio::io::split(app);
    let (link_r, link_w) = tokio::io::split(link);
    let writer = tokio::sync::Mutex::new(link_w);
    let room = Notify::new();
    let never = Notify::new();
    let stop = stop.unwrap_or(&never);
    let Carry { state, undelivered } = carry;

    // Both directions live in this block, so that neither holds the writer
    // when it ends.
    let (end, close) = {
        let up = up(&mut app_r, &writer, state, &room);
        let down = down(&mut app_w, link_r, decoder, &writer, state, &room, undelivered);
        tokio::pin!(up);
        tokio::pin!(down);
        tokio::select! {
            // An application that stopped reading ended the session too, and
            // `CLOSE` says so.
            end = &mut down => {
                let close = matches!(end, End::LocalEnd);
                (end, close)
            }
            up_end = &mut up => match up_end {
                // The application is done and `CLOSE` is out: the peer ends
                // the link in turn, or the wait does.
                None => match tokio::time::timeout(LINGER, &mut down).await {
                    Ok(End::Closed(_) | End::Lost(_)) | Err(_) => (End::LocalEnd, false),
                    Ok(other) => (other, false),
                },
                Some(failed) => (failed, false),
            },
            _ = stop.notified() => (End::Stopped, false),
        }
    };
    if close {
        let _ = send_close(&mut *writer.lock().await).await;
    }
    let state = lock(state);
    Ended { end, received: state.received(), sent: state.sent() }
}

fn lock(state: &Mutex<Link>) -> std::sync::MutexGuard<'_, Link> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

/// The application's bytes out: `None` when it ended them and `CLOSE` went
/// out, else why the link failed. It reads only what the replay buffer has
/// room for, and waits for an acknowledgement when it has none. A byte read
/// is in the buffer before any await, so a link that ends loses none.
async fn up<R, W>(app: &mut R, writer: &tokio::sync::Mutex<W>, state: &Mutex<Link>, room: &Notify) -> Option<End>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK.min(MAX_DATA)];
    let mut out = Vec::with_capacity(CHUNK + 16);
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
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        out.clear();
        if let Err(e) = lock(state).send(&buf[..n], &mut out) {
            return Some(End::Broken(e));
        }
        if let Err(e) = writer.lock().await.write_all(&out).await {
            return Some(End::Lost(Some(e)));
        }
    }
    match send_close(&mut *writer.lock().await).await {
        Ok(()) => None,
        Err(e) => Some(End::Lost(Some(e))),
    }
}

/// `CLOSE` with no reason: the session ends, not only this link. Then the
/// link's write side is shut, so the transport ends it in turn (the
/// operator leg sends its Close after the bytes before it).
async fn send_close<W: AsyncWrite + Unpin>(writer: &mut W) -> std::io::Result<()> {
    if let Ok(bytes) = (Record::Close { reason: String::new() }).to_bytes() {
        writer.write_all(&bytes).await?;
    }
    writer.shutdown().await
}

async fn send<W: AsyncWrite + Unpin>(writer: &tokio::sync::Mutex<W>, record: &Record) -> Result<(), End> {
    if let Ok(bytes) = record.to_bytes() {
        writer.lock().await.write_all(&bytes).await.map_err(|e| End::Lost(Some(e)))?;
    }
    Ok(())
}

/// Write the bytes kept for the application in steps that a cancel cannot
/// cut: each byte written leaves the buffer before the next await.
async fn deliver<W: AsyncWrite + Unpin>(app: &mut W, undelivered: &mut Vec<u8>) -> std::io::Result<()> {
    while !undelivered.is_empty() {
        let n = app.write(undelivered).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        undelivered.drain(..n);
    }
    app.flush().await
}

/// The peer's records in, until the link or the session ends.
async fn down<W, R, LW>(
    app: &mut W,
    mut link: R,
    mut decoder: Decoder,
    writer: &tokio::sync::Mutex<LW>,
    state: &Mutex<Link>,
    room: &Notify,
    undelivered: &mut Vec<u8>,
) -> End
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    LW: AsyncWrite + Unpin,
{
    // What an earlier link received and could not write yet goes first.
    if deliver(app, undelivered).await.is_err() {
        return End::LocalEnd;
    }
    let mut buf = vec![0u8; 64 * 1024];
    // When the bytes not yet acknowledged must be.
    let mut ack_at: Option<Instant> = None;
    loop {
        loop {
            let record = match decoder.next() {
                Ok(Some(record)) => record,
                Ok(None) => break,
                Err(e) => return End::Broken(lock(state).fail(e.into())),
            };
            let acknowledges = matches!(record, Record::Ack { .. } | Record::Pong { .. });
            let event = lock(state).on_record(record);
            match event {
                Ok(Event::Deliver(bytes)) => {
                    undelivered.extend_from_slice(&bytes);
                    // An application that stopped reading has ended the
                    // session on its side; its own end says why.
                    if deliver(app, undelivered).await.is_err() {
                        return End::LocalEnd;
                    }
                }
                Ok(Event::Reply(record)) => {
                    if let Err(end) = send(writer, &record).await {
                        return end;
                    }
                }
                Ok(Event::Closed(reason)) => return End::Closed(reason),
                Ok(Event::Nothing) => {}
                Err(e) => return End::Broken(e),
            }
            if acknowledges {
                room.notify_one();
            }
        }
        // 64 KiB or more: acknowledged at once; fewer: after the delay.
        let due = {
            let mut state = lock(state);
            if state.ack_due() {
                Some(state.ack())
            } else {
                None
            }
        };
        if let Some(ack) = due {
            ack_at = None;
            if let Err(end) = send(writer, &ack).await {
                return end;
            }
        } else if ack_at.is_none() && lock(state).ack_pending() {
            ack_at = Some(Instant::now() + ACK_DELAY);
        }
        let read = match ack_at {
            Some(at) => tokio::select! {
                read = link.read(&mut buf) => read,
                _ = tokio::time::sleep_until(at) => {
                    ack_at = None;
                    let ack = {
                        let mut state = lock(state);
                        state.ack_pending().then(|| state.ack())
                    };
                    if let Some(ack) = ack {
                        if let Err(end) = send(writer, &ack).await {
                            return end;
                        }
                    }
                    continue;
                }
            },
            None => link.read(&mut buf).await,
        };
        match read {
            Ok(0) => return End::Lost(None),
            Ok(n) => decoder.push(&buf[..n]),
            Err(e) => return End::Lost(Some(e)),
        }
    }
}
