//! The peer's records in, until the link or the session ends. The reader
//! never writes to the link: an answer or an acknowledgement waits in the
//! outbox for the writer (T-262), so the reader goes on reading while the
//! writer waits for room on the link. It goes on reading while the
//! application is slow too (T-387): the peer's acknowledgements free this
//! side's replay buffer, and an application that waits for this side's own
//! bytes (an echo, a shell) would otherwise wait on a reader that waits on
//! it, until the link was taken for dead.

use std::sync::Mutex;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::super::decode::Decoder;
use super::super::hearing::Hearing;
use super::super::link::{Event, Link};
use super::super::record::Record;
use super::super::replay::MAX_CAPACITY;
use super::outbox::Outbox;
use super::{lock, End, Watch, ACK_DELAY};

/// The most bytes held for a slow application before the link is no longer
/// read. An acknowledgement covers the bytes written (T-387), so a peer with
/// a replay buffer sends at most its window past them, and twice the largest
/// window (once more after a resume, whose offset covers the bytes held) is
/// never met; a peer with no replay buffer meets it, and waits.
const HOLD_MAX: usize = 2 * MAX_CAPACITY + (1 << 20);

/// Write the bytes kept for the application in steps that a cancel cannot
/// cut: each byte written leaves the buffer before the next await.
async fn deliver<W: AsyncWrite + Unpin>(
    app: &mut W,
    undelivered: &mut Vec<u8>,
    state: &Mutex<Link>,
) -> std::io::Result<()> {
    while !undelivered.is_empty() {
        let n = app.write(undelivered).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        undelivered.drain(..n);
        lock(state).holding(undelivered.len() as u64);
    }
    app.flush().await
}

/// The end `end`, once the bytes held for the application reached it: the
/// peer's last bytes before a `CLOSE`, and each byte before a broken record.
/// An application that stopped reading has ended the session on its side,
/// and its own end says why.
async fn after_delivery<W: AsyncWrite + Unpin>(
    app: &mut W,
    undelivered: &mut Vec<u8>,
    state: &Mutex<Link>,
    end: End,
) -> End {
    match deliver(app, undelivered, state).await {
        Ok(()) => end,
        Err(_) => End::LocalEnd,
    }
}

/// What happened while the reader waited.
enum Next {
    Wrote(std::io::Result<usize>),
    Read(std::io::Result<usize>),
    AckDue,
}

/// Read the link until it ends, and give the application each new byte.
/// `heard` is when the far end's last bytes came on this link; `hearing`,
/// the same across the session's links, for a notice of silence (T-302).
#[allow(clippy::too_many_arguments)]
pub(super) async fn run<W, R>(
    app: &mut W,
    mut link: R,
    mut decoder: Decoder,
    outbox: &Outbox,
    state: &Mutex<Link>,
    room: &Notify,
    undelivered: &mut Vec<u8>,
    heard: &Mutex<Instant>,
    hearing: &Hearing,
    watch: &Watch,
) -> End
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    // When the bytes not yet acknowledged must be.
    let mut ack_at: Option<Instant> = None;
    loop {
        loop {
            let record = match decoder.next() {
                Ok(Some(record)) => record,
                Ok(None) => break,
                Err(e) => {
                    let end = End::Broken(lock(state).fail(e.into()));
                    return after_delivery(app, undelivered, state, end).await;
                }
            };
            let acknowledges = matches!(record, Record::Ack { .. } | Record::Pong { .. });
            // The bytes held are said under the same lock as the record, so
            // that no acknowledgement in between covers bytes not written.
            let event = {
                let mut link = lock(state);
                let event = link.on_record(record);
                if let Ok(Event::Deliver(bytes)) = &event {
                    link.holding((undelivered.len() + bytes.len()) as u64);
                }
                event
            };
            match event {
                // Held for the application, which takes it below, while the
                // link is read on.
                Ok(Event::Deliver(bytes)) => undelivered.extend_from_slice(&bytes),
                Ok(Event::Reply(record)) => outbox.reply(record),
                Ok(Event::Closed(reason)) => {
                    return after_delivery(app, undelivered, state, End::Closed(reason)).await;
                }
                Ok(Event::Retired) => return End::Retired,
                Ok(Event::Nothing) => {}
                Err(e) => return after_delivery(app, undelivered, state, End::Broken(e)).await,
            }
            if acknowledges {
                room.notify_one();
            }
        }
        // 64 KiB or more written: acknowledged at the writer's next turn;
        // fewer: after the delay, unless an `ACK` already waits for the writer.
        if lock(state).ack_due() {
            ack_at = None;
            outbox.ack();
        } else if ack_at.is_none() && !outbox.acking() && lock(state).ack_pending() {
            ack_at = Some(Instant::now() + ACK_DELAY);
        }
        let reading = undelivered.len() < HOLD_MAX;
        // The application first: bytes wait here only while it is slow.
        let next = tokio::select! {
            biased;
            wrote = app.write(undelivered), if !undelivered.is_empty() => Next::Wrote(wrote),
            read = link.read(&mut buf), if reading => Next::Read(read),
            () = sleep_until_some(ack_at) => Next::AckDue,
        };
        match next {
            Next::Wrote(Ok(n)) if n > 0 => {
                undelivered.drain(..n);
                lock(state).holding(undelivered.len() as u64);
                if undelivered.is_empty() && app.flush().await.is_err() {
                    return End::LocalEnd;
                }
            }
            // An application that stopped reading has ended the session on
            // its side; its own end says why.
            Next::Wrote(_) => return End::LocalEnd,
            Next::AckDue => {
                ack_at = None;
                if lock(state).ack_pending() {
                    outbox.ack();
                }
            }
            Next::Read(Ok(0)) => return End::Lost(None),
            Next::Read(Ok(n)) => {
                *lock(heard) = Instant::now();
                hearing.heard();
                watch.count(n as u64);
                decoder.push(&buf[..n]);
            }
            Next::Read(Err(e)) => return End::Lost(Some(e)),
        }
    }
}

/// The time `at`, or never.
async fn sleep_until_some(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
