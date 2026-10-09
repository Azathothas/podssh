//! The peer's records in, until the link or the session ends. The reader
//! never writes to the link: an answer or an acknowledgement waits in the
//! outbox for the writer (T-262), so the reader goes on reading while the
//! writer waits for room on the link.

use std::sync::Mutex;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::super::decode::Decoder;
use super::super::link::{Event, Link};
use super::super::record::Record;
use super::outbox::Outbox;
use super::{lock, End, Watch, ACK_DELAY};

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

/// Read the link until it ends, and give the application each new byte.
/// `heard` is when the far end's last bytes came.
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
    watch: &Watch,
) -> End
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
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
                Ok(Event::Reply(record)) => outbox.reply(record),
                Ok(Event::Closed(reason)) => return End::Closed(reason),
                Ok(Event::Retired) => return End::Retired,
                Ok(Event::Nothing) => {}
                Err(e) => return End::Broken(e),
            }
            if acknowledges {
                room.notify_one();
            }
        }
        // 64 KiB or more: acknowledged at the writer's next turn; fewer:
        // after the delay, unless an `ACK` already waits for the writer.
        if lock(state).ack_due() {
            ack_at = None;
            outbox.ack();
        } else if ack_at.is_none() && !outbox.acking() && lock(state).ack_pending() {
            ack_at = Some(Instant::now() + ACK_DELAY);
        }
        let read = match ack_at {
            Some(at) => tokio::select! {
                read = link.read(&mut buf) => read,
                _ = tokio::time::sleep_until(at) => {
                    ack_at = None;
                    if lock(state).ack_pending() {
                        outbox.ack();
                    }
                    continue;
                }
            },
            None => link.read(&mut buf).await,
        };
        match read {
            Ok(0) => return End::Lost(None),
            Ok(n) => {
                *lock(heard) = Instant::now();
                watch.count(n as u64);
                decoder.push(&buf[..n]);
            }
            Err(e) => return End::Lost(Some(e)),
        }
    }
}
