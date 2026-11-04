//! The application's bytes out, as `DATA` for the writer, within the room of
//! the replay buffer and the window of the link's road (T-152, T-443).

use std::sync::Mutex;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{mpsc, Notify};

use super::super::link::Link;
use super::super::record::MAX_DATA;
use super::{lock, End, CHUNK};

/// The end of the first record in `records`: a type byte, a 32-bit length,
/// the body.
fn first_record(records: &[u8]) -> usize {
    match records.get(1..5) {
        Some(len) => (5 + u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize).min(records.len()),
        None => records.len(),
    }
}

/// Wait until `fits` holds of the session's state: each acknowledgement
/// looks again.
async fn until(state: &Mutex<Link>, room: &Notify, fits: impl Fn(&Link) -> bool) {
    loop {
        // Asked for before the check, so that an `ACK` between the two is
        // not missed.
        let freed = room.notified();
        let fit = fits(&lock(state));
        if fit {
            return;
        }
        freed.await;
    }
}

/// The application's bytes out, as `DATA` for the writer: first the records
/// of a resume (`again`), a record at a time, then the application's new
/// bytes. `None` when the application ended them, which `CLOSE` or `END`
/// then says (T-632), else why the session cannot go on. It reads only what
/// the replay buffer has room for, and what `window` lets the link carry
/// with no acknowledgement (T-443), and waits for an acknowledgement when it
/// has none. A byte read is in the buffer before any await, so a link that
/// ends loses none. An application that `ended` its bytes on an earlier link
/// is not read again: its end goes again after the records of the resume.
pub(super) async fn run<R>(
    app: &mut R,
    again: Vec<u8>,
    data: mpsc::Sender<Vec<u8>>,
    state: &Mutex<Link>,
    room: &Notify,
    window: Option<usize>,
    ended: bool,
) -> Option<End>
where
    R: AsyncRead + Unpin,
{
    // The records of a resume are in the replay buffer already: a link that
    // ends before they go out loses none, and the next resume sends them.
    // Each waits for the window: a buffer filled on another road can hold
    // more than this link may carry at once.
    let mut rest = &again[..];
    while !rest.is_empty() {
        let end = first_record(rest);
        let record = &rest[..end];
        until(state, room, |link| link.again_fits(record, window)).await;
        if data.send(record.to_vec()).await.is_err() {
            return std::future::pending().await;
        }
        rest = &rest[end..];
    }
    // An input that ended may not end twice (a terminal waits again).
    if ended {
        return None;
    }
    let mut buf = vec![0u8; CHUNK.min(MAX_DATA)];
    loop {
        let space = loop {
            // Asked for before the check, so that an `ACK` between the two is
            // not missed.
            let freed = room.notified();
            let space = lock(state).room_within(window);
            if space > 0 {
                break space;
            }
            freed.await;
        };
        let want = buf.len().min(space);
        let n = match app.read(&mut buf[..want]).await {
            Ok(0) => return None,
            // No end of one direction: the application is gone, and the
            // session ends with `CLOSE` (T-632).
            Err(_) => {
                lock(state).app_failed();
                return None;
            }
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
