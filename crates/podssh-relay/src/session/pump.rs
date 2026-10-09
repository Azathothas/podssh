//! An established link over tokio streams: the application's bytes out as
//! `DATA`, the peer's records in, both ends of the session at once.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::decode::Decoder;
use super::link::{Event, Link, LinkError};
use super::record::{Record, MAX_DATA};

/// How much of the application's bytes one read takes: a `DATA` record that
/// fits a frame of the reverse road with its id.
const CHUNK: usize = 32 * 1024;
/// How long the link may take to end after this side's `CLOSE`.
const LINGER: Duration = Duration::from_secs(10);

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

/// Carry the session between `app` and `link` until either ends. `decoder`
/// holds what the handshake read past its last record.
pub(crate) async fn run<A, L>(app: A, link: L, decoder: Decoder, state: Link) -> Ended
where
    A: AsyncRead + AsyncWrite + Send,
    L: AsyncRead + AsyncWrite + Send,
{
    let (mut app_r, mut app_w) = tokio::io::split(app);
    let (link_r, link_w) = tokio::io::split(link);
    let state = Arc::new(Mutex::new(state));
    let writer = tokio::sync::Mutex::new(link_w);

    // Both directions live in this block, so that neither holds the writer
    // when it ends.
    let (end, close) = {
        let up = up(&mut app_r, &writer, &state);
        let down = down(&mut app_w, link_r, decoder, &writer, &state);
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
        }
    };
    if close {
        let _ = send_close(&mut *writer.lock().await).await;
    }
    // The application learns that no more bytes come, whatever the reason.
    let _ = app_w.shutdown().await;
    let state = lock(&state);
    Ended { end, received: state.received(), sent: state.sent() }
}

fn lock(state: &Mutex<Link>) -> std::sync::MutexGuard<'_, Link> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

/// The application's bytes out: `None` when it ended them and `CLOSE` went
/// out, else why the link failed.
async fn up<R, W>(app: &mut R, writer: &tokio::sync::Mutex<W>, state: &Mutex<Link>) -> Option<End>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK.min(MAX_DATA)];
    let mut out = Vec::with_capacity(CHUNK + 16);
    loop {
        let n = match app.read(&mut buf).await {
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

/// The peer's records in, until the link or the session ends.
async fn down<W, R, LW>(
    app: &mut W,
    mut link: R,
    mut decoder: Decoder,
    writer: &tokio::sync::Mutex<LW>,
    state: &Mutex<Link>,
) -> End
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    LW: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        loop {
            let record = match decoder.next() {
                Ok(Some(record)) => record,
                Ok(None) => break,
                Err(e) => return End::Broken(lock(state).fail(e.into())),
            };
            let event = lock(state).on_record(record);
            match event {
                Ok(Event::Deliver(bytes)) => {
                    // An application that stopped reading has ended the
                    // session on its side; its own end says why.
                    if app.write_all(&bytes).await.is_err() {
                        return End::LocalEnd;
                    }
                }
                Ok(Event::Reply(record)) => {
                    if let Ok(bytes) = record.to_bytes() {
                        if let Err(e) = writer.lock().await.write_all(&bytes).await {
                            return End::Lost(Some(e));
                        }
                    }
                }
                Ok(Event::Closed(reason)) => return End::Closed(reason),
                Ok(Event::Nothing) => {}
                Err(e) => return End::Broken(e),
            }
        }
        match link.read(&mut buf).await {
            Ok(0) => return End::Lost(None),
            Ok(n) => decoder.push(&buf[..n]),
            Err(e) => return End::Lost(Some(e)),
        }
    }
}
