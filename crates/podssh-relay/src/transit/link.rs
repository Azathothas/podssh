//! A link of the transit road: the byte stream that two ends' WebSocket
//! messages carry once they met, which the resumable layer reads and
//! writes as it does a relay's leg. Two tasks pump it, as `podssh pipe ws:`
//! does: this side's bytes go out in binary messages of [`CHUNK`] bytes at
//! most, and each message that comes in is bytes, wherever it ends.
//!
//! The relay has no half-close: one side's Close ends both
//! (transit_server.py, `disconnect_partner`). So the end of this side's
//! bytes sends the Close, and what the far end sent before it still comes;
//! the far end's Close is the end of the link, and a dead connection or a
//! failure ends it with its reason, which a read then gives.
//!
//! A link of the forward road to the resumable layer of podssh's relay role
//! (T-173, `crate::forward_layer`) is the same byte stream over one
//! WebSocket, whose failures name the relay ([`Link::start_by`]).

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use podssh_ws::session::close_code_and_reason;
use podssh_ws::{frame, RelaySession, SessionError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::watch;

/// Each direction of the pipe between the link and its pumps.
const PIPE: usize = 256 * 1024;
/// The largest message sent.
pub const CHUNK: usize = 32 * 1024;

/// A link to the far end, through the transit relay.
pub struct Link {
    pipe: DuplexStream,
    /// Why the link failed, once it did; none for a clean end.
    why: Arc<Mutex<Option<String>>>,
}

impl Link {
    /// The link over `session`, whose meeting is done: `first` holds the far
    /// end's bytes that came with its proof, given before the rest.
    pub fn start<S>(session: RelaySession<S>, first: Vec<u8>) -> Link
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        Link::start_by(session, first, "the transit relay")
    }

    /// [`Link::start`], whose failures name `who`, the server at the other
    /// end of `session`.
    pub fn start_by<S>(session: RelaySession<S>, first: Vec<u8>, who: &'static str) -> Link
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let session = Arc::new(session);
        let why: Arc<Mutex<Option<String>>> = Arc::default();
        // Set once either pump ends: the other one stops too.
        let (ended, end) = watch::channel(false);
        let ended = Arc::new(ended);
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let (from_pipe, to_pipe) = tokio::io::split(theirs);
        tokio::spawn(up(session.clone(), from_pipe, why.clone(), ended.clone(), end.clone(), who));
        tokio::spawn(down(session, to_pipe, first, why.clone(), ended, end, who));
        Link { pipe: ours, why }
    }

    /// Why the link failed, once it did.
    pub fn failure(&self) -> Option<String> {
        lock(&self.why).clone()
    }
}

/// This side's bytes, out in binary messages; at their end, the Close.
async fn up<S>(
    session: Arc<RelaySession<S>>,
    mut from_pipe: tokio::io::ReadHalf<DuplexStream>,
    why: Arc<Mutex<Option<String>>>,
    ended: Arc<watch::Sender<bool>>,
    mut end: watch::Receiver<bool>,
    who: &'static str,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = tokio::select! {
            n = from_pipe.read(&mut buf) => n.unwrap_or(0),
            () = ended_by(&mut end) => return,
        };
        if n == 0 {
            // No half-close at the relay: the far end's bytes that were on
            // their way still come before its answer.
            let _ = session.send_close(1000, "").await;
            return;
        }
        if let Err(e) = session.send_binary(&buf[..n]).await {
            fail(&why, format!("sending to {who} failed: {e}"));
            let _ = ended.send(true);
            return;
        }
    }
}

/// The far end's bytes, in from each message, until its Close or a failure.
async fn down<S>(
    session: Arc<RelaySession<S>>,
    mut to_pipe: tokio::io::WriteHalf<DuplexStream>,
    first: Vec<u8>,
    why: Arc<Mutex<Option<String>>>,
    ended: Arc<watch::Sender<bool>>,
    mut end: watch::Receiver<bool>,
    who: &'static str,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let carried = async {
        if !first.is_empty() && to_pipe.write_all(&first).await.is_err() {
            return;
        }
        let liveness = session.watch_liveness(podssh_ws::LIVENESS_EVERY, podssh_ws::LIVENESS_ALLOWED);
        tokio::pin!(liveness);
        loop {
            let read = tokio::select! {
                read = session.read_frame() => read,
                dead = &mut liveness => {
                    fail(&why, dead.to_string());
                    return;
                }
            };
            let f = match read {
                Ok(f) => f,
                // After this side's Close, an end with no Close is the end.
                Err(SessionError::ClosedWithoutClose(_)) if session.close_sent() => return,
                Err(e) => {
                    fail(&why, e.to_string());
                    return;
                }
            };
            match f.opcode {
                frame::OPCODE_BINARY | frame::OPCODE_TEXT => {
                    if to_pipe.write_all(&f.payload).await.is_err() {
                        // The link was dropped: nobody reads any more.
                        return;
                    }
                }
                frame::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    if !matches!(code, None | Some(1000)) {
                        let reason = podssh_ws::text::one_line(&reason);
                        fail(&why, format!("{who} closed the link: {} {reason}", code.unwrap_or(0)));
                    }
                    return;
                }
                other => {
                    fail(&why, format!("{who} sent an unexpected frame (opcode {other:#x})"));
                    return;
                }
            }
        }
    };
    tokio::select! {
        () = carried => {}
        () = ended_by(&mut end) => {}
    }
    // The reason first, then the end that a read sees.
    let _ = ended.send(true);
    let _ = to_pipe.shutdown().await;
    let _ = session.send_close(1000, "").await;
}

/// Until the other pump ended the link.
async fn ended_by(end: &mut watch::Receiver<bool>) {
    let _ = end.wait_for(|e| *e).await;
}

fn fail(why: &Mutex<Option<String>>, text: String) {
    lock(why).get_or_insert(text);
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("transit::Link(..)")
    }
}

impl AsyncRead for Link {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let (before, room) = (buf.filled().len(), buf.remaining());
        match Pin::new(&mut self.pipe).poll_read(cx, buf) {
            // The end of the bytes: a failure says why.
            Poll::Ready(Ok(())) if room > 0 && buf.filled().len() == before => match self.failure() {
                Some(why) => Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, why))),
                None => Poll::Ready(Ok(())),
            },
            other => other,
        }
    }
}

impl AsyncWrite for Link {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.pipe).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_shutdown(cx)
    }
}
