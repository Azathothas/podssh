//! A connection of the test's server that a command can cut (T-461): once
//! cut, its reads end and its writes fail, so russh drops the stream with
//! no DISCONNECT, as the relay's close of a session at its cap leaves the
//! SSH inside it. `cut N` gives the exit status 0, then N bytes, then the
//! cut, with no EOF and no Close, as #84's server did; `cut-eof N` sends its
//! EOF after the bytes, then the cut.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use russh::server::Session;
use russh::ChannelId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How long after its last message a command cuts: the session's loop has
/// written each one by then, and the client has read them.
const SETTLE: Duration = Duration::from_secs(2);
/// The size of each block of `cut`'s bytes.
const BLOCK: usize = 32 * 1024;

/// The switch of one connection; each clone cuts the same one.
#[derive(Clone, Default)]
pub struct Cut(Arc<State>);

#[derive(Default)]
struct State {
    cut: AtomicBool,
    /// The read that waits, woken by the cut: a client that sends nothing
    /// would keep it waiting for ever.
    waker: Mutex<Option<Waker>>,
}

impl Cut {
    pub fn now(&self) {
        self.0.cut.store(true, Ordering::SeqCst);
        if let Some(waker) = self.0.waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    fn is_cut(&self) -> bool {
        self.0.cut.load(Ordering::SeqCst)
    }
}

/// The connection's stream, with its switch.
pub struct Cuttable<S> {
    inner: S,
    cut: Cut,
}

impl<S> Cuttable<S> {
    pub fn new(inner: S, cut: Cut) -> Self {
        Cuttable { inner, cut }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Cuttable<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.cut.is_cut() {
            return Poll::Ready(Ok(()));
        }
        *self.cut.0.waker.lock().unwrap() = Some(cx.waker().clone());
        // A cut between the look and the waker's place is seen here.
        if self.cut.is_cut() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Cuttable<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        if self.cut.is_cut() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.cut.is_cut() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `cut N` and `cut-eof N`; `None` for another command.
pub(super) fn run(
    command: &str,
    link: &Cut,
    channel: ChannelId,
    session: &mut Session,
) -> Option<Result<(), russh::Error>> {
    let mut words = command.split_whitespace();
    let eof = match words.next()? {
        "cut" => false,
        "cut-eof" => true,
        _ => return None,
    };
    let bytes: usize = words.next()?.parse().ok()?;
    let (handle, link) = (session.handle(), link.clone());
    // From a task: the session's loop must go on, to take the client's
    // window adjustments while the bytes go out.
    tokio::spawn(async move {
        let _ = handle.exit_status_request(channel, 0).await;
        let mut left = bytes;
        while left > 0 {
            let n = left.min(BLOCK);
            if handle.data(channel, vec![0x63_u8; n]).await.is_err() {
                return;
            }
            left -= n;
        }
        if eof {
            let _ = handle.eof(channel).await;
        }
        tokio::time::sleep(SETTLE).await;
        link.now();
    });
    Some(Ok(()))
}
