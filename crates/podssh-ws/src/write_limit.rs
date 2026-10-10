//! A stream whose write fails when it makes no progress for a while
//! (T-227): a peer that stops reading below SSH, as a TCP zero window that
//! never opens, ends the session with the rule of the relay leg
//! ([`crate::client::WRITE_TIMEOUT`]), never a wait for ever. Reads pass as
//! they are: a quiet peer is not a stuck one.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// `inner`, with a limit on each write, flush and shutdown that waits.
pub struct WriteLimit<S> {
    inner: S,
    limit: Duration,
    /// Armed by the first wait of a write; each byte that goes resets it.
    stall: Option<Pin<Box<Sleep>>>,
}

impl<S> WriteLimit<S> {
    pub fn new(inner: S, limit: Duration) -> Self {
        WriteLimit { inner, limit, stall: None }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// The inner stream waits: so does this, until the limit, armed now when
    /// it was not, ends the wait with an error.
    fn waiting<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        let limit = self.limit;
        let stall = self.stall.get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        match stall.as_mut().poll(cx) {
            Poll::Ready(()) => self.done(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("a write made no progress for {} s: the peer reads nothing", limit.as_secs()),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// The end of a wait, with a result or an error: the next wait starts its
    /// own count.
    fn done<T>(&mut self, result: io::Result<T>) -> Poll<io::Result<T>> {
        self.stall = None;
        Poll::Ready(result)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteLimit<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteLimit<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(result) => this.done(result),
            Poll::Pending => this.waiting(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(result) => this.done(result),
            Poll::Pending => this.waiting(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(result) => this.done(result),
            Poll::Pending => this.waiting(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(result) => this.done(result),
            Poll::Pending => this.waiting(cx),
        }
    }
}
