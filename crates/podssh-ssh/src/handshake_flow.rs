//! What a road's layer carried under SSH (T-588): its bytes each way and
//! when it began, for the line of a handshake that does not finish on a
//! node's road, where SSH reads what the end-to-end channel gives it and the
//! channel what the resumable layer gives it.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// The bytes that a layer carried, and when it began to carry them.
#[derive(Debug, Default)]
pub struct Flow {
    from: AtomicU64,
    to: AtomicU64,
    opened: OnceLock<Instant>,
}

impl Flow {
    /// When the layer first read or wrote the stream that it carries: its
    /// handshake was done then.
    pub fn opened(&self) -> Option<Instant> {
        self.opened.get().copied()
    }

    /// The bytes from the far end, and to it.
    pub fn carried(&self) -> (u64, u64) {
        (self.from.load(Ordering::Relaxed), self.to.load(Ordering::Relaxed))
    }

    pub(crate) fn open(&self) {
        self.opened.get_or_init(Instant::now);
    }
}

/// The road under SSH, as the line of a handshake that does not finish names
/// it: the far end that answers SSH, the end that the layer reaches, what
/// the layer carried, and whether an end-to-end channel runs above it.
#[derive(Debug, Clone)]
pub struct Road {
    /// "the node's TARGET".
    pub far: String,
    /// "the node".
    pub end: String,
    pub flow: Arc<Flow>,
    pub channel: bool,
}

/// The stream that a layer carries, counted into a [`Flow`]: what the layer
/// reads of it goes to the far end, and what it writes came from it. With
/// no flow it counts nothing.
pub struct Counted<S> {
    inner: S,
    flow: Option<Arc<Flow>>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, flow: Option<Arc<Flow>>) -> Self {
        Counted { inner, flow }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Some(flow) = &self.flow {
            flow.open();
            flow.to.fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Some(flow) = &self.flow {
            flow.open();
            if let Poll::Ready(Ok(n)) = &polled {
                flow.from.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
