//! The stream of a cloud's road that says why the road ended (T-351), once,
//! before SSH reads the end of its stream: SSH alone can only say that the
//! connection closed, where IAP or the endpoint said why. The road's task
//! records its end before the stream ends, so the line comes first.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use podssh_ssh::Log;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// The stream to SSH, and the road's word on its end.
pub struct Told {
    inner: DuplexStream,
    why: Box<dyn Fn() -> Option<String> + Send>,
    log: Arc<Log>,
    told: bool,
}

impl Told {
    /// `inner`, whose end `why` explains: `None` for an ordinary end.
    pub fn new(inner: DuplexStream, why: impl Fn() -> Option<String> + Send + 'static, log: Arc<Log>) -> Told {
        Told { inner, why: Box::new(why), log, told: false }
    }

    fn tell(&mut self) {
        if !self.told {
            self.told = true;
            if let Some(line) = (self.why)() {
                self.log.error(&line);
            }
        }
    }
}

impl AsyncRead for Told {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let (before, room) = (buf.filled().len(), buf.remaining());
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        // The end of the stream: a read with room that took nothing.
        let end = match &polled {
            Poll::Ready(Ok(())) => room > 0 && buf.filled().len() == before,
            Poll::Ready(Err(_)) => true,
            Poll::Pending => false,
        };
        if end {
            this.tell();
        }
        polled
    }
}

impl AsyncWrite for Told {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The line goes once, at the end of the stream and not before it; an
    /// ordinary end says nothing.
    #[tokio::test]
    async fn told_says_the_end_once_at_the_end() {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let said = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = said.clone();
        let why = move || {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some("the road ended".to_string())
        };
        let mut told = Told::new(ours, why, Arc::new(Log::new(podssh_ssh::LogLevel::Quiet)));
        theirs.write_all(b"bytes").await.unwrap();
        let mut buf = [0u8; 5];
        told.read_exact(&mut buf).await.unwrap();
        assert_eq!(said.load(std::sync::atomic::Ordering::SeqCst), 0, "not before the end");
        drop(theirs);
        let mut rest = Vec::new();
        told.read_to_end(&mut rest).await.unwrap();
        assert_eq!(told.read(&mut buf).await.unwrap(), 0);
        assert_eq!(said.load(std::sync::atomic::Ordering::SeqCst), 1, "once");
    }
}
