//! stdin and stdout of `podssh proxy` where the role's layer ends one
//! direction with `END` (T-632). The end of stdin is the layer's `END`, so a
//! target that reads to the end of its input gets that end and still answers
//! (`echo QUERY | podssh proxy HOST PORT`). The end of the target's bytes, at
//! which the layer shuts stdout, ends stdin too: the session then ends with
//! the target, as on the contract's road and as before, and a program that
//! keeps stdin open (OpenSSH, a terminal) is not left with a proxy that waits
//! on its input.

use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// `read` and `write` as one application of the layer, whose input ends
/// once its output is shut.
pub(crate) struct EndsWithReply<R, W> {
    read: R,
    write: W,
    /// The layer shut the output: the target's bytes ended.
    shut: bool,
    /// The task of a read that waits, woken when the output is shut.
    waiting: Option<Waker>,
}

impl<R, W> EndsWithReply<R, W> {
    pub(crate) fn new(read: R, write: W) -> Self {
        EndsWithReply { read, write, shut: false, waiting: None }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for EndsWithReply<R, W> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if this.shut {
            // The end of the input: nothing filled.
            return Poll::Ready(Ok(()));
        }
        let polled = Pin::new(&mut this.read).poll_read(cx, buf);
        if polled.is_pending() {
            this.waiting = Some(cx.waker().clone());
        }
        polled
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for EndsWithReply<R, W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        let shut = Pin::new(&mut this.write).poll_shutdown(cx);
        // An output that failed to shut is gone as well.
        if shut.is_ready() {
            this.shut = true;
            if let Some(waiting) = this.waiting.take() {
                waiting.wake();
            }
        }
        shut
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// The input passes until the output is shut; a read that waits then
    /// wakes with the end of the input, and the output's reader gets its end.
    #[tokio::test]
    async fn the_input_ends_when_the_output_is_shut() {
        let (input, mut typed) = tokio::io::duplex(64);
        let (output, mut shown) = tokio::io::duplex(64);
        let (mut read, mut write) = tokio::io::split(EndsWithReply::new(input, output));
        typed.write_all(b"query").await.unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(read.read(&mut buf).await.unwrap(), 5);
        // Nothing more is typed, and stdin stays open: the read waits.
        let waiting = tokio::spawn(async move {
            let mut rest = [0u8; 16];
            let n = read.read(&mut rest).await;
            (n, read)
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "the read waits for the input");
        write.write_all(b"reply").await.unwrap();
        write.shutdown().await.unwrap();
        let (n, mut read) =
            tokio::time::timeout(Duration::from_secs(5), waiting).await.expect("the shut woke the read").unwrap();
        assert_eq!(n.unwrap(), 0, "the end of the input");
        typed.write_all(b"late").await.unwrap();
        assert_eq!(read.read(&mut buf).await.unwrap(), 0, "no byte after the end");
        let mut got = Vec::new();
        shown.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"reply");
    }
}
