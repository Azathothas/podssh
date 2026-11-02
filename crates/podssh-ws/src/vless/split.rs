//! A stream of two halves, as XHTTP's stream-up and packet-up carry a
//! session on two requests: the target's bytes from one, this side's to the
//! other. A write that fails after the upload failed says why the upload
//! failed (a POST's status), not only that the pipe broke.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Why the upload ended, once it did.
pub(super) type Failed = Arc<Mutex<Option<String>>>;

pub(super) struct Halves<R, W> {
    pub read: R,
    pub write: W,
    pub failed: Failed,
}

impl<R, W> Halves<R, W> {
    fn why(&self, e: io::Error) -> io::Error {
        match self.failed.lock().unwrap_or_else(|p| p.into_inner()).clone() {
            Some(why) => io::Error::new(io::ErrorKind::BrokenPipe, why),
            None => e,
        }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for Halves<R, W> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for Halves<R, W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match std::task::ready!(Pin::new(&mut self.write).poll_write(cx, data)) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(self.why(e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reads_come_from_one_half_and_writes_go_to_the_other_with_the_upload_s_words() {
        let (down, mut far_down) = tokio::io::duplex(64);
        let (up, far_up) = tokio::io::duplex(64);
        let failed: Failed = Arc::default();
        let mut halves = Halves { read: down, write: up, failed: failed.clone() };
        far_down.write_all(b"from the GET").await.unwrap();
        let mut got = [0u8; 12];
        halves.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"from the GET");
        drop(far_up);
        *failed.lock().unwrap() = Some("a POST of packet-up: HTTP 500".into());
        let e = halves.write_all(b"x").await.unwrap_err();
        assert_eq!(e.to_string(), "a POST of packet-up: HTTP 500");
    }
}
