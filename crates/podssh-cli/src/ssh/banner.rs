//! The server's version line on a connection that opened (RFC 4253, section
//! 4.2): `podssh doctor`'s check that a connection to port 22 carries SSH,
//! and the check of the direct road that follows the relay hosts (T-363). A
//! `200` to CONNECT proves that a proxy took the request, not that the
//! tunnel carries bytes as they are: a proxy that intercepts TLS waits for a
//! ClientHello, and sends nothing or resets (T-317). The bytes that the check
//! read go to the SSH client first ([`Prefixed`]).

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// The most read at once: a version line is 255 bytes at most, and a server
/// may send other lines first, and its first packet after.
const READ: usize = 4096;

/// The first bytes of `stream` within `wait`, when a line of them is an SSH
/// version line (a server may send other lines before it); else why not.
pub(crate) async fn read<S: AsyncRead + Unpin>(stream: &mut S, wait: Duration) -> Result<Vec<u8>, String> {
    let mut first = vec![0u8; READ];
    match tokio::time::timeout(wait, stream.read(&mut first)).await {
        Err(_) => Err(format!("nothing came in {} s", wait.as_secs())),
        Ok(Ok(0)) => Err("it was closed with nothing sent".into()),
        Ok(Ok(n)) if String::from_utf8_lossy(&first[..n]).lines().any(|l| l.starts_with("SSH-")) => {
            first.truncate(n);
            Ok(first)
        }
        Ok(Ok(_)) => Err("what came was not an SSH banner".into()),
        Ok(Err(e)) => Err(format!("it broke with nothing sent ({e})")),
    }
}

/// A stream whose first bytes were read already: it gives them again first,
/// then reads on; writes go through as they are.
pub(crate) struct Prefixed<S> {
    first: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(crate) fn new(first: Vec<u8>, inner: S) -> Prefixed<S> {
        Prefixed { first, at: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.at < self.first.len() {
            let n = (self.first.len() - self.at).min(buf.remaining());
            let at = self.at;
            buf.put_slice(&self.first[at..at + n]);
            self.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
