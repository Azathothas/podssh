//! One bidirectional QUIC stream as a byte stream of tokio (T-667), as the
//! relay role reads a connection of HTTP/1.1 and a client its session. It
//! holds its connection, so that the connection lives while the stream does,
//! and a client's holds its endpoint too, whose socket is the connection's
//! own. A client's stream that is dropped finishes its side, waits a moment
//! for the role to take what it holds (the last frame, a Close, is often
//! there), then closes the connection: one connection for each session, so
//! its end is the session's.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use noq::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How long a client's dropped stream waits for the role to take its last
/// bytes, and then for its close to leave.
pub const LINGER: Duration = Duration::from_secs(2);

/// A stream, and what keeps it alive.
pub struct QuicStream {
    recv: RecvStream,
    /// `None` once a client's drop took it to finish it.
    send: Option<SendStream>,
    connection: Connection,
    /// A client's endpoint; none at the role, whose endpoint serves each
    /// connection.
    endpoint: Option<Endpoint>,
}

impl QuicStream {
    /// A stream of `connection` at the role.
    pub fn new(send: SendStream, recv: RecvStream, connection: Connection) -> QuicStream {
        QuicStream { recv, send: Some(send), connection, endpoint: None }
    }

    /// A client's stream, whose connection and endpoint end with it.
    pub fn client(send: SendStream, recv: RecvStream, connection: Connection, endpoint: Endpoint) -> QuicStream {
        QuicStream { recv, send: Some(send), connection, endpoint: Some(endpoint) }
    }

    fn closed() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::NotConnected, "the QUIC stream ended")
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        // The trait's method: noq's own `poll_read` takes a slice.
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut().send.as_mut() {
            Some(send) => AsyncWrite::poll_write(Pin::new(send), cx, buf),
            None => Poll::Ready(Err(QuicStream::closed())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut().send.as_mut() {
            Some(send) => AsyncWrite::poll_flush(Pin::new(send), cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut().send.as_mut() {
            Some(send) => AsyncWrite::poll_shutdown(Pin::new(send), cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl Drop for QuicStream {
    fn drop(&mut self) {
        // The role's stream finishes on its own drop, and its connection
        // ends with the client's.
        let (Some(mut send), Some(endpoint)) = (self.send.take(), self.endpoint.take()) else { return };
        let connection = self.connection.clone();
        let _ = send.finish();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            connection.close(VarInt::from_u32(0), b"");
            return;
        };
        runtime.spawn(async move {
            // Until the role has each byte, or stopped reading.
            let _ = tokio::time::timeout(LINGER, send.stopped()).await;
            connection.close(VarInt::from_u32(0), b"");
            let _ = tokio::time::timeout(LINGER, endpoint.wait_idle()).await;
        });
    }
}
