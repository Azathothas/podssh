//! One session over the iroh road: a bidirectional QUIC stream, which the
//! resumable layer reads and writes as it does a relay link (T-151).
//!
//! A QUIC peer learns of a stream only from its first byte, and the layer's
//! client sends nothing before the far end's `GREETING`. So the client sends
//! one byte first, which names what the stream carries, and the far end reads
//! it before it greets.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// The first byte of a stream that carries a session of the layer.
pub const SESSION: u8 = 0x01;

/// The two halves of a QUIC stream as one byte stream.
pub struct Stream {
    send: SendStream,
    recv: RecvStream,
}

impl Stream {
    pub fn new(send: SendStream, recv: RecvStream) -> Stream {
        Stream { send, recv }
    }
}

/// Open a stream for a session on `connection`, and announce it.
pub async fn open_session(connection: &Connection) -> io::Result<Stream> {
    let (mut send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
    // tokio's `write_all`, not the stream's own, whose error is not io's.
    AsyncWriteExt::write_all(&mut send, &[SESSION]).await?;
    Ok(Stream::new(send, recv))
}

/// The next stream that the client opened for a session on `connection`.
/// A stream that names another use is refused with an error.
pub async fn accept_session(connection: &Connection) -> io::Result<Stream> {
    let (send, mut recv) = connection.accept_bi().await.map_err(io::Error::other)?;
    let mut first = [0u8; 1];
    AsyncReadExt::read_exact(&mut recv, &mut first).await?;
    if first[0] != SESSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a stream of an unknown kind ({:#04x})", first[0]),
        ));
    }
    Ok(Stream::new(send, recv))
}

impl AsyncRead for Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    // The stream's `finish`: the far end reads the end of the bytes.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
