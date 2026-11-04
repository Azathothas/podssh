//! One session over the iroh road: a bidirectional QUIC stream, which the
//! resumable layer reads and writes as it does a relay link (T-151).
//!
//! A QUIC peer learns of a stream only from its first byte, and the layer's
//! client sends nothing before the far end's `GREETING`. So the client sends
//! one byte first, which names what the stream carries, and the far end reads
//! it before it greets.
//!
//! A session's [`Lane`] (T-666) puts a copy's stream below a terminal's in
//! the order in which each end sends the bytes of one connection: a copy's
//! first byte is [`SESSION_BULK`], on a connection of [`crate::ALPN_LANES`]
//! alone, whose far end reads it; on one of [`crate::ALPN`], the far end of
//! an older podssh, a copy's stream is announced as any session's, and only
//! this end's bytes take its lane.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// The first byte of a stream that carries a session of the layer.
pub const SESSION: u8 = 0x01;
/// The first byte of a session's stream whose bytes go after the others'
/// (T-666): a copy's.
pub const SESSION_BULK: u8 = 0x02;

/// What a session's stream carries, for its place in the order in which a
/// connection's bytes are sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// A terminal, a command, a forward: what a user waits on.
    Interactive,
    /// A copy: its bytes wait for the others'.
    Bulk,
}

tokio::task_local! {
    static LANE: Lane;
}

impl Lane {
    /// The send priority of the lane's streams: QUIC's default for a
    /// terminal, as each stream had before lanes, and one below for a copy.
    pub fn priority(self) -> i32 {
        match self {
            Lane::Interactive => 0,
            Lane::Bulk => -1,
        }
    }

    /// The lane of the task that runs: that of [`Lane::scope`], else
    /// [`Lane::Interactive`].
    pub fn current() -> Lane {
        LANE.try_with(|lane| *lane).unwrap_or(Lane::Interactive)
    }

    /// `future`, in which each session that opens takes this lane. A task
    /// that it spawns takes the lane again with this, as a task-local value
    /// does not pass to a new task.
    pub fn scope<F: Future>(self, future: F) -> impl Future<Output = F::Output> {
        LANE.scope(self, future)
    }
}

/// The two halves of a QUIC stream as one byte stream.
pub struct Stream {
    send: SendStream,
    recv: RecvStream,
}

impl Stream {
    pub fn new(send: SendStream, recv: RecvStream) -> Stream {
        Stream { send, recv }
    }

    /// The send priority that this end gives the stream's bytes; `None` once
    /// the stream is closed.
    pub fn priority(&self) -> Option<i32> {
        self.send.priority().ok()
    }
}

/// Open a stream for a session on `connection`, and announce it.
pub async fn open_session(connection: &Connection) -> io::Result<Stream> {
    open_lane(connection, Lane::Interactive).await
}

/// Open a stream for a session of `lane` on `connection`, and announce it:
/// as a copy's only where the far end reads that ([`crate::ALPN_LANES`]).
pub async fn open_lane(connection: &Connection, lane: Lane) -> io::Result<Stream> {
    let (mut send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
    // Before the first byte: a priority given to a stream with bytes
    // waiting may take effect only after they are sent.
    let _ = send.set_priority(lane.priority());
    let first = if lane == Lane::Bulk && connection.alpn() == crate::ALPN_LANES { SESSION_BULK } else { SESSION };
    // tokio's `write_all`, not the stream's own, whose error is not io's.
    AsyncWriteExt::write_all(&mut send, &[first]).await?;
    Ok(Stream::new(send, recv))
}

/// The next stream that the client opened for a session on `connection`,
/// with this end's bytes on it in the lane that its first byte names. A
/// stream that names another use is refused with an error.
pub async fn accept_session(connection: &Connection) -> io::Result<Stream> {
    let (send, mut recv) = connection.accept_bi().await.map_err(io::Error::other)?;
    let mut first = [0u8; 1];
    AsyncReadExt::read_exact(&mut recv, &mut first).await?;
    let lane = match first[0] {
        SESSION => Lane::Interactive,
        SESSION_BULK => Lane::Bulk,
        other => {
            let why = format!("a stream of an unknown kind ({other:#04x})");
            return Err(io::Error::new(io::ErrorKind::InvalidData, why));
        }
    };
    let _ = send.set_priority(lane.priority());
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
