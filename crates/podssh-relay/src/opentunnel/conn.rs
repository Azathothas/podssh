//! A visitor's connection over a bridge, as a byte stream: what the service
//! sends of it, from the ClientHello on, and what the node answers, which
//! TLS ends at the node reads and writes as it reads and writes TCP. Two
//! tasks pump it, as the transit road's link: the node's bytes go out in
//! data frames of 32 KiB at most, behind each control message of the
//! bridge's, and the service's come in from the bridge's reader, which
//! waits 5 s at most for a connection whose reader does not read, then
//! resets it, so that one stalled connection never holds the others. Each
//! side half-closes with `end`, and `reset` aborts: a read then fails with
//! the reason.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, watch};

use super::wire::{self, codes, Up};

/// Each direction of the pipe between the connection and its pumps.
const PIPE: usize = 256 * 1024;
/// The frames of one connection that wait for its reader: 512 KiB, the
/// service's own bound for one visitor.
pub const INBOUND: usize = 16;
/// How long the bridge's reader waits for a connection that does not read.
pub const STALL_LIMIT: Duration = Duration::from_secs(5);

/// What the bridge gives a connection.
#[derive(Debug)]
pub enum Inbound {
    Data(Vec<u8>),
    /// The visitor half-closed.
    End,
}

/// What a bridge sends: control messages, ahead of the data frames, so that
/// a `pong` or a `reset` never waits behind a connection's bytes.
#[derive(Clone)]
pub struct Outbox {
    control: mpsc::UnboundedSender<String>,
    data: mpsc::Sender<Vec<u8>>,
}

/// The writer's side of an [`Outbox`].
pub struct Outgoing {
    pub control: mpsc::UnboundedReceiver<String>,
    pub data: mpsc::Receiver<Vec<u8>>,
}

impl Outbox {
    /// An outbox whose data waits in `queue` frames at most.
    pub fn new(queue: usize) -> (Outbox, Outgoing) {
        let (control, control_rx) = mpsc::unbounded_channel();
        let (data, data_rx) = mpsc::channel(queue.max(1));
        (Outbox { control, data }, Outgoing { control: control_rx, data: data_rx })
    }

    /// Send a control message; false once the bridge ended.
    pub fn control(&self, up: &Up<'_>) -> bool {
        self.control.send(up.text()).is_ok()
    }

    /// Send a data frame, waiting while the queue is full; false once the
    /// bridge ended.
    pub async fn data(&self, frame: Vec<u8>) -> bool {
        self.data.send(frame).await.is_ok()
    }
}

/// A visitor's connection.
pub struct Visitor {
    pipe: DuplexStream,
    why: Arc<Mutex<Option<String>>>,
    /// The bridge's id of the connection, the visitor's address as the
    /// service names it, and the name that its ClientHello asked for.
    pub conn: u32,
    pub peer: String,
    pub sni: String,
}

/// The bridge's hold on a connection: where its bytes go, and its reset.
pub struct Held {
    inbound: mpsc::Sender<Inbound>,
    reset: watch::Sender<Option<String>>,
}

impl Held {
    /// Give the connection `item`, waiting [`STALL_LIMIT`] at most while its
    /// queue is full; false when it did not take it in time.
    pub async fn deliver(&self, item: Inbound) -> bool {
        match self.inbound.try_send(item) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => true,
            Err(mpsc::error::TrySendError::Full(item)) => {
                tokio::time::timeout(STALL_LIMIT, self.inbound.send(item)).await.is_ok()
            }
        }
    }

    /// End the connection with `why`: a read of it then fails so.
    pub fn reset(self, why: String) {
        let _ = self.reset.send(Some(why));
    }
}

/// A new connection `conn`, whose bytes go out through `outbox`; `gone`
/// hears its id once both of its ways ended.
pub fn open(conn: u32, peer: String, sni: String, outbox: Outbox, gone: mpsc::UnboundedSender<u32>) -> (Visitor, Held) {
    let why: Arc<Mutex<Option<String>>> = Arc::default();
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (from_pipe, to_pipe) = tokio::io::split(theirs);
    let (inbound, inbound_rx) = mpsc::channel(INBOUND);
    let (reset, reset_rx) = watch::channel(None);
    let pumps = {
        let (outbox, why) = (outbox.clone(), why.clone());
        let up = up(conn, from_pipe, outbox.clone(), reset_rx.clone());
        let down = down(conn, to_pipe, inbound_rx, outbox, reset_rx, why);
        async move {
            tokio::join!(up, down);
            let _ = gone.send(conn);
        }
    };
    tokio::spawn(pumps);
    (Visitor { pipe: ours, why, conn, peer, sni }, Held { inbound, reset })
}

/// Until the connection is reset.
async fn reset_by(reset: &mut watch::Receiver<Option<String>>) {
    let _ = reset.wait_for(Option::is_some).await;
}

/// The node's bytes, out in data frames; at their end, `end`.
async fn up(
    conn: u32,
    mut from_pipe: tokio::io::ReadHalf<DuplexStream>,
    outbox: Outbox,
    mut reset: watch::Receiver<Option<String>>,
) {
    let mut buf = vec![0u8; wire::MAX_PAYLOAD];
    loop {
        let n = tokio::select! {
            n = from_pipe.read(&mut buf) => n.unwrap_or(0),
            () = reset_by(&mut reset) => return,
        };
        if n == 0 {
            outbox.control(&Up::End { conn });
            return;
        }
        let sent = tokio::select! {
            sent = outbox.data(wire::data_frame(conn, &buf[..n])) => sent,
            () = reset_by(&mut reset) => return,
        };
        if !sent {
            return;
        }
    }
}

/// The service's bytes, in from the bridge, until its `end`, a reset, or
/// the end of the bridge.
async fn down(
    conn: u32,
    mut to_pipe: tokio::io::WriteHalf<DuplexStream>,
    mut inbound: mpsc::Receiver<Inbound>,
    outbox: Outbox,
    mut reset: watch::Receiver<Option<String>>,
    why: Arc<Mutex<Option<String>>>,
) {
    loop {
        let item = tokio::select! {
            item = inbound.recv() => item,
            () = reset_by(&mut reset) => None,
        };
        match item {
            Some(Inbound::Data(bytes)) => {
                if to_pipe.write_all(&bytes).await.is_err() {
                    // Nobody reads the connection any more: the service
                    // hears that it is gone.
                    outbox.control(&Up::Reset { conn, code: codes::UPSTREAM_IO_ERROR });
                    return;
                }
            }
            Some(Inbound::End) => break,
            None => {
                let reason = reset.borrow().clone();
                fail(&why, reason.unwrap_or_else(|| "the bridge to OpenTunnel ended".to_string()));
                break;
            }
        }
    }
    let _ = to_pipe.shutdown().await;
}

fn fail(why: &Mutex<Option<String>>, text: String) {
    lock(why).get_or_insert(text);
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Visitor {
    /// Why the connection failed, once it did.
    pub fn failure(&self) -> Option<String> {
        lock(&self.why).clone()
    }
}

impl std::fmt::Debug for Visitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Visitor").field("conn", &self.conn).field("peer", &self.peer).finish_non_exhaustive()
    }
}

impl AsyncRead for Visitor {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let (before, room) = (buf.filled().len(), buf.remaining());
        match Pin::new(&mut self.pipe).poll_read(cx, buf) {
            // The end of the bytes: a reset says why.
            Poll::Ready(Ok(())) if room > 0 && buf.filled().len() == before => match self.failure() {
                Some(why) => Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, why))),
                None => Poll::Ready(Ok(())),
            },
            other => other,
        }
    }
}

impl AsyncWrite for Visitor {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.pipe).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_connection_s_bytes_go_out_in_frames_and_its_end_and_reset_are_said() {
        let (outbox, mut out) = Outbox::new(8);
        let (gone, mut gone_rx) = mpsc::unbounded_channel();
        let (mut visitor, held) = open(7, "203.0.113.9:1".into(), "r.a.test".into(), outbox, gone);
        assert!(held.deliver(Inbound::Data(b"hello".to_vec())).await);
        let mut got = [0u8; 5];
        visitor.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        visitor.write_all(&vec![1u8; 40 * 1024]).await.unwrap();
        let first = out.data.recv().await.unwrap();
        assert_eq!(wire::split_frame(&first).map(|(c, p)| (c, p.len())), Some((7, wire::MAX_PAYLOAD)));
        let second = out.data.recv().await.unwrap();
        assert_eq!(wire::split_frame(&second).map(|(c, p)| (c, p.len())), Some((7, 8 * 1024)));
        visitor.shutdown().await.unwrap();
        let end: serde_json::Value = serde_json::from_str(&out.control.recv().await.unwrap()).unwrap();
        assert_eq!(end, serde_json::json!({ "type": "end", "conn": 7 }));
        held.reset("OpenTunnel reset the connection (client_io_error)".into());
        let mut rest = Vec::new();
        let read = visitor.read_to_end(&mut rest).await.expect_err("a reset is no clean end");
        assert!(read.to_string().contains("client_io_error"), "{read}");
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), gone_rx.recv()).await.unwrap(), Some(7));
    }
}
