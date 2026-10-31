//! One TCP connection inside the tunnel, as tokio's `AsyncRead` and
//! `AsyncWrite`: a read takes what smoltcp's socket holds, a write puts
//! bytes in its buffer, and each that cannot go on waits on the socket's
//! waker, which smoltcp wakes as the connection changes. The driver is told
//! of each change that may send a segment.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::stack::Core;

/// A TCP connection inside the tunnel. Its drop closes it, with a FIN, and
/// the tunnel ends with its last connection and its stack.
pub struct Stream {
    core: Arc<Core>,
    handle: SocketHandle,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream").field("peer", &self.peer()).finish_non_exhaustive()
    }
}

impl Stream {
    pub(crate) fn new(core: Arc<Core>, handle: SocketHandle) -> Stream {
        Stream { core, handle }
    }

    /// The far end of the connection.
    pub fn peer(&self) -> Option<SocketAddr> {
        let inner = self.core.shared.lock();
        let endpoint = inner.sockets.get::<tcp::Socket>(self.handle).remote_endpoint()?;
        Some(SocketAddr::new(endpoint.addr.into(), endpoint.port))
    }

    /// Wait until the handshake of a connection that this end opened is
    /// done; why, when it is not.
    pub(crate) async fn established(&self) -> Result<(), String> {
        std::future::poll_fn(|cx| {
            let mut inner = self.core.shared.lock();
            let ended = inner.ended.clone();
            let socket = inner.sockets.get_mut::<tcp::Socket>(self.handle);
            match socket.state() {
                tcp::State::SynSent | tcp::State::SynReceived => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
                tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
                _ => Poll::Ready(Err(match ended {
                    Some(why) => format!("the tunnel ended: {why}"),
                    None => "refused: the far end reset the connection".to_string(),
                })),
            }
        })
        .await
    }

    /// The error of a connection that can go no further: the tunnel's end
    /// when it has ended, else `kind`.
    fn ended(why: Option<String>, kind: io::ErrorKind) -> io::Error {
        match why {
            Some(why) => io::Error::new(io::ErrorKind::ConnectionAborted, format!("WARP's tunnel ended: {why}")),
            None => io::Error::from(kind),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut inner = this.core.shared.lock();
        let ended = inner.ended.clone();
        let socket = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        if socket.can_recv() {
            let read = socket.recv_slice(buf.initialize_unfilled());
            drop(inner);
            let n = read.map_err(|e| io::Error::other(e.to_string()))?;
            buf.advance(n);
            // The window opened: the driver may say so to the far end.
            this.core.shared.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !socket.may_recv() {
            // A FIN is the end of the stream; the tunnel's end is an error.
            return Poll::Ready(match ended {
                Some(why) => Err(Stream::ended(Some(why), io::ErrorKind::ConnectionAborted)),
                None => Ok(()),
            });
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let mut inner = this.core.shared.lock();
        let ended = inner.ended.clone();
        let socket = inner.sockets.get_mut::<tcp::Socket>(this.handle);
        if socket.can_send() {
            let sent = socket.send_slice(buf);
            drop(inner);
            let n = sent.map_err(|e| io::Error::other(e.to_string()))?;
            this.core.shared.wake.notify_one();
            return Poll::Ready(Ok(n));
        }
        if !socket.may_send() {
            return Poll::Ready(Err(Stream::ended(ended, io::ErrorKind::BrokenPipe)));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A write is in smoltcp's buffer, which the driver sends as the
        // window allows: there is nothing more to push.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.core.shared.lock().sockets.get_mut::<tcp::Socket>(this.handle).close();
        this.core.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let mut inner = self.core.shared.lock();
        inner.sockets.get_mut::<tcp::Socket>(self.handle).close();
        let handle = self.handle;
        inner.live.retain(|h| *h != handle);
        inner.closing.push(handle);
        drop(inner);
        self.core.shared.wake.notify_one();
    }
}
