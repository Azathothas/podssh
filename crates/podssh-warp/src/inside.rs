//! Connections that come in, inside the tunnel, for the far end of the
//! stand-in edge alone (compiled with the stand-in): a socket of smoltcp in
//! this process waits for a SYN at one address and port of its stack, as
//! Cloudflare's targets wait. No socket of the system listens here, and the
//! client of the road never takes a connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;

use crate::stack::{socket, Core, Stack};
use crate::stream::Stream;

impl Stack {
    /// The connections to `at` inside the tunnel.
    pub fn listen(&self, at: SocketAddr) -> Result<Listener, String> {
        let handle = waiting(self.core(), at)?;
        Ok(Listener { core: self.core().clone(), at, handle })
    }
}

/// A socket of the stack that waits at `at`.
fn waiting(core: &Arc<Core>, at: SocketAddr) -> Result<SocketHandle, String> {
    let mut inner = core.shared.lock();
    let mut socket = socket();
    socket.listen(at).map_err(|e| format!("{at}: {e}"))?;
    let handle = inner.sockets.add(socket);
    inner.live.push(handle);
    Ok(handle)
}

/// The connections that come to one address and port inside the tunnel.
pub struct Listener {
    core: Arc<Core>,
    at: SocketAddr,
    handle: SocketHandle,
}

impl Listener {
    /// The next connection, once its handshake is done; a new socket waits
    /// in its place.
    pub async fn accept(&mut self) -> Result<Stream, String> {
        let at = self.at;
        let handle = std::future::poll_fn(|cx| {
            let mut inner = self.core.shared.lock();
            let ended = inner.ended.clone();
            let socket = inner.sockets.get_mut::<tcp::Socket>(self.handle);
            match socket.state() {
                tcp::State::Listen | tcp::State::SynReceived => {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
                tcp::State::Closed => Poll::Ready(Err(ended.unwrap_or_else(|| format!("{at}: the socket closed")))),
                _ => Poll::Ready(Ok(self.handle)),
            }
        })
        .await?;
        self.handle = waiting(&self.core, at)?;
        Ok(Stream::new(self.core.clone(), handle))
    }
}
