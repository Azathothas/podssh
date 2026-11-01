//! The runtime that Arti runs on: tokio and rustls as Arti's own, with a
//! TCP provider whose connections are podssh-ws's [`dial`]: through the
//! proxy that the environment names, else directly. Arti asks for a relay
//! by its address and port alone, which a proxy's CONNECT carries as they
//! are, with no name to resolve. It never listens: a client of Tor needs no
//! listener (`AGENTS.md`, section 5, rule 2).

use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::io::{AsyncRead, AsyncWrite};
use podssh_ws::dial::{dial, ProxyChoice};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt as _};
use tor_rtcompat::{NetStreamListener, NetStreamProvider, StreamOps, TcpConnectOptions, TcpListenOptions};

/// How long one connection to a relay may take, the proxy's CONNECT included.
pub const CONNECT_WAIT: Duration = Duration::from_secs(20);

/// The TCP provider: each connection through podssh-ws's dial.
#[derive(Clone, Debug)]
pub struct ProxiedTcp {
    proxy: ProxyChoice,
    wait: Duration,
}

impl ProxiedTcp {
    /// Connections through `proxy`, each within `wait`.
    pub fn new(proxy: ProxyChoice, wait: Duration) -> Self {
        ProxiedTcp { proxy, wait }
    }
}

/// A connection to a relay, as Arti reads and writes it.
pub struct ProxiedStream {
    inner: Compat<tokio::net::TcpStream>,
}

impl AsyncRead for ProxiedStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxiedStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

// The socket options of a stream through a proxy are the proxy's, so none is
// offered: the trait's defaults refuse each one.
impl StreamOps for ProxiedStream {}

/// The listener that is never made.
pub struct NoListener;

impl NetStreamListener<SocketAddr> for NoListener {
    type Stream = ProxiedStream;
    type Incoming = futures::stream::Pending<IoResult<(ProxiedStream, SocketAddr)>>;
    fn incoming(self) -> Self::Incoming {
        futures::stream::pending()
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        Err(refused())
    }
}

fn refused() -> Error {
    Error::new(ErrorKind::Unsupported, "podssh's road through Tor listens on no socket")
}

#[async_trait::async_trait]
impl NetStreamProvider<SocketAddr> for ProxiedTcp {
    type Stream = ProxiedStream;
    type Listener = NoListener;
    type ConnectOptions = TcpConnectOptions;
    type ListenOptions = TcpListenOptions;

    async fn connect(&self, addr: &SocketAddr, _: &TcpConnectOptions) -> IoResult<ProxiedStream> {
        let stream = dial(&addr.ip().to_string(), addr.port(), &self.proxy, self.wait)
            .await
            .map_err(|e| Error::new(ErrorKind::ConnectionRefused, e.to_string()))?;
        Ok(ProxiedStream { inner: stream.compat() })
    }

    async fn listen(&self, _: &SocketAddr, _: &TcpListenOptions) -> IoResult<NoListener> {
        Err(refused())
    }
}
