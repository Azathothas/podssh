//! How a runner reaches the relay: TLS for each real use, or plain `ws://` to
//! a stand-in relay on the loopback, for the tests of an embedder (feature
//! `plain-ws`, T-068). The binary never enables the feature
//! (`scripts/no-plain-ws.sh`).

use podssh_ws::client::{connect, ConnectError, WsClientConfig};
use podssh_ws::session::RelaySession;

/// The wire of a socket to the relay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Wire {
    /// TLS to the relay, through the proxy when one is set.
    #[default]
    Tls,
    /// Plain `ws://` to a stand-in relay on the loopback, for tests. A host
    /// that is not the loopback is refused before any connection, so a token
    /// never leaves the host in clear (`podssh_ws::plain`).
    #[cfg(feature = "plain-ws")]
    PlainLoopback,
}

/// A socket to the relay, on either wire.
pub(crate) enum Socket {
    Tls(RelaySession),
    #[cfg(feature = "plain-ws")]
    Plain(RelaySession<tokio::net::TcpStream>),
}

/// Connect on `wire` with `token`, as `config` says.
pub(crate) async fn open(wire: Wire, config: &WsClientConfig, token: &str) -> Result<Socket, ConnectError> {
    match wire {
        Wire::Tls => connect(config, token).await.map(Socket::Tls),
        #[cfg(feature = "plain-ws")]
        Wire::PlainLoopback => {
            let at = &config.endpoint;
            podssh_ws::plain::connect_loopback(&at.host, at.port, &at.path, token, config.timeout, config.idle_timeout)
                .await
                .map(Socket::Plain)
        }
    }
}

/// What the facade's forward stream uses of a socket.
#[cfg(feature = "blocking")]
impl Socket {
    pub(crate) async fn read_frame(&self) -> Result<podssh_ws::Frame, podssh_ws::SessionError> {
        match self {
            Socket::Tls(s) => s.read_frame().await,
            #[cfg(feature = "plain-ws")]
            Socket::Plain(s) => s.read_frame().await,
        }
    }

    pub(crate) async fn send_binary(&self, payload: &[u8]) -> Result<(), podssh_ws::SessionError> {
        match self {
            Socket::Tls(s) => s.send_binary(payload).await,
            #[cfg(feature = "plain-ws")]
            Socket::Plain(s) => s.send_binary(payload).await,
        }
    }

    pub(crate) async fn send_close(&self, code: u16, reason: &str) -> Result<(), podssh_ws::SessionError> {
        match self {
            Socket::Tls(s) => s.send_close(code, reason).await,
            #[cfg(feature = "plain-ws")]
            Socket::Plain(s) => s.send_close(code, reason).await,
        }
    }

    pub(crate) fn close_sent(&self) -> bool {
        match self {
            Socket::Tls(s) => s.close_sent(),
            #[cfg(feature = "plain-ws")]
            Socket::Plain(s) => s.close_sent(),
        }
    }
}
