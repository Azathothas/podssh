//! The way to a DERP server: TLS over TCP, through `HTTPS_PROXY` when one is
//! set, with podssh-ws's own provider and trust store; then a WebSocket at
//! `/derp` with the subprotocol `derp`, which derper's handler requires
//! (tailscale/tailscale:derp/derpserver/websocket.go at v1.104.4), and which
//! Tailscale's own client in a browser offers. No relay token goes with it:
//! a token goes to the deployment that minted it alone.
//!
//! A [`Dial`] gives the byte stream before the upgrade, so that a test can
//! give a pipe to a stand-in in place of TLS.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::session::RelaySession;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};

use super::servers::Server;

/// The path of DERP's WebSocket.
pub const PATH: &str = "/derp";
/// The subprotocol of DERP's WebSocket.
pub const SUBPROTOCOL: &str = "derp";
/// What podssh says it is.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));
/// The bound of the connection, of TLS and of the upgrade, each.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(20);
/// The bound of each read: a server answers the pings of [`super::conn`]
/// each 10 s, so silence this long is a dead link.
pub const IDLE_LIMIT: Duration = Duration::from_secs(30);
/// The bound of each write.
pub const WRITE_LIMIT: Duration = Duration::from_secs(20);
/// The largest message read: a server's writer may join several frames.
pub const RECEIVE_CAP: usize = 1 << 20;

/// A byte stream to a server, before its upgrade.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;
/// A dial in progress.
pub type Dialing = Pin<Box<dyn Future<Output = Result<BoxIo, String>> + Send>>;
/// How to reach a server: TLS through the proxy ([`tls`]), or a test's pipe.
pub type Dial = Arc<dyn Fn(&Server) -> Dialing + Send + Sync>;

/// TLS to each server, through `proxy`, verified with `trust`.
pub fn tls(trust: Trust, proxy: ProxyChoice) -> Dial {
    Arc::new(move |server: &Server| -> Dialing {
        let (server, trust, proxy) = (server.clone(), trust.clone(), proxy.clone());
        Box::pin(async move {
            let host = server.host.as_str();
            let opened = podssh_ws::client::open_tls(host, server.port, host, &trust, &proxy, CONNECT_LIMIT);
            let tls = opened.await.map_err(|e| format!("{server}: {e}"))?;
            Ok(Box::new(tls) as BoxIo)
        })
    })
}

/// The upgrade request, as the WebSocket of Tailscale's own client asks
/// for it, with `key` as its `Sec-WebSocket-Key`.
pub fn request(server: &Server, key: &str) -> Vec<u8> {
    let host = if server.port == super::servers::PORT { server.host.clone() } else { server.authority() };
    let mut out = String::with_capacity(256);
    out.push_str(&format!("GET {PATH} HTTP/1.1\r\n"));
    out.push_str(&format!("Host: {host}\r\n"));
    out.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
    out.push_str("Upgrade: websocket\r\n");
    out.push_str("Connection: Upgrade\r\n");
    out.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    out.push_str("Sec-WebSocket-Version: 13\r\n");
    out.push_str(&format!("Sec-WebSocket-Protocol: {SUBPROTOCOL}\r\n"));
    out.push_str("\r\n");
    out.into_bytes()
}

/// The WebSocket of DERP over `io`, a stream to `server`.
pub async fn upgrade(io: BoxIo, server: &Server) -> Result<RelaySession<BoxIo>, String> {
    let key = podssh_ws::handshake::generate_key().map_err(|e| e.to_string())?;
    let ask = request(server, &key);
    let asked = podssh_ws::client::upgrade_with(io, &ask, &key);
    let (io, pending) = match tokio::time::timeout(CONNECT_LIMIT, asked).await {
        Err(_) => return Err(format!("{server} did not answer the upgrade within {} s", CONNECT_LIMIT.as_secs())),
        Ok(Err(e)) => return Err(format!("{server} refused DERP's WebSocket: {e}")),
        Ok(Ok(upgraded)) => upgraded,
    };
    let session = RelaySession::new(io, pending, Some(IDLE_LIMIT), WRITE_LIMIT).without_pings();
    session.set_receive_cap(RECEIVE_CAP);
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upgrade_asks_for_derp_s_subprotocol_at_its_path_and_names_no_token() {
        let server = Server::parse("tc301a.ipn.dev").unwrap();
        let text = String::from_utf8(request(&server, "dGhlIHNhbXBsZSBub25jZQ==")).unwrap();
        assert!(text.starts_with("GET /derp HTTP/1.1\r\nHost: tc301a.ipn.dev\r\n"), "{text}");
        assert!(text.contains("\r\nSec-WebSocket-Protocol: derp\r\n"));
        assert!(text.contains("\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(!text.to_ascii_lowercase().contains("token"), "no credential goes to a DERP server");
        let other = Server::parse("127.0.0.1:8443").unwrap();
        assert!(String::from_utf8(request(&other, "k")).unwrap().contains("\r\nHost: 127.0.0.1:8443\r\n"));
    }
}
