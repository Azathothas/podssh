//! The connection to frps, as frpc makes it (`client/connector.go` at
//! v0.71.1), in one of two forms:
//!
//! - `frp://HOST[:PORT]` (port 7000 by default), frpc's `tcp` with TLS on,
//!   its default since 0.50: TCP through the host's proxy, frp's first byte
//!   `0x17`, then TLS, which frps tells from its other protocols by that byte;
//! - `wss://HOST[:PORT][/PATH]`, frpc's `wss`: TLS, then a WebSocket at
//!   `/~!frp` in binary messages, as a TLS front end on port 443 carries it to
//!   frps's port, which reads a WebSocket by its first line.
//!
//! TLS is checked with podssh's trust, never skipped as frpc does with no CA
//! of its own: frps's own certificate, which it makes itself when none is
//! given, needs its CA in the file of the road. yamux runs inside each.

use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::dial::{self, ProxyChoice};
use crate::forwarder::{carry, Form, Note};
use crate::tls::Trust;
use crate::url::WsUrl;
use crate::via::Duplex;

/// frps's port when an `frp://` URL names none (`bindPort`'s default).
pub const DEFAULT_PORT: u16 = 7000;
/// The path of frp's WebSocket (`pkg/util/net.FrpWebsocketPath`).
pub const WEBSOCKET_PATH: &str = "/~!frp";
/// The byte that frpc sends before its TLS (`FRPTLSHeadByte`).
pub const TLS_HEAD_BYTE: u8 = 0x17;
/// The largest message of the WebSocket that podssh takes from frps.
const RECEIVE_CAP: usize = 1024 * 1024;
/// Who is at the other end, in the words of a failure.
pub const PEER: &str = "frps";

/// Where frps is, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Server {
    /// frp's TCP with TLS.
    Tls { host: String, port: u16 },
    /// A WebSocket over TLS, at its URL.
    WebSocket(WsUrl),
}

impl Server {
    /// `frp://HOST[:PORT]` or `wss://HOST[:PORT][/PATH]`; nothing in the
    /// clear, as the token and the services' names would cross in it.
    pub fn parse(text: &str) -> Result<Server, String> {
        let text = text.trim();
        if let Some(rest) = text.strip_prefix("frp://") {
            let rest = rest.trim_end_matches('/');
            if rest.contains('/') || rest.contains('@') || rest.is_empty() {
                return Err(format!("{text}: frp://HOST[:PORT] holds no path and no user"));
            }
            let (host, port) = crate::pt::host_port(rest, DEFAULT_PORT).map_err(|why| format!("{text}: {why}"))?;
            return Ok(Server::Tls { host, port });
        }
        if text.starts_with("wss://") {
            let with_path = match text.splitn(4, '/').nth(3) {
                Some(path) if !path.is_empty() => text.to_string(),
                _ => format!("{}{WEBSOCKET_PATH}", text.trim_end_matches('/')),
            };
            let url = WsUrl::parse(&with_path).map_err(|why| format!("{text}: {why}"))?;
            return Ok(Server::WebSocket(url));
        }
        Err(format!(
            "{text}: frps is named frp://HOST[:PORT] (frp's TCP with TLS) or wss://HOST[:PORT][/PATH] \
             (its WebSocket over TLS); ws:// and plain TCP would carry the token in the clear"
        ))
    }

    /// The server as a line names it: no path, which a front end may keep
    /// secret.
    pub fn shown(&self) -> String {
        match self {
            Server::Tls { host, port } => format!("frp://{}", crate::dial::authority(host, *port)),
            Server::WebSocket(url) => format!("wss://{}/...", url.host_header()),
        }
    }
}

/// The connection to `server`: the bytes that yamux runs on.
pub async fn connect(
    server: &Server,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<Box<dyn Duplex>, String> {
    let shown = server.shown();
    match server {
        Server::Tls { host, port } => {
            let mut tcp = dial::dial(host, *port, proxy, timeout).await.map_err(|e| format!("{shown}: {e}"))?;
            tcp.write_all(&[TLS_HEAD_BYTE]).await.map_err(|e| format!("{shown}: {e}"))?;
            let tls =
                crate::tls_wrap::tls_over(tcp, host, trust, timeout).await.map_err(|e| format!("{shown}: {e}"))?;
            Ok(Box::new(tls))
        }
        Server::WebSocket(url) => {
            let session =
                crate::url::dial(url, trust, proxy, timeout, None).await.map_err(|e| format!("{shown}: {e}"))?;
            let session = session.naming(PEER);
            session.set_receive_cap(RECEIVE_CAP);
            // frps sends no text message; one would be no part of yamux.
            let note: Note = std::sync::Arc::new(|_: &str| {});
            let (carried, _first) = carry::spawn(session, Form::Query, false, note, PEER);
            Ok(Box::new(carried.stream))
        }
    }
}
