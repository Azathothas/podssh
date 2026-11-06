//! chisel's road (T-490, the operator's ruling Q66): a server of
//! jpillora/chisel that the user runs (`chisel server --port 443 --auth
//! user:pass`), one static binary that takes the destination from its
//! client, is the road in place of the relay. Read in chisel's source at
//! v1.13.0 (2026-10-11):
//!
//! - the client's upgrade names the subprotocol `chisel-v3`
//!   (`share/version.go`, `ProtocolVersion`), and the server takes the
//!   WebSocket only with it (`server/server_handler.go`,
//!   `handleClientHandler`); its 101 names no subprotocol, as its upgrader
//!   is built with none, so a 101 alone proves no chisel: the SSH that comes
//!   next does, its version `SSH-chisel-v3-server`;
//! - an upgrade without the subprotocol, or to a server that is not
//!   chisel's, falls through to its reverse proxy, or to a 404 "Not found";
//! - the bytes go in binary frames, masked, as gorilla's server reads a
//!   client's frames.
//!
//! This module carries the WebSocket alone, as a stream of bytes; the SSH
//! inside it, its `config` request and its channels are the binary's
//! (`podssh-cli`'s `chisel`), which holds russh.

use std::time::Duration;

use crate::client::{self, ConnectError, WRITE_TIMEOUT};
use crate::dial::{self, ProxyChoice};
use crate::forwarder::carry;
use crate::forwarder::Form;
use crate::session::RelaySession;
use crate::tls::Trust;
use crate::url::{Stream, WsUrl};

pub mod upgrade;

pub use crate::forwarder::{Carried, Ended, Status};

/// The subprotocol of the upgrade, which the server requires.
pub const SUBPROTOCOL: &str = "chisel-v3";

/// The largest frame taken: chisel's server sends what a read of its SSH
/// connection gave, far under it.
pub const RECEIVE_CAP: usize = 1024 * 1024;

/// The other end, in the words of a failure.
pub const PEER: &str = "the chisel server";

/// A chisel server: `https://HOST[:PORT][/PATH]` or `wss://...`, which
/// chisel's own client takes as the same; `http://` or `ws://` to this
/// host alone, as a password and the session would go in the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    url: WsUrl,
}

impl Server {
    /// Parse the server's URL; chisel's client turns `http` into `ws` and
    /// `https` into `wss`, and so does this.
    pub fn parse(text: &str) -> Result<Server, String> {
        let text = text.trim();
        let (scheme, rest) = text.split_once("://").unwrap_or(("", text));
        let ws = match scheme.to_ascii_lowercase().as_str() {
            "https" | "wss" => format!("wss://{rest}"),
            "http" | "ws" => format!("ws://{rest}"),
            _ => {
                return Err(
                    "a chisel server's URL starts with https:// or wss:// (http:// or ws:// to this host)".into()
                )
            }
        };
        let url = WsUrl::parse(&ws).map_err(|why| why.replace("a WebSocket's URL", "a chisel server's URL"))?;
        let server = Server { url };
        if !server.url.tls && !server.is_loopback() {
            return Err(format!(
                "{} has no TLS: the chisel server's password would cross the network in the clear; use https:// \
                 (http:// is for a server on this host)",
                server.shown()
            ));
        }
        Ok(server)
    }

    /// `https://HOST[:PORT][/PATH]`, as chisel's users name a server.
    pub fn shown(&self) -> String {
        let path = if self.url.target == "/" { "" } else { self.url.target.as_str() };
        format!("{}://{}{path}", if self.url.tls { "https" } else { "http" }, self.url.host_header())
    }

    pub fn tls(&self) -> bool {
        self.url.tls
    }

    pub fn host(&self) -> &str {
        &self.url.host
    }

    pub fn port(&self) -> u16 {
        self.url.port
    }

    /// The request's target: the URL's path and query, `/` with none.
    pub fn target(&self) -> &str {
        &self.url.target
    }

    /// Whether the server is this host: `localhost`, or a loopback address.
    pub fn is_loopback(&self) -> bool {
        let host = self.url.host.as_str();
        host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }
}

/// How the WebSocket to the server is opened.
pub struct Dial<'a> {
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// Bound on the dial, TLS and the upgrade.
    pub timeout: Duration,
}

/// Why a server carried no WebSocket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChiselError {
    /// TCP, the host's proxy, or TLS.
    Connect(ConnectError),
    /// The server's answer to the upgrade, in its words ([`upgrade`]).
    Refused { status: u16, words: String },
}

impl ChiselError {
    /// The line that says it, the server named as `shown`.
    pub fn line(&self, shown: &str) -> String {
        match self {
            ChiselError::Connect(ConnectError::Tls(why)) => format!("TLS with {PEER} {shown} failed: {why}"),
            ChiselError::Connect(other) => format!("{PEER} {shown}: {other}"),
            ChiselError::Refused { status, words } => format!("{PEER} {shown} refused the WebSocket: {status} {words}"),
        }
    }
}

/// The WebSocket to `server`: TCP through the proxy that `dial` names, TLS
/// for `https://` checked for the server's name, the upgrade with the
/// subprotocol, then the bytes in binary frames, as a stream. The end of
/// this side's bytes sends a Close at once: the SSH connection inside is
/// done.
pub async fn open(server: &Server, dial: &Dial<'_>) -> Result<Carried, ChiselError> {
    let key =
        crate::handshake::generate_key().map_err(|e| ChiselError::Connect(ConnectError::Config(e.to_string())))?;
    let request = upgrade::request(&server.url.host_header(), server.target(), &key);
    let (h, p, limit) = (server.host(), server.port(), dial.timeout);
    let stream = if server.tls() {
        let tls = client::open_tls(h, p, h, dial.trust, dial.proxy, limit).await;
        Stream::Tls(Box::new(tls.map_err(ChiselError::Connect)?))
    } else {
        let tcp = dial::dial(h, p, dial.proxy, limit).await;
        Stream::Plain(tcp.map_err(|e| ChiselError::Connect(ConnectError::Dial(e)))?)
    };
    let upgraded = tokio::time::timeout(limit, upgrade::upgrade(stream, request.as_bytes(), &key)).await;
    let late = |_| ChiselError::Connect(ConnectError::Timeout { step: "the WebSocket upgrade", after: limit });
    let (stream, pending) = upgraded.map_err(late)??;
    // No idle bound here: the SSH inside sends chisel's pings, and a quiet
    // session of the user's may last.
    let session = RelaySession::new(stream, pending, None, WRITE_TIMEOUT).naming(PEER);
    session.set_receive_cap(RECEIVE_CAP);
    let note: crate::forwarder::Note = std::sync::Arc::new(|_: &str| {});
    let (carried, _first) = carry::spawn(session, Form::Query, true, note, PEER);
    Ok(carried)
}

#[cfg(test)]
mod tests;
