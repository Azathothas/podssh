//! A WebSocket session over plain TCP to the loopback, for tests only
//! (feature `plain-ws`, T-068): the tests of an embedder (podbox) and a
//! stand-in relay then need no CA. A token over plain TCP must not leave the
//! host, so a host that is not the loopback is refused before any
//! connection, each address that a name resolves to must be the loopback
//! too, and no proxy is used. The binary never enables the feature.

use std::time::Duration;

use tokio::net::TcpStream;

use crate::client::{upgrade, ConnectError, Endpoint, WsClientConfig, WRITE_TIMEOUT};
use crate::dial::{self, DialError, ProxyChoice};
use crate::session::RelaySession;
use crate::tls::Trust;

/// Connect to `host:port` on the loopback over plain TCP, and upgrade at
/// `path` with `token` in the `X-Relay-Token` header, as [`crate::connect`]
/// does over TLS.
pub async fn connect_loopback(
    host: &str,
    port: u16,
    path: &str,
    token: &str,
    timeout: Duration,
    idle: Option<Duration>,
) -> Result<RelaySession<TcpStream>, ConnectError> {
    if !dial::is_loopback(host) {
        return Err(ConnectError::Config(format!(
            "plain ws:// goes only to the loopback, and {host:?} is not: a token over plain TCP \
             must not leave this host"
        )));
    }
    // The rules of a path and a token are those of `connect`.
    let config = WsClientConfig {
        endpoint: Endpoint { host: host.to_string(), port, path: path.to_string() },
        trust: Trust::Default,
        server_name: host.to_string(),
        timeout,
        idle_timeout: idle,
        proxy: ProxyChoice::Direct,
    };
    config.validate().map_err(ConnectError::Config)?;
    if token.contains(['\r', '\n']) {
        return Err(ConnectError::Config("the relay token contains a line break".into()));
    }
    let name = host.trim_start_matches('[').trim_end_matches(']');
    let addrs = tokio::time::timeout(timeout, tokio::net::lookup_host((name, port)))
        .await
        .map_err(|_| ConnectError::Timeout { step: "resolving the loopback name", after: timeout })?
        .map_err(|e| ConnectError::Dial(DialError::Resolve { host: name.to_string(), detail: e.to_string() }))?;
    // A name such as `x.localhost` goes through the resolver: only a
    // loopback answer is used, so the token stays on this host.
    let Some(addr) = addrs.into_iter().find(|a| a.ip().is_loopback()) else {
        return Err(ConnectError::Config(format!("{name:?} resolved to no loopback address")));
    };
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| ConnectError::Timeout { step: "the TCP connection", after: timeout })?
        .map_err(|e| ConnectError::Dial(DialError::Connect { target: addr.to_string(), detail: e.to_string() }))?;
    let host_header = dial::authority(name, port);
    let (tcp, pending) = tokio::time::timeout(timeout, upgrade(tcp, &host_header, path, token))
        .await
        .map_err(|_| ConnectError::Timeout { step: "the WebSocket upgrade", after: timeout })??;
    Ok(RelaySession::new(tcp, pending, idle, WRITE_TIMEOUT))
}
