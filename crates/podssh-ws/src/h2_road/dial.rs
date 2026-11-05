//! A connection of the road (T-321): TCP through the proxy, as each road
//! dials; TLS of this road's own, which offers `h2` then `http/1.1` and
//! shares the trust's cache of sessions, so that the upgrade's connection
//! after it resumes TLS; and on `h2`, HTTP/2's handshake with the road's
//! windows, then a PING. The server's SETTINGS are its first frame (RFC 9113
//! section 3.4), so they are read once the PING's answer came, and no
//! request goes before them, as RFC 8441 section 3 asks. And the probe of
//! `podssh doctor`, which sends nothing more.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;

use super::pool::{self, Conn, Driven};
use super::{Fallback, CONNECTION_WINDOW, H2, HTTP1, STREAMS, STREAM_WINDOW};
use crate::client::{ConnectError, RelayStream, WsClientConfig};
use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// What a new connection gave.
pub(super) enum Dialed {
    /// HTTP/2 whose SETTINGS offered extended CONNECT.
    H2(Conn),
    /// TLS chose `http/1.1`, or no protocol: the connection, for the upgrade,
    /// and the address of its TCP.
    Http1(Box<RelayStream>, Option<SocketAddr>),
    /// HTTP/2 that the road cannot take, closed already, and why.
    Lacks(Fallback),
}

/// A new connection for `config`'s host.
pub(super) async fn dial(config: &WsClientConfig) -> Result<Dialed, ConnectError> {
    let at = &config.endpoint;
    let (tls, peer) =
        open(&at.host, at.port, &config.server_name, &config.trust, &config.proxy, config.timeout).await?;
    if tls.get_ref().1.alpn_protocol() != Some(H2) {
        return Ok(Dialed::Http1(Box::new(tls), peer));
    }
    let (sender, driven) = match settled(tls, config.timeout).await {
        Ok(settled) => settled,
        Err(why) => return Ok(Dialed::Lacks(Fallback::Carried(why))),
    };
    // No `:protocol` where the server did not offer it: a server that does
    // not know it reads the request as malformed.
    if !sender.is_extended_connect_protocol_enabled() {
        // Closed before the upgrade's connection opens.
        driven.close().await;
        return Ok(Dialed::Lacks(Fallback::NotOffered));
    }
    let most = sender.current_max_send_streams().clamp(1, STREAMS);
    Ok(Dialed::H2(Conn::of(sender, peer, most, driven)))
}

/// TCP to `host:port` through `proxy`, and TLS for `server_name` with the
/// roots of `trust`, offering this road's protocols; and the address of the
/// TCP.
async fn open(
    host: &str,
    port: u16,
    server_name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
) -> Result<(RelayStream, Option<SocketAddr>), ConnectError> {
    // Sealed where the user asked for ECH and the name publishes a list, with
    // this road's protocols (T-642); else a copy of the trust's own
    // configuration with them: the same verifier and the same cache of
    // sessions.
    crate::client::open_tls_offering(host, port, server_name, trust, proxy, limit, &[H2, HTTP1]).await
}

/// HTTP/2's handshake on `tls`, its connection driven in a task, and its
/// SETTINGS read; `Err` once the connection is closed again.
async fn settled(tls: RelayStream, limit: Duration) -> Result<(SendRequest<Bytes>, Driven), String> {
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(STREAM_WINDOW).initial_connection_window_size(CONNECTION_WINDOW).enable_push(false);
    let (sender, mut connection) = match tokio::time::timeout(limit, builder.handshake::<_, Bytes>(tls)).await {
        Ok(Ok(made)) => made,
        Ok(Err(e)) => return Err(format!("HTTP/2's handshake: {e}")),
        Err(_) => return Err(format!("HTTP/2's handshake did not end within {} s", limit.as_secs())),
    };
    let ping = connection.ping_pong();
    let driven = pool::drive(async move {
        let _ = connection.await;
    });
    let Some(mut ping) = ping else {
        driven.close().await;
        return Err("HTTP/2 gave no PING to send".into());
    };
    match tokio::time::timeout(limit, ping.ping(h2::Ping::opaque())).await {
        Ok(Ok(_)) => Ok((sender, driven)),
        Ok(Err(e)) => {
            driven.close().await;
            Err(format!("HTTP/2's PING: {e}"))
        }
        Err(_) => {
            driven.close().await;
            Err(format!("no answer to HTTP/2's PING within {} s", limit.as_secs()))
        }
    }
}

/// What a host offers the road, as `podssh doctor` says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offered {
    /// The protocol that TLS chose of `h2` and `http/1.1`, or none.
    pub alpn: Option<String>,
    /// On `h2`: whether its SETTINGS offered extended CONNECT.
    pub extended: Option<bool>,
    /// On `h2`: its streams at once, by its SETTINGS.
    pub streams: Option<usize>,
}

impl Offered {
    /// What was offered, in words.
    pub fn words(&self) -> String {
        let streams = match self.streams {
            Some(n) if n < 1 << 20 => format!("{n} streams at once"),
            _ => "no bound on its streams".to_string(),
        };
        match (self.alpn.as_deref(), self.extended) {
            (None, _) => "its TLS chose no protocol by ALPN: HTTP/1.1".into(),
            (Some(alpn), None) => format!("its TLS chose {alpn}, not h2"),
            (Some(_), Some(true)) => {
                format!("its TLS chose h2, whose SETTINGS offer extended CONNECT (RFC 8441), {streams}")
            }
            (Some(_), Some(false)) => "its TLS chose h2, whose SETTINGS offer no extended CONNECT (RFC 8441)".into(),
        }
    }
}

/// What `host:port` offers the road, with nothing sent but HTTP/2's
/// preface, its SETTINGS and a PING, all within `limit` each: TLS checked
/// for `server_name` as each road checks it, through `proxy`.
pub async fn probe(
    host: &str,
    port: u16,
    server_name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
) -> Result<Offered, ConnectError> {
    if matches!(trust, Trust::Caller(_)) {
        let why = "the caller's own TLS configuration is used as it is, with no ALPN";
        return Err(ConnectError::Config(why.into()));
    }
    let (tls, _) = open(host, port, server_name, trust, proxy, limit).await?;
    // Of the two offered: rustls takes no other answer.
    let alpn = tls.get_ref().1.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
    if alpn.as_deref().map(str::as_bytes) != Some(H2) {
        return Ok(Offered { alpn, extended: None, streams: None });
    }
    let (sender, driven) = settled(tls, limit).await.map_err(ConnectError::Http)?;
    let offered = Offered {
        alpn,
        extended: Some(sender.is_extended_connect_protocol_enabled()),
        streams: Some(sender.current_max_send_streams()),
    };
    driven.close().await;
    Ok(offered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_host_offers_is_said() {
        let of = |alpn: Option<&str>, extended, streams| Offered { alpn: alpn.map(String::from), extended, streams };
        assert_eq!(of(None, None, None).words(), "its TLS chose no protocol by ALPN: HTTP/1.1");
        assert_eq!(of(Some("http/1.1"), None, None).words(), "its TLS chose http/1.1, not h2");
        let yes = of(Some("h2"), Some(true), Some(16)).words();
        assert!(yes.contains("offer extended CONNECT (RFC 8441), 16 streams at once"), "{yes}");
        assert!(of(Some("h2"), Some(false), Some(256)).words().contains("offer no extended CONNECT"));
        assert!(of(Some("h2"), Some(true), Some(usize::MAX)).words().ends_with("no bound on its streams"));
    }
}
