//! The way to a Piping Server: TCP through `HTTPS_PROXY` when one is set
//! (podssh-ws's dialer), then TLS verified with podssh-ws's provider and
//! trust store, offering HTTP/2 and HTTP/1.1 by ALPN. `ppng.io` takes `h2`
//! (read on 2026-11-02), so a node's door and each of its links share one
//! connection; a server or a proxy that takes HTTP/1.1 alone gets that. A
//! caller's own TLS configuration (`Trust::caller`) is used as it is, with
//! no ALPN, so HTTP/1.1.
//!
//! A [`Dial`] gives the stream and its protocol, so that a test gives the
//! loopback's TCP in place of TLS, as a Piping Server on the loopback serves
//! cleartext.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};

use super::server::Server;

/// The bound of the TCP connection, and of TLS, each.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(20);
/// ALPN's names of the two protocols.
pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_H1: &[u8] = b"http/1.1";

/// The protocol of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    H1,
    H2,
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Proto::H1 => "HTTP/1.1",
            Proto::H2 => "HTTP/2",
        })
    }
}

/// A byte stream to a server.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;
/// A dial in progress.
pub type Dialing = Pin<Box<dyn Future<Output = Result<(BoxIo, Proto), String>> + Send>>;
/// How to reach a server: TLS through the proxy ([`tls`]), or a test's TCP.
pub type Dial = Arc<dyn Fn(&Server) -> Dialing + Send + Sync>;

/// TLS to each server, through `proxy`, verified with `trust`.
pub fn tls(trust: Trust, proxy: ProxyChoice) -> Dial {
    Arc::new(move |server: &Server| -> Dialing {
        let (server, trust, proxy) = (server.clone(), trust.clone(), proxy.clone());
        Box::pin(async move {
            let shown = server.to_string();
            let config = config(&trust).map_err(|why| format!("{shown}: {why}"))?;
            let name = rustls::pki_types::ServerName::try_from(server.host.clone())
                .map_err(|e| format!("{shown}: {:?} is not a server name: {e}", server.host))?;
            let tcp = podssh_ws::dial::dial(&server.host, server.port, &proxy, CONNECT_LIMIT)
                .await
                .map_err(|e| format!("{shown}: {e}"))?;
            let connector = tokio_rustls::TlsConnector::from(config);
            let tls = match tokio::time::timeout(CONNECT_LIMIT, connector.connect(name, tcp)).await {
                Err(_) => return Err(format!("{shown}: no TLS within {} s", CONNECT_LIMIT.as_secs())),
                Ok(Err(e)) => return Err(format!("{shown}: {}", podssh_ws::tls::handshake_failure(&e))),
                Ok(Ok(tls)) => tls,
            };
            let proto = if tls.get_ref().1.alpn_protocol() == Some(ALPN_H2) { Proto::H2 } else { Proto::H1 };
            Ok((Box::new(tls) as BoxIo, proto))
        })
    })
}

/// podssh's configuration for `trust`, offering both protocols; a caller's
/// own, unchanged.
fn config(trust: &Trust) -> Result<Arc<rustls::ClientConfig>, String> {
    let base = podssh_ws::tls::config_for(trust).map_err(|e| e.to_string())?;
    if matches!(trust, Trust::Caller(_)) {
        return Ok(base);
    }
    let mut config = (*base).clone();
    config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn podssh_s_own_trust_offers_h2_then_http_1_1() {
        let config = config(&Trust::Default).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let unchanged = podssh_ws::tls::config_for(&Trust::Default).unwrap();
        assert!(unchanged.alpn_protocols.is_empty(), "the relay's configuration keeps no ALPN");
    }
}
