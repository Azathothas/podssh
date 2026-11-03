//! The ways to an OpenTunnel service: TLS to its API's host through
//! `HTTPS_PROXY` when one is set, verified with podssh-ws's provider and
//! trust store, for the API and the bridges ([`tls`]); and a TCP stream
//! through the same proxy to a tunnel's name on port 443, before TLS, for a
//! client, whose TLS goes to the node and is checked there ([`tcp`]). The
//! proxy gets the name, never an address, so the host needs no DNS. No
//! credential of podssh's goes to the service: the bearer token of a tunnel
//! is the service's own, in a header alone.
//!
//! A [`Dial`] and a [`Visit`] give byte streams, so that a test gives pipes
//! to a stand-in in their place.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};

use super::Service;

/// The bound of the TCP connection, and of TLS, each.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(20);

/// A byte stream to the service.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;
/// A dial in progress.
pub type Dialing = Pin<Box<dyn Future<Output = Result<BoxIo, String>> + Send>>;
/// How to reach the API's host, after TLS: [`tls`], or a test's pipe.
pub type Dial = Arc<dyn Fn(&Service) -> Dialing + Send + Sync>;
/// How a client reaches a tunnel's name on port 443, before TLS: [`tcp`],
/// or a test's pipe.
pub type Visit = Arc<dyn Fn(&str) -> Dialing + Send + Sync>;

/// TLS to the service's API host, through `proxy`, verified with `trust`.
pub fn tls(trust: Trust, proxy: ProxyChoice) -> Dial {
    Arc::new(move |service: &Service| -> Dialing {
        let (service, trust, proxy) = (service.clone(), trust.clone(), proxy.clone());
        Box::pin(async move {
            let host = service.host.as_str();
            let opened = podssh_ws::client::open_tls(host, service.port, host, &trust, &proxy, CONNECT_LIMIT);
            let tls = opened.await.map_err(|e| format!("{service}: {e}"))?;
            Ok(Box::new(tls) as BoxIo)
        })
    })
}

/// TCP to each name on port 443, through `proxy`.
pub fn tcp(proxy: ProxyChoice) -> Visit {
    Arc::new(move |name: &str| -> Dialing {
        let (name, proxy) = (name.to_string(), proxy.clone());
        Box::pin(async move {
            let tcp = podssh_ws::dial::dial(&name, super::PORT, &proxy, CONNECT_LIMIT)
                .await
                .map_err(|e| format!("{name}:{}: {e}", super::PORT))?;
            Ok(Box::new(tcp) as BoxIo)
        })
    })
}
