//! The hellos of one connection with ECH (T-642): the name's list, a sealed
//! hello with it, one more with the server's retry configs where it sent
//! some, and a plain hello after any other failure, each on a TCP
//! connection of its own, one after another. A sealed hello's failure is
//! read by rustls's own error, never by its words.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::EchStatus;
use rustls::internal::msgs::codec::Codec as _;
use rustls::{ClientConfig, PeerIncompatible};
use rustls_pki_types::ServerName;

use super::cache::{self, Cache, Lookup, Why};
use super::{config, note, Mode, Outcome};
use crate::client::{ConnectError, RelayStream};
use crate::cut::TlsFailure;
use crate::dial::{self, ProxyChoice};
use crate::tls::{self, Trust};

/// The bound of a sealed hello's answer: a hop that drops sealed hellos
/// costs this, not the step's whole bound, before the plain hello.
pub const SEALED_WAIT: Duration = Duration::from_secs(10);

/// The bound of the read of a name's record, before the connection.
pub const READ_WITHIN: Duration = Duration::from_secs(4);

/// Where a connection goes, and how.
pub struct Dial<'a> {
    /// The host that TCP reaches, through `proxy`.
    pub host: &'a str,
    pub port: u16,
    /// The name that TLS checks, and that ECH seals.
    pub server_name: &'a str,
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// The bound of each step: the dial, and each handshake.
    pub limit: Duration,
    /// The protocols offered by ALPN; none for the relay's upgrade.
    pub alpn: &'a [&'a [u8]],
}

/// What follows a sealed hello that failed after its connection opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Next {
    /// The server refused it and sent these retry configs, as a list.
    Retry(Vec<u8>),
    /// It failed, and why: a plain hello comes next.
    Refused(String),
}

/// How one sealed hello ended, when it did not open.
enum Failed {
    /// No connection: the plain hello would meet the same.
    Dial(ConnectError),
    Next(Next),
}

/// The connection of `dial`, sealed with the list that `cache` holds for its
/// name or reads for it; plain where there is none, or after a refusal, but
/// in `strict`.
pub(super) async fn sealed(
    cache: &Cache,
    mode: Mode,
    dial: &Dial<'_>,
) -> Result<(RelayStream, Option<SocketAddr>), ConnectError> {
    let (name, proxy) = (dial.server_name, dial.proxy);
    let within = dial.limit.min(READ_WITHIN);
    let read = move || async move {
        let deadline = tokio::time::Instant::now() + within;
        crate::resolve::https::doh_https(name, proxy, deadline).await
    };
    let mut list = match cache.lookup(name, read).await {
        Lookup::List(list) => list,
        Lookup::None(Why::NotPublished) => return unsealed(mode, dial, Outcome::NotPublished).await,
        Lookup::None(Why::ReadFailed(why)) => return unsealed(mode, dial, Outcome::ReadFailed(why)).await,
        Lookup::None(Why::Cooled) => return unsealed(mode, dial, Outcome::Cooled).await,
    };
    let mut retried = false;
    loop {
        match attempt(&list, dial).await {
            Ok(opened) => {
                note(name, Outcome::Sealed { retried });
                return Ok(opened);
            }
            Err(Failed::Dial(e)) => return Err(e),
            // One retry, with what the server sent: they replace the list.
            Err(Failed::Next(Next::Retry(configs))) if !retried => {
                cache.remember(name, configs.clone(), cache::NO_TTL);
                (list, retried) = (configs, true);
            }
            Err(Failed::Next(Next::Retry(_))) => {
                cache.refused(name);
                let why = "the server refused the retry configs that it sent".to_string();
                return unsealed(mode, dial, Outcome::Refused(why)).await;
            }
            Err(Failed::Next(Next::Refused(why))) => {
                cache.refused(name);
                return unsealed(mode, dial, Outcome::Refused(why)).await;
            }
        }
    }
}

/// A plain hello after `outcome`, which is noted; none in `strict`.
async fn unsealed(
    mode: Mode,
    dial: &Dial<'_>,
    outcome: Outcome,
) -> Result<(RelayStream, Option<SocketAddr>), ConnectError> {
    if mode == Mode::Strict {
        let why = format!("{}: {}", dial.server_name, outcome.reason());
        note(dial.server_name, Outcome::Strict(why.clone()));
        return Err(ConnectError::Tls(TlsFailure::from(Outcome::Strict(why).words())));
    }
    note(dial.server_name, outcome);
    plain(dial).await
}

/// One sealed hello with `list`, on a connection of its own.
async fn attempt(list: &[u8], dial: &Dial<'_>) -> Result<(RelayStream, Option<SocketAddr>), Failed> {
    let config = config::sealed(dial.trust, dial.server_name, list, dial.alpn)
        .map_err(|why| Failed::Next(Next::Refused(why)))?;
    let name = server_name(dial).map_err(Failed::Dial)?;
    let tcp = dial::dial(dial.host, dial.port, dial.proxy, dial.limit)
        .await
        .map_err(|e| Failed::Dial(ConnectError::Dial(e)))?;
    let peer = tcp.peer_addr().ok();
    let wait = dial.limit.min(SEALED_WAIT);
    let tls = match tokio::time::timeout(wait, tokio_rustls::TlsConnector::from(config).connect(name, tcp)).await {
        Err(_) => {
            let why = format!("no answer to the sealed hello within {} s", wait.as_secs());
            return Err(Failed::Next(Next::Refused(why)));
        }
        Ok(Err(e)) => return Err(Failed::Next(after(&e))),
        Ok(Ok(tls)) => tls,
    };
    // rustls ends a handshake whose sealed hello the server did not open;
    // one that ended well was opened, which this reads again.
    if tls.get_ref().1.ech_status() != EchStatus::Accepted {
        return Err(Failed::Next(Next::Refused("the server did not confirm the sealed hello".into())));
    }
    Ok((tls, peer))
}

/// What follows a sealed hello that `error` ended: the retry configs of a
/// server that refused it with some, as an ECHConfigList; else why.
pub(super) fn after(error: &std::io::Error) -> Next {
    let rejected = match error.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::PeerIncompatible(PeerIncompatible::ServerRejectedEncryptedClientHello(configs))) => configs,
        _ => return Next::Refused(TlsFailure::of(error).why),
    };
    match rejected {
        Some(configs) if !configs.is_empty() => Next::Retry(configs.get_encoding()),
        _ => Next::Refused("the server refused the sealed hello and sent no retry configs".into()),
    }
}

/// The name that TLS checks, refused before anything connects.
fn server_name(dial: &Dial<'_>) -> Result<ServerName<'static>, ConnectError> {
    ServerName::try_from(dial.server_name.to_string())
        .map_err(|e| ConnectError::Config(format!("{:?} is not a valid server name: {e}", dial.server_name)))
}

/// A plain hello, as each road makes it: the trust's own configuration, and
/// with ALPN a copy of it that offers `dial.alpn`.
pub(super) async fn plain(dial: &Dial<'_>) -> Result<(RelayStream, Option<SocketAddr>), ConnectError> {
    let tcp = dial::dial(dial.host, dial.port, dial.proxy, dial.limit).await.map_err(ConnectError::Dial)?;
    let peer = tcp.peer_addr().ok();
    if dial.alpn.is_empty() {
        let tls = crate::tls_wrap::tls_over(tcp, dial.server_name, dial.trust, dial.limit).await?;
        return Ok((tls, peer));
    }
    let kept = tls::config_for(dial.trust).map_err(|e| ConnectError::Config(e.to_string()))?;
    let mut config: ClientConfig = (*kept).clone();
    config.alpn_protocols = dial.alpn.iter().map(|p| p.to_vec()).collect();
    let name = server_name(dial)?;
    let tls = tokio::time::timeout(dial.limit, tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp))
        .await
        .map_err(|_| ConnectError::Timeout { step: "the TLS handshake", after: dial.limit })?
        .map_err(|e| ConnectError::Tls(TlsFailure::of(&e)))?;
    Ok((tls, peer))
}

#[cfg(test)]
#[path = "road_tests.rs"]
mod tests;
