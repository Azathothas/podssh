//! A bridge's pluggable transport, answered in this process (T-385). Arti
//! reaches a transport that it does not manage as a SOCKS5 proxy at the
//! transport's `proxy_addr`, through its runtime's TCP provider: podssh's
//! ([`crate::runtime`]). Each of podssh's two transports has a sentinel
//! address there, and the provider answers a dial of one with one end of a
//! pipe in memory; a task here holds the other end, answers Arti's SOCKS5
//! handshake ([`crate::socks`]), whose user and password carry the bridge's
//! arguments, opens the transport through podssh-ws (its dial, its proxy,
//! its TLS), says whether it opened, and carries the bytes.
//!
//! Nothing binds, listens or starts (`AGENTS.md`, section 5, rules 2 and 3):
//! a sentinel is a key that the provider matches, never dialled. That Arti
//! dials a transport through its runtime is its code at 0.47, not a promise
//! of its API; a test drives Arti's own client against the sentinel, so
//! that a release which changes it fails there.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::pt::Reach;
use tokio::io::DuplexStream;

use crate::socks;

/// How long a transport's dial and TLS may take: Arti gives a channel
/// through a transport 10 s for those and its own handshake.
pub const TRANSPORT_WAIT: Duration = Duration::from_secs(10);
/// How long Arti's SOCKS5 handshake may take, in memory.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);
/// The pipe in memory, each way.
const PIPE: usize = 256 * 1024;

/// A transport that podssh speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Meek,
    WebTunnel,
}

impl Kind {
    /// Each one, in the order of the configuration.
    pub const ALL: [Kind; 2] = [Kind::Meek, Kind::WebTunnel];

    /// Its name in a bridge line, and in Arti's configuration.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Meek => "meek_lite",
            Kind::WebTunnel => "webtunnel",
        }
    }

    /// The transport of a bridge line's name.
    pub fn by_name(name: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Its sentinel: a loopback address of a port that nothing serves, as
    /// Arti warns of a transport elsewhere; a key, never dialled.
    pub fn at(self) -> SocketAddr {
        let port = match self {
            Kind::Meek => 1,
            Kind::WebTunnel => 2,
        };
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    /// The transport whose sentinel `addr` is.
    pub fn by_addr(addr: &SocketAddr) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.at() == *addr)
    }
}

/// The last failure of a transport, shared with whoever made the runtime:
/// Arti says only that a channel failed, and the bootstrap's failure names
/// this one ([`crate::client`]).
#[derive(Debug, Clone, Default)]
pub struct Said(Arc<Mutex<Option<String>>>);

impl Said {
    /// The last failure, if any.
    pub fn last(&self) -> Option<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set(&self, line: String) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(line);
    }
}

/// Arti's end of a pipe whose far end, a task, serves `kind` with `reach`.
pub(crate) fn spawn(kind: Kind, reach: Reach, said: Said) -> DuplexStream {
    let (arti, far) = tokio::io::duplex(PIPE);
    tokio::spawn(serve(kind, far, reach, said));
    arti
}

/// An open transport.
enum Open {
    // A session holds its fronts and its reach; boxed, as the stream is small.
    Meek(Box<podssh_ws::meek::Session>),
    WebTunnel(podssh_ws::url::Stream),
}

/// The far end: the handshake, the transport, then its bytes.
async fn serve(kind: Kind, mut far: DuplexStream, reach: Reach, said: Said) {
    let name = kind.name();
    let raw = match tokio::time::timeout(HANDSHAKE_WAIT, socks::accept(&mut far)).await {
        Ok(Ok(raw)) => raw,
        Ok(Err(why)) => return said.set(format!("{name}: Arti's SOCKS5 handshake: {why}")),
        Err(_) => return said.set(format!("{name}: no SOCKS5 handshake within {} s", HANDSHAKE_WAIT.as_secs())),
    };
    let opened = match socks::settings(&raw) {
        Ok(settings) => open(kind, &settings, &reach).await,
        Err(why) => Err(why),
    };
    let carried = match opened {
        Ok(carried) => carried,
        Err(why) => {
            said.set(format!("{name}: {why}"));
            let _ = socks::reply(&mut far, socks::FAILED).await;
            return;
        }
    };
    if socks::reply(&mut far, socks::SUCCEEDED).await.is_err() {
        // Arti gave up on the channel while the transport opened.
        return;
    }
    match carried {
        Open::Meek(session) => {
            if let Some(why) = (*session).carry(far).await.failure() {
                said.set(format!("{name}: {why}"));
            }
        }
        Open::WebTunnel(mut stream) => {
            if let Err(e) = tokio::io::copy_bidirectional(&mut far, &mut stream).await {
                said.set(format!("{name}: the bridge's connection: {e}"));
            }
        }
    }
}

/// `kind` opened for a bridge's `settings`.
async fn open(kind: Kind, settings: &[(String, String)], reach: &Reach) -> Result<Open, String> {
    match kind {
        Kind::Meek => {
            let args = podssh_ws::meek::Args::parse(settings)?;
            podssh_ws::meek::open(&args, reach).await.map(|session| Open::Meek(Box::new(session)))
        }
        Kind::WebTunnel => {
            let args = podssh_ws::webtunnel::Args::parse(settings)?;
            podssh_ws::webtunnel::open(&args, reach).await.map(Open::WebTunnel)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_transport_has_a_sentinel_of_its_own_on_the_loopback() {
        for kind in Kind::ALL {
            assert_eq!(Kind::by_addr(&kind.at()), Some(kind));
            assert_eq!(Kind::by_name(kind.name()), Some(kind));
            assert!(kind.at().ip().is_loopback());
        }
        assert_ne!(Kind::Meek.at(), Kind::WebTunnel.at());
        assert_eq!(Kind::by_addr(&"127.0.0.1:443".parse().unwrap()), None);
        assert_eq!(Kind::by_name("obfs4"), None);
    }
}
