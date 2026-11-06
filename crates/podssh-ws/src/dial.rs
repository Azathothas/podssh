//! Opening the TCP connection to the relay: `pod-proxy` of PodUtils/podcrates
//! with podssh's settings ([`settings`]) and podssh's resolver ([`Resolver`],
//! the order of [`crate::resolve`]). Directly, or through an HTTP CONNECT
//! proxy or a SOCKS5 proxy named by the environment (`https_proxy`,
//! `HTTPS_PROXY`, `all_proxy`, `ALL_PROXY`, minus anything
//! `no_proxy`/`NO_PROXY` excludes), read at each dial.
//!
//! On the hosts podssh is for, the proxy is often the only way out: a direct
//! `connect()` is refused or silently dropped and DNS does not resolve, while
//! the proxy accepts `CONNECT name:443` and resolves the name itself. So an
//! HTTP proxy and a `socks5h://` proxy get the relay's *name*, never an
//! address, and this host needs no DNS. A `socks5://` proxy gets the address
//! that podssh's resolver gives, as curl does.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pod_core::{BoxFuture, Class, Failure, Found, Resolve};
use pod_proxy::{Dialer, Environment, Settings};
use tokio::net::TcpStream;
use tokio::time::Instant;

pub use pod_proxy::env::{is_loopback, no_proxy_entry, no_proxy_matches, NO_PROXY_VARS, PROXY_VARS};
pub use pod_proxy::host::{authority, check_name, split_host_port};
pub use pod_proxy::http::parse_status_line;
pub use pod_proxy::{interleave, DialError, HttpProxy, Multipath, Proxy, ProxyKind, ATTEMPT_DELAY};
// The stage of a [`DialError::Timeout`]: the proxy, the connection, the
// resolution.
pub use pod_core::Stage;

use crate::resolve;

/// How to reach the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyChoice {
    /// Use the proxy the environment names, if any (the default).
    FromEnvironment,
    /// Connect directly and ignore the environment.
    Direct,
    /// Use this proxy.
    Via(Proxy),
}

/// podssh's settings of the dial for `proxy`: the program in the words of a
/// refusal, its user agent, the unsent bytes of each socket, the attempt
/// delay; the environment of the process read now. Multipath TCP is asked
/// for with `multipath` alone.
pub fn settings(proxy: &ProxyChoice, multipath: bool) -> Settings {
    let proxy = match proxy {
        ProxyChoice::FromEnvironment => pod_proxy::ProxyChoice::FromEnvironment(environment()),
        ProxyChoice::Direct => pod_proxy::ProxyChoice::Direct,
        ProxyChoice::Via(p) => pod_proxy::ProxyChoice::Via(p.clone()),
    };
    let mut settings = Settings::new("podssh", proxy);
    settings.user_agent = Some(user_agent());
    settings.multipath = multipath;
    settings
}

/// `podssh/VERSION`: the `User-Agent` of a CONNECT and of each request.
pub fn user_agent() -> String {
    format!("podssh/{}", env!("CARGO_PKG_VERSION"))
}

/// The proxy variables of the process, read now: a test or a command that
/// sets one sees it at its next dial.
fn environment() -> Environment {
    Environment::read(&|name| std::env::var_os(name))
}

/// The dialer of `proxy`, over podssh's resolver.
pub fn dialer(proxy: &ProxyChoice, multipath: bool) -> Dialer {
    Dialer::new(settings(proxy, multipath), Arc::new(Resolver))
}

// The dial of the TLS roads, which gives rustls the bare TCP stream.
mod bare;
pub use bare::Bare;

/// The proxy, if any, the process environment selects for `target_host`. A
/// loopback target never goes through a proxy (as in Go's net/http): the
/// proxy's loopback is not this host's, and podvm measured a proxy answering
/// 405 to `CONNECT 127.0.0.1`. A name that `--relay-addr` or
/// `PODSSH_RELAY_ADDR` pins to loopback addresses alone is such a target too
/// (T-318).
pub fn proxy_from_env(target_host: &str) -> Result<Option<Proxy>, String> {
    environment().proxy_for(target_host, &resolve::pinned(target_host))
}

/// Open a TCP connection to `host:port`, through the proxy `proxy` selects.
/// The whole operation (resolution, connect, and the exchange with a proxy)
/// is bounded by `timeout`.
pub async fn dial(host: &str, port: u16, proxy: &ProxyChoice, timeout: Duration) -> Result<TcpStream, DialError> {
    dialer(proxy, false).tcp(host, port, timeout).await
}

/// [`dial`], with Multipath TCP asked for (T-172, [`crate::mptcp`]): only a
/// connection with no proxy can carry it, and only Linux makes it. Else, and
/// where the kernel refuses it, the stream is plain TCP, as [`dial`] gives
/// it; the second value says which, and why.
pub async fn dial_multipath(
    host: &str,
    port: u16,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<(TcpStream, Multipath), DialError> {
    dialer(proxy, true).tcp_multipath(host, port, timeout).await
}

/// podssh's resolver as the dial asks it: the order of [`crate::resolve`]
/// (an IP literal, the pins, the system resolver, the cache, DNS over
/// HTTPS, the old cache), each source by its place in [`resolve::ORDER`].
/// The dial tells it the source of each address that connected, for
/// `podssh doctor` and for the cache.
#[derive(Debug, Clone, Copy, Default)]
pub struct Resolver;

/// The source of the resolver as `pod-core` names it: its place in the
/// order, and a word.
fn source_of(source: resolve::Source) -> pod_core::Source {
    let rank = resolve::ORDER.iter().position(|s| *s == source).unwrap_or_default() as u8;
    let name = match source {
        resolve::Source::Literal => "literal",
        resolve::Source::Pin => "pin",
        resolve::Source::System => "system",
        resolve::Source::Cache => "cache",
        resolve::Source::Doh => "doh",
        resolve::Source::OldCache => "old-cache",
    };
    pod_core::Source { rank, name }
}

/// The source of the resolver of a `pod-core` source.
fn source_from(source: pod_core::Source) -> Option<resolve::Source> {
    resolve::ORDER.get(usize::from(source.rank)).copied()
}

impl Resolve for Resolver {
    fn label(&self) -> String {
        "podssh's resolver".into()
    }

    fn resolve_from<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        deadline: Instant,
        after: Option<pod_core::Source>,
    ) -> BoxFuture<'a, Result<Found, Failure>> {
        Box::pin(async move {
            let after = after.and_then(source_from);
            match resolve::resolve_from(host, port, deadline, after).await {
                Ok(found) => Ok(Found { addrs: found.addrs, source: source_of(found.source), more: found.more }),
                Err(detail) => Err(Failure::new(Stage::Dns, Class::Unavailable, detail)),
            }
        })
    }

    fn pinned(&self, host: &str) -> Vec<IpAddr> {
        resolve::pinned(host)
    }

    fn note_dialed(&self, host: &str, peer: SocketAddr, source: pod_core::Source) {
        if let Some(source) = source_from(source) {
            resolve::note_dialed(host, peer, source);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each source of podssh's order keeps its place through `pod-core`.
    #[test]
    fn each_source_of_the_order_comes_back_as_it_went() {
        for source in resolve::ORDER {
            assert_eq!(source_from(source_of(source)), Some(source), "{source:?}");
        }
        assert_eq!(source_from(pod_core::Source { rank: 6, name: "other" }), None);
    }

    /// podssh's words and its user agent: a refusal names podssh.
    #[test]
    fn the_settings_are_podssh_s() {
        let direct = settings(&ProxyChoice::Direct, true);
        assert_eq!((direct.app.as_str(), direct.multipath), ("podssh", true));
        assert_eq!(direct.proxy, pod_proxy::ProxyChoice::Direct);
        assert_eq!(direct.user_agent, Some(format!("podssh/{}", env!("CARGO_PKG_VERSION"))));
        assert_eq!(direct.lowat, Some(pod_proxy::lowat::LOWAT));
        let via = Proxy::parse("socks5h://proxy.example:1080").unwrap();
        let chosen = settings(&ProxyChoice::Via(via.clone()), false);
        assert_eq!((chosen.proxy, chosen.multipath), (pod_proxy::ProxyChoice::Via(via), false));
    }
}
