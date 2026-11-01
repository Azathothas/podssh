//! A client of Tor: Arti on podssh's runtime ([`crate::runtime`]), its state
//! and its copy of the directory in podssh's cache, bootstrapped once for a
//! run, then a stream through a circuit to each `host:port` that the run
//! asks for. The exit resolves the name, so no name of a target is resolved
//! here, and none leaves this host but inside Tor.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::{CfgPath, TorClientConfigBuilder};
use arti_client::{DataStream, TorClient};
use podssh_ws::dial::ProxyChoice;
use tor_netdoc::types::policy::AddrPortPattern;
use tor_rtcompat::tokio::TokioRustlsRuntime;
use tor_rtcompat::{CompoundRuntime, RuntimeSubstExt as _};

use crate::runtime::{ProxiedTcp, CONNECT_WAIT};

/// The runtime of the client: tokio and rustls, with podssh's TCP provider.
pub type Runtime = CompoundRuntime<
    TokioRustlsRuntime,
    TokioRustlsRuntime,
    TokioRustlsRuntime,
    ProxiedTcp,
    TokioRustlsRuntime,
    TokioRustlsRuntime,
    TokioRustlsRuntime,
>;

/// What a client needs.
#[derive(Debug, Clone)]
pub struct Options {
    /// Arti's state: its guards, kept between runs, as Tor asks.
    pub state_dir: PathBuf,
    /// Arti's copy of the directory, so that a later run starts sooner.
    pub cache_dir: PathBuf,
    /// The proxy of each first hop.
    pub proxy: ProxyChoice,
    /// The ports that a first hop may have, or `None` for any: through a
    /// proxy that allows 443 alone, a guard on 9001 can never be reached.
    pub first_hop_ports: Option<Vec<u16>>,
    /// Whether Arti may skip its check of the directories' owners and modes,
    /// which a sandbox's mounts can fail although only this user writes them.
    pub trust_directories: bool,
    /// Another Tor network than Tor's own: the TOML of arti-client's
    /// configuration, as chutney writes it for a network of its own
    /// (`arti.toml`), whose authorities, caches and rules of paths replace
    /// Tor's. The directories, the proxy and the first hops above still hold.
    pub network: Option<String>,
    /// Bridges (T-385): with any, Arti's first hops are these alone,
    /// through their transports, and `first_hop_ports` does not hold.
    pub bridges: Vec<crate::bridges::Bridge>,
    /// The roots that a bridge's transport checks its TLS with.
    pub trust: podssh_ws::Trust,
}

/// Why the client could not be made, or a stream not opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// What failed: "the configuration", "the bootstrap", "the stream".
    pub step: &'static str,
    /// Arti's words, and its kind of error.
    pub detail: String,
    /// Whether Arti refused the directories' owners or modes.
    pub permissions: bool,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.step, self.detail)
    }
}

fn failure(step: &'static str, e: impl std::fmt::Display) -> Failure {
    Failure { step, detail: e.to_string(), permissions: false }
}

fn arti_failure(step: &'static str, e: &arti_client::Error) -> Failure {
    use tor_error::HasKind as _;
    let kind = e.kind();
    Failure { step, detail: format!("{e} ({kind})"), permissions: kind == tor_error::ErrorKind::FsPermissions }
}

/// The patterns of [`Options::first_hop_ports`], as Arti reads them.
pub fn reachable(ports: &[u16]) -> Result<Vec<AddrPortPattern>, String> {
    ports.iter().map(|p| format!("*:{p}").parse::<AddrPortPattern>().map_err(|e| format!("*:{p}: {e}"))).collect()
}

/// A client of Tor, bootstrapped.
pub struct Tor {
    client: Arc<TorClient<Runtime>>,
}

impl Tor {
    /// Make the client and bootstrap it, within `wait`: Arti fetches what it
    /// lacks of the directory and builds a first circuit. It must run inside
    /// a tokio runtime, with a default `CryptoProvider` of rustls installed.
    pub async fn bootstrap(options: &Options, wait: Duration) -> Result<Tor, Failure> {
        let base = TokioRustlsRuntime::current().map_err(|e| failure("the runtime", e))?;
        let tcp = ProxiedTcp::new(options.proxy.clone(), CONNECT_WAIT).with_trust(options.trust.clone());
        let said = tcp.said();
        let runtime: Runtime = base.with_tcp_provider(tcp);
        let mut builder = match &options.network {
            Some(text) => {
                // A transport there could be a program that Arti starts.
                crate::bridges::refuse_transports(text).map_err(|e| failure("the configuration", e))?;
                toml::from_str::<TorClientConfigBuilder>(text)
                    .map_err(|e| failure("the configuration", format!("the network's configuration: {e}")))?
            }
            None => TorClientConfigBuilder::default(),
        };
        // podssh's directories, as `from_directories` sets them, whatever the
        // network's configuration names.
        builder
            .storage()
            .cache_dir(CfgPath::new_literal(&options.cache_dir))
            .state_dir(CfgPath::new_literal(&options.state_dir));
        if options.trust_directories {
            builder.storage().permissions().dangerously_trust_everyone();
        }
        if !options.bridges.is_empty() {
            crate::bridges::apply(&mut builder, &options.bridges).map_err(|e| failure("the configuration", e))?;
        } else if let Some(ports) = &options.first_hop_ports {
            let list = builder.path_rules().reachable_addrs();
            list.clear();
            for pattern in reachable(ports).map_err(|e| failure("the configuration", e))? {
                list.push(pattern);
            }
        }
        let config = builder.build().map_err(|e| failure("the configuration", e))?;
        let builder = TorClient::with_runtime(runtime).config(config);
        // Arti says that a channel failed; a bridge's transport says why.
        let transport =
            || said.last().map_or_else(String::new, |why| format!("; the last failure of a transport: {why}"));
        let client = match tokio::time::timeout(wait, builder.create_bootstrapped()).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                let mut failed = arti_failure("the bootstrap", &e);
                failed.detail.push_str(&transport());
                return Err(failed);
            }
            Err(_) => {
                return Err(failure("the bootstrap", format!("not done within {} s{}", wait.as_secs(), transport())));
            }
        };
        Ok(Tor { client })
    }

    /// A stream to `host:port` through a circuit, within `wait`; the exit
    /// resolves `host`. The stream keeps the client, whose channels carry it.
    pub async fn connect(&self, host: &str, port: u16, wait: Duration) -> Result<TorStream, Failure> {
        match tokio::time::timeout(wait, self.client.connect((host, port))).await {
            Ok(Ok(stream)) => Ok(TorStream { stream, _client: self.client.clone() }),
            Ok(Err(e)) => Err(arti_failure("the stream", &e)),
            Err(_) => Err(failure("the stream", format!("not open within {} s", wait.as_secs()))),
        }
    }
}

/// A stream through Tor, with the client that carries it.
pub struct TorStream {
    stream: DataStream,
    _client: Arc<TorClient<Runtime>>,
}

impl tokio::io::AsyncRead for TorStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TorStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ports_of_the_first_hop_are_patterns_of_any_address() {
        let patterns = reachable(&[443, 80]).unwrap();
        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0], "*:443".parse::<AddrPortPattern>().unwrap());
    }
}
