//! The Tor road's run, in a build with the feature `tor`: Arti's
//! directories in the cache, podssh-ws's rustls provider as the process's,
//! the bootstrap through the proxy, then a stream through an exit.

use std::path::PathBuf;
use std::time::Duration;

use podssh_tor::{Options, Tor, TorStream};
use podssh_ws::dial::ProxyChoice;

use super::{first_hop_ports, Failed, Target, DIR_NAME, PORTS_ENV};
use crate::exitmap::sysexits::{EX_CANTCREAT, EX_CONFIG, EX_UNAVAILABLE};

/// How long a bootstrap may take: a first run fetches the directory, a few
/// MiB through each first hop that the proxy allows.
pub const BOOTSTRAP_WAIT: Duration = Duration::from_secs(180);
/// How long a circuit and the exit's connection may take.
pub const STREAM_WAIT: Duration = Duration::from_secs(60);

/// Arti's state and cache under the first of the cache's directories that
/// can be made private (T-243).
fn directories() -> Result<(PathBuf, PathBuf), Failed> {
    use podssh_relay::cache::{candidate_dirs, chosen, private_dir, Chosen, DIR_ENV};
    if chosen() == Chosen::Nothing {
        let line = format!(
            "{}=none: the Tor road keeps Arti's guards and directory in the cache, as Tor asks; \
             name a directory, or leave it unset",
            DIR_ENV
        );
        return Err((line, EX_CONFIG));
    }
    let mut tried = Vec::new();
    for dir in candidate_dirs() {
        let base = dir.join(DIR_NAME);
        let (state, cache) = (base.join("state"), base.join("cache"));
        match private_dir(&base).and_then(|()| private_dir(&state)).and_then(|()| private_dir(&cache)) {
            Ok(()) => return Ok((state, cache)),
            Err(e) => tried.push(format!("{}: {e}", base.display())),
        }
    }
    Err((format!("no private directory for Arti's state: {}", tried.join("; ")), EX_CANTCREAT))
}

/// The stream to `target` through Tor.
pub async fn open(
    target: &Target,
    say: &(dyn Fn(&str) + Sync),
    verbose: &(dyn Fn(&str) + Sync),
) -> Result<TorStream, Failed> {
    let shown = target.shown();
    // Arti's rustls takes the process's provider; podssh's own, as each
    // other road's. A second call finds it there already, which is as good.
    let _ = rustls::crypto::CryptoProvider::install_default(podssh_ws::crypto::provider());
    let proxied = podssh_ws::dial::proxy_from_env("tor.invalid")
        .map_err(|why| (format!("{shown}: the proxy: {why}"), EX_CONFIG))?
        .is_some();
    let ports = first_hop_ports(std::env::var(PORTS_ENV).ok().as_deref(), proxied)
        .map_err(|why| (format!("{shown}: {why}"), EX_CONFIG))?;
    let (state_dir, cache_dir) = directories().map_err(|(line, code)| (format!("{shown}: {line}"), code))?;
    let mut options = Options {
        state_dir,
        cache_dir,
        proxy: ProxyChoice::FromEnvironment,
        first_hop_ports: ports.clone(),
        trust_directories: false,
    };
    let held = match &ports {
        Some(ports) => {
            let list: Vec<String> = ports.iter().map(u16::to_string).collect();
            format!("first hops on port {} alone", list.join(", "))
        }
        None => "first hops on any port".to_string(),
    };
    let via = if proxied { "through the proxy" } else { "directly" };
    say(&format!("bootstrapping Tor (Arti) {via}, {held}: a first run fetches the directory"));
    let tor = match Tor::bootstrap(&options, BOOTSTRAP_WAIT).await {
        Ok(tor) => tor,
        // podssh made the directories private itself; Arti's check of each
        // directory above them can fail on a sandbox's mounts.
        Err(failure) if failure.permissions => {
            verbose(&format!("{shown}: Arti refused the directories ({failure}); trying again without its check"));
            options.trust_directories = true;
            Tor::bootstrap(&options, BOOTSTRAP_WAIT)
                .await
                .map_err(|f| (format!("{shown}: Tor: {f}"), EX_UNAVAILABLE))?
        }
        Err(failure) => return Err((format!("{shown}: Tor: {failure}"), EX_UNAVAILABLE)),
    };
    verbose(&format!("{shown}: Tor bootstrapped; opening a stream to port {} through an exit", target.port));
    tor.connect(&target.host, target.port, STREAM_WAIT)
        .await
        .map_err(|f| (format!("{shown}: Tor: {f}"), EX_UNAVAILABLE))
}
