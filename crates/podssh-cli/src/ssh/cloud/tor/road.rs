//! The Tor road's run, in a build with the feature `tor`: Arti's
//! directories in the cache, podssh-ws's rustls provider as the process's,
//! the bootstrap through the proxy, then a stream through an exit.

use std::path::PathBuf;
use std::time::Duration;

use podssh_tor::{Bridge, Options, Tor, TorStream};
use podssh_ws::dial::ProxyChoice;
use podssh_ws::Trust;

use super::{first_hop_ports, Failed, Target, BRIDGES_ENV, DIR_NAME, NETWORK_ENV, PORTS_ENV};
use crate::exitmap::sysexits::{EX_CANTCREAT, EX_CONFIG, EX_UNAVAILABLE};

/// How long a bootstrap may take: a first run fetches the directory, a few
/// MiB through each first hop that the proxy allows.
pub const BOOTSTRAP_WAIT: Duration = Duration::from_secs(180);
/// How long a circuit and the exit's connection may take.
pub const STREAM_WAIT: Duration = Duration::from_secs(60);

/// Arti's state and cache under the first of the cache's directories that
/// can be made private (T-243). Another network's go under `networks/`, by
/// a digest of its configuration: its guards and directory are not Tor's.
fn directories(network: Option<&str>) -> Result<(PathBuf, PathBuf), Failed> {
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
        let mut base = dir.join(DIR_NAME);
        let mut made = vec![base.clone()];
        if let Some(text) = network {
            use sha2::Digest as _;
            let digest = sha2::Sha256::digest(text.as_bytes());
            let name: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
            base = base.join("networks").join(name);
            made.extend([base.parent().map(PathBuf::from).unwrap_or_default(), base.clone()]);
        }
        let (state, cache) = (base.join("state"), base.join("cache"));
        made.extend([state.clone(), cache.clone()]);
        match made.iter().try_for_each(|d| private_dir(d)) {
            Ok(()) => return Ok((state, cache)),
            Err(e) => tried.push(format!("{}: {e}", base.display())),
        }
    }
    Err((format!("no private directory for Arti's state: {}", tried.join("; ")), EX_CANTCREAT))
}

/// The longest configuration of another network that is read: chutney's of
/// a few hundred relays fits many times.
const MOST_NETWORK_BYTES: u64 = 1 << 20;
/// The longest file of bridges that is read: a bridge line is a few hundred
/// bytes.
const MOST_BRIDGES_BYTES: u64 = 64 << 10;

/// The text of the file that `var` names, at most `most` bytes, and that
/// name; none when it is unset or empty.
fn file_of(var: &str, most: u64) -> Result<Option<(String, String)>, String> {
    use std::io::Read as _;
    let Some(path) = std::env::var_os(var).filter(|v| !v.is_empty()) else { return Ok(None) };
    let shown = PathBuf::from(&path).display().to_string();
    let file = std::fs::File::open(&path).map_err(|e| format!("{var}={shown}: {e}"))?;
    let mut text = String::new();
    file.take(most + 1).read_to_string(&mut text).map_err(|e| format!("{var}={shown}: {e}"))?;
    if text.len() as u64 > most {
        return Err(format!("{var}={shown}: longer than {most} bytes"));
    }
    Ok(Some((text, shown)))
}

/// The configuration of another Tor network, from the file that
/// [`NETWORK_ENV`] names, and that name; none when it is unset or empty.
fn network() -> Result<Option<(String, String)>, String> {
    file_of(NETWORK_ENV, MOST_NETWORK_BYTES)
}

/// The bridges of the file that [`BRIDGES_ENV`] names, a bridge line a
/// line (`#` begins a comment), and that name; none when it is unset or
/// empty. A line is named by its number alone: a bridge's line is not
/// shown.
fn bridges() -> Result<Option<(Vec<Bridge>, String)>, String> {
    let Some((text, shown)) = file_of(BRIDGES_ENV, MOST_BRIDGES_BYTES)? else { return Ok(None) };
    let mut list = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let bridge = Bridge::parse(line).map_err(|why| format!("{BRIDGES_ENV}={shown}, line {}: {why}", n + 1))?;
        list.push(bridge);
    }
    if list.is_empty() {
        return Err(format!("{BRIDGES_ENV}={shown}: no bridge line"));
    }
    Ok(Some((list, shown)))
}

/// The stream to `target` through Tor.
pub async fn open(
    target: &Target,
    trust: &Trust,
    say: &(dyn Fn(&str) + Sync),
    verbose: &(dyn Fn(&str) + Sync),
) -> Result<TorStream, Failed> {
    let shown = target.shown();
    let (tor, _) = bootstrap(&shown, trust, say, verbose).await?;
    verbose(&format!("{shown}: Tor bootstrapped; opening a stream to port {} through an exit", target.port));
    tor.connect(&target.host, target.port, STREAM_WAIT)
        .await
        .map_err(|f| (format!("{shown}: Tor: {f}"), EX_UNAVAILABLE))
}

/// A client of Tor, bootstrapped as the road makes it, for `shown`, which
/// each line names; and how it went: through the proxy or not, its first
/// hops or its bridges, and the network when it is not Tor's own. `podssh
/// doctor --full` takes it too.
pub async fn bootstrap(
    shown: &str,
    trust: &Trust,
    say: &(dyn Fn(&str) + Sync),
    verbose: &(dyn Fn(&str) + Sync),
) -> Result<(Tor, String), Failed> {
    // Arti's rustls takes the process's provider; podssh's own, as each
    // other road's. A second call finds it there already, which is as good.
    let _ = rustls::crypto::CryptoProvider::install_default(podssh_ws::crypto::provider());
    let proxied = podssh_ws::dial::proxy_from_env("tor.invalid")
        .map_err(|why| (format!("{shown}: the proxy: {why}"), EX_CONFIG))?
        .is_some();
    let ports = first_hop_ports(std::env::var(PORTS_ENV).ok().as_deref(), proxied)
        .map_err(|why| (format!("{shown}: {why}"), EX_CONFIG))?;
    let network = network().map_err(|why| (format!("{shown}: {why}"), EX_CONFIG))?;
    let bridges = bridges().map_err(|why| (format!("{shown}: {why}"), EX_CONFIG))?;
    let (state_dir, cache_dir) = directories(network.as_ref().map(|(text, _)| text.as_str()))
        .map_err(|(line, code)| (format!("{shown}: {line}"), code))?;
    let held = match (&bridges, &ports) {
        // A bridge is the first hop, through its transport: the ports of a
        // relay do not hold.
        (Some((list, file)), _) => format!("{}, named in {file}", podssh_tor::bridges::summary(list)),
        (None, Some(ports)) => {
            let list: Vec<String> = ports.iter().map(u16::to_string).collect();
            format!("first hops on port {} alone", list.join(", "))
        }
        (None, None) => "first hops on any port".to_string(),
    };
    let mut options = Options {
        state_dir,
        cache_dir,
        proxy: ProxyChoice::FromEnvironment,
        first_hop_ports: if bridges.is_some() { None } else { ports },
        trust_directories: false,
        network: network.as_ref().map(|(text, _)| text.clone()),
        bridges: bridges.as_ref().map(|(list, _)| list.clone()).unwrap_or_default(),
        trust: trust.clone(),
    };
    let via = if proxied { "through the proxy" } else { "directly" };
    let which = network.map_or_else(String::new, |(_, file)| format!(" in the network of {file}"));
    say(&format!("bootstrapping Tor (Arti){which} {via}, {held}: a first run fetches the directory"));
    let how = format!("{via}, {held}{which}");
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
    Ok((tor, how))
}
