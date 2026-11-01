//! `tor://[user@]HOST[:PORT]` (T-353, the operator's ruling Q52): a port of
//! any host, 22 by default, through the Tor network, by Arti in podssh's
//! process (`podssh_tor`), with no relay of podssh's. Each connection to a
//! Tor relay goes through `HTTPS_PROXY` when one is set, and then only to
//! the ports of [`PORTS_ENV`], 443 by default; the exit resolves the host's
//! name. The road is in a build with the feature `tor` only; without it, a
//! `tor://` destination is refused before anything connects, with exit 70.
//!
//! Arti keeps its guards and its copy of the directory in [`DIR_NAME`] of the
//! cache (T-243), as Tor asks a client to keep its guards, and so that a
//! later run starts sooner.

use std::sync::Arc;

use podssh_ssh::Log;

use crate::ssh::transport::{Duplex, NotReached, Reached};

/// The form of a destination on this road.
pub const SCHEME: &str = "tor://";
/// The ports that a first hop may have: a list such as `443,80`, or `any`.
pub const PORTS_ENV: &str = "PODSSH_TOR_PORTS";
/// Arti's directory in the cache: `state` and `cache` under it.
pub const DIR_NAME: &str = "tor";
/// The file of arti-client's configuration of another Tor network, as
/// chutney writes it: a private network of the user's, or of a test.
pub const NETWORK_ENV: &str = "PODSSH_TOR_NETWORK";

/// A host and a port beyond an exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    /// The host as a destination shows it: an IPv6 address in brackets.
    pub fn shown(&self) -> String {
        if self.host.contains(':') {
            format!("{SCHEME}[{}]", self.host)
        } else {
            format!("{SCHEME}{}", self.host)
        }
    }
}

/// `tor://[user@]HOST[:PORT]` as its user and target; `None` for another
/// destination. An IPv6 address goes in brackets.
pub fn destination(text: &str) -> Result<Option<(Option<String>, Target)>, String> {
    let found = super::host_destination(text, SCHEME)?;
    Ok(found.map(|(user, host, port)| (user, Target { host, port })))
}

/// Why this build has no Tor road, for `what` that needs it.
pub fn not_built(what: &str) -> String {
    format!(
        "{what}: the Tor road is not in this build; build podssh with --features tor \
         (cargo build -p podssh-cli --features tor)"
    )
}

/// Whether `destination` names a host on this road.
pub fn is_tor(destination: &str) -> bool {
    destination.starts_with(SCHEME)
}

/// The ports that a first hop may have, from [`PORTS_ENV`]'s `value`: a
/// list, or `any` for each port (`None`). Unset or empty: 443 alone where
/// a proxy carries the first hop, as a cage's proxy allows little more,
/// and any port where none does.
pub fn first_hop_ports(value: Option<&str>, proxied: bool) -> Result<Option<Vec<u16>>, String> {
    let value = value.map(str::trim).unwrap_or("");
    if value.is_empty() {
        return Ok(proxied.then(|| vec![443]));
    }
    if value.eq_ignore_ascii_case("any") {
        return Ok(None);
    }
    let mut ports = Vec::new();
    for word in value.split(',').map(str::trim) {
        match word.parse::<u16>() {
            Ok(port) if port != 0 => ports.push(port),
            _ => {
                return Err(format!("{PORTS_ENV}={value}: {word:?} is not a port; give a list such as 443,80, or any"))
            }
        }
    }
    Ok(Some(ports))
}

/// A line of the road, and the code of a run that it ends.
pub type Failed = (String, i32);

/// The stream to `target` through Tor. `say` tells the user of the
/// bootstrap, which can take a minute on a first run, and `verbose` the rest.
#[cfg(feature = "tor")]
pub async fn open(
    target: &Target,
    say: &(dyn Fn(&str) + Sync),
    verbose: &(dyn Fn(&str) + Sync),
) -> Result<Box<dyn Duplex>, Failed> {
    let stream = road::open(target, say, verbose).await?;
    Ok(Box::new(stream))
}

/// In a build without the feature: the refusal, which `podssh ssh` says
/// before anything is resolved; a road that reaches here says it again.
#[cfg(not(feature = "tor"))]
pub async fn open(
    target: &Target,
    _say: &(dyn Fn(&str) + Sync),
    _verbose: &(dyn Fn(&str) + Sync),
) -> Result<Box<dyn Duplex>, Failed> {
    Err((not_built(&target.shown()), crate::exit_codes::EXIT_NOT_IMPLEMENTED))
}

/// The stream to `target`, as `podssh ssh` reaches a first hop.
pub(super) async fn reach(target: &Target, log: &Arc<Log>) -> Result<Reached, NotReached> {
    let (info, more) = (log.clone(), log.clone());
    let say = move |line: &str| info.info(line);
    let verbose = move |line: &str| more.verbose(line);
    match open(target, &say, &verbose).await {
        Ok(stream) => Ok(Reached { stream, relay: None, direct_proxy: None, layer: None }),
        Err((line, code)) => Err(NotReached { lines: vec![line], code }),
    }
}

#[cfg(feature = "tor")]
pub(crate) mod road;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_a_destination_is_read() {
        let (user, target) = destination("tor://me@github.com").unwrap().unwrap();
        assert_eq!((user.as_deref(), target.host.as_str(), target.port), (Some("me"), "github.com", 22));
        assert_eq!(target.shown(), "tor://github.com");
        let (_, target) = destination("tor://[2001:db8::1]:2222").unwrap().unwrap();
        assert_eq!((target.host.as_str(), target.port), ("2001:db8::1", 2222));
        assert_eq!(destination("warp://github.com").unwrap(), None);
        for bad in ["tor://", "tor://@host", "tor://2001:db8::1", "tor://host:0", "tor://host/path", "tor://ho st"] {
            assert!(destination(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tor_the_first_hop_s_ports_follow_the_proxy_and_the_variable() {
        assert_eq!(first_hop_ports(None, true), Ok(Some(vec![443])));
        assert_eq!(first_hop_ports(None, false), Ok(None));
        assert_eq!(first_hop_ports(Some(" "), true), Ok(Some(vec![443])));
        assert_eq!(first_hop_ports(Some("443, 80"), false), Ok(Some(vec![443, 80])));
        assert_eq!(first_hop_ports(Some("ANY"), true), Ok(None));
        for bad in ["443,", "0", "443;80", "http"] {
            assert!(first_hop_ports(Some(bad), true).unwrap_err().starts_with("PODSSH_TOR_PORTS="), "{bad}");
        }
    }
}
