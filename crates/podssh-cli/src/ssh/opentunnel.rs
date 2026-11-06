//! The OpenTunnel road of `podssh ssh node://NAME` (T-531): the name that the
//! node prints, `ROUTE.ID.opentunnel.xyz`, given as `--opentunnel-name`, or
//! kept under NAME in the cache from a run that gave it, as a DERP ticket is
//! kept. A name given races 250 ms after the road before it; a kept one only
//! once each road before it failed, the fallback of a client that the
//! operator's ruling Q76 allows, which `PODSSH_OPENTUNNEL=no` turns off. Each
//! link is TLS by the name on port 443, through `HTTPS_PROXY`, with no
//! upgrade: a proxy that refuses the WebSocket upgrade passes it. TLS proves
//! the name; the end-to-end channel checks the node's key by the pins of
//! NAME, or `--node-key`, on whichever road wins.

use std::path::PathBuf;
use std::sync::Arc;

use podssh_relay::opentunnel::{self, dial, Dialer, Name};
use podssh_ssh::Log;
use podssh_ws::{ProxyChoice, Trust};

use super::args::SshArgs;
use crate::relay_settings::Refusal;

/// The domain of OpenTunnel's own tunnels, whose certificates are public:
/// `.` and the fact `tunnel-zone` of `opentunnel` (`pod-services`).
fn hosted() -> String {
    let service = pod_services::get("opentunnel").expect("pod-services holds the service opentunnel");
    format!(".{}", service.text("tunnel-zone").expect("opentunnel of pod-services holds the fact tunnel-zone"))
}

/// The OpenTunnel road of a `node://NAME` destination: the name of
/// `--opentunnel-name`, or none; and whether a name kept under NAME may be
/// dialled when none is given (Q76).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Race {
    pub name: Option<Name>,
    pub fallback: bool,
}

/// The OpenTunnel road of one run to a node: its name, and whether the user
/// gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Road {
    pub name: Name,
    pub asked: bool,
}

impl Race {
    /// The road of a run to the node of `label`: the name given, else the
    /// one kept under the label, when the road is on; else none.
    pub(crate) fn road(&self, label: &str) -> Option<Road> {
        match &self.name {
            Some(name) => Some(Road { name: name.clone(), asked: true }),
            None if self.fallback => kept(label).map(|name| Road { name, asked: false }),
            None => None,
        }
    }
}

/// `--opentunnel-name` and `PODSSH_OPENTUNNEL` of a `node://NAME`
/// destination, checked before anything connects: a bad name is a usage
/// error (64), a bad variable a configuration error (78).
pub(super) fn race(args: &SshArgs) -> Result<Race, Refusal> {
    let name = match &args.opentunnel_name {
        Some(text) => Some(Name::parse(text).map_err(|why| Refusal::usage(format!("--opentunnel-name: {why}")))?),
        None => None,
    };
    let on = crate::node_opentunnel::service()?.is_some();
    if name.is_some() && !on {
        let why = format!("--opentunnel-name: {}=no turns the OpenTunnel road off", opentunnel::ENV);
        return Err(Refusal::usage(why));
    }
    Ok(Race { name, fallback: on })
}

/// The file of the name kept under `label`, in the cache.
fn name_file(label: &str) -> String {
    format!("opentunnel-{}.name", podssh_relay::cache::safe_name(label))
}

/// Keep `name` under `label`, for the fallback of a later run. A name is an
/// address, not a credential; it goes in a private file as the pins do, as
/// its route keeps scanners of the logs of Certificate Transparency away.
pub(crate) fn keep(label: &str, name: &Name) -> Result<PathBuf, String> {
    podssh_relay::cache::store_file(&name_file(label), format!("{name}\n").as_bytes())
}

/// The name kept under `label`, when one is and it reads as one.
pub(crate) fn kept(label: &str) -> Option<Name> {
    let text = podssh_relay::cache::load_file(&name_file(label))?;
    Name::parse(text.trim()).ok()
}

/// The trust of a node's TLS: the host's for a tunnel of OpenTunnel's own,
/// whose certificate is public; `trust`, the relay's `--ca-file` when given,
/// for a tunnel of another service, which may be the user's own.
fn trust_for(name: &Name, trust: &Trust) -> Trust {
    if name.hostname.ends_with(&hosted()) {
        crate::pairs::trust(None)
    } else {
        trust.clone()
    }
}

/// A dialer of the node of `road`, through the proxy of the environment; its
/// lines go to `-v` under `shown`. A name that the user gave is kept under
/// `label` (Q76).
pub(crate) fn dialer(road: &Road, label: &str, trust: &Trust, log: &Arc<Log>, shown: &str) -> Dialer {
    if road.asked {
        match keep(label, &road.name) {
            Ok(path) => log.verbose(&format!("{shown}: the OpenTunnel name is kept in {}", path.display())),
            Err(why) => log.verbose(&format!("{shown}: the OpenTunnel name could not be kept: {why}")),
        }
    }
    let say: opentunnel::Say = {
        let (log, shown) = (log.clone(), shown.to_string());
        Arc::new(move |line: String| log.verbose(&format!("{shown}: {line}")))
    };
    let visit = dial::tcp(ProxyChoice::FromEnvironment);
    Dialer::new(road.name.clone(), visit, trust_for(&road.name, trust), say)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_given_races_and_a_kept_one_is_the_fallback() {
        let name = Name::parse("r7k2qmx4.abcdefghijkl.opentunnel.xyz").unwrap();
        let given = Race { name: Some(name.clone()), fallback: true };
        assert_eq!(given.road("lab"), Some(Road { name: name.clone(), asked: true }));
        let off = Race { name: None, fallback: false };
        assert_eq!(off.road("lab"), None, "no fallback, no road");
        let pair = Trust::File("/the/pair/relay/ca.pem".into());
        assert!(
            !matches!(trust_for(&name, &pair), Trust::File(ref f) if f == std::path::Path::new("/the/pair/relay/ca.pem"))
        );
        let own = Name::parse("r7k2qmx4.abcdefghijkl.tunnels.example.test").unwrap();
        assert!(
            matches!(trust_for(&own, &pair), Trust::File(ref f) if f == std::path::Path::new("/the/pair/relay/ca.pem"))
        );
    }
}
