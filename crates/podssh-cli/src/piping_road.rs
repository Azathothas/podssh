//! `PODSSH_PIPING` (T-437): the Piping Server road of a pair, for a proxy
//! that refuses the WebSocket upgrade. Unset or empty, the road is the
//! fallback that the operator's ruling Q65 allows, through `https://ppng.io`
//! and then each other public server of pod-services (T-497):
//! a node serves it once its probe finds the upgrade refused on the way, and
//! `podssh ssh node://NAME` tries it once the pair's road found the same.
//! `no` turns it off; `yes` (the public servers), or a server's `https://`
//! URL (that server alone), asks for it, and then a node serves it beside
//! the pair's road and a client races it.

use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::piping::{dial, server, Dialer, Http, Node, Say, Secret, Server};
use podssh_ssh::Log;
use podssh_ws::{ProxyChoice, Trust};

use crate::relay_settings::Refusal;

/// The variable of the road.
pub const ENV: &str = "PODSSH_PIPING";

/// What the user asked of the road.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Want {
    /// No road through a Piping Server.
    Off,
    /// The fallback of Q65, through these servers, in order.
    Unasked(Vec<Server>),
    /// The road, through these servers, as the user asked.
    Asked(Vec<Server>),
}

/// [`Want`], by [`ENV`].
pub fn want() -> Result<Want, Refusal> {
    want_from(std::env::var(ENV).ok().as_deref())
}

/// Unset or empty: the fallback; no: off; yes: asked, through the public
/// servers; a server's URL: asked, through it alone. Another word is a setting that cannot be
/// used (78).
pub fn want_from(value: Option<&str>) -> Result<Want, Refusal> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Want::Unasked(server::public()));
    };
    match value.to_ascii_lowercase().as_str() {
        "no" | "off" | "false" | "0" => Ok(Want::Off),
        "yes" | "on" | "true" | "1" => Ok(Want::Asked(server::public())),
        _ => Server::parse(value)
            .map(|server| Want::Asked(vec![server]))
            .map_err(|why| Refusal::config(format!("{ENV}: {why}; it takes no, yes or https://HOST[:PORT][/PREFIX]"))),
    }
}

/// The road of one run of `podssh ssh node://NAME`: its servers, whether the
/// user asked for it, and whether a road found the upgrade refused already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Race {
    pub servers: Vec<Server>,
    pub asked: bool,
    pub refused: bool,
}

impl Race {
    /// This road, once a road found the upgrade refused.
    pub fn refused(&self) -> Race {
        Race { refused: true, ..self.clone() }
    }
}

/// The road of a run, by [`ENV`], checked before anything connects.
pub fn race() -> Result<Option<Race>, Refusal> {
    Ok(match want()? {
        Want::Off => None,
        Want::Unasked(servers) => Some(Race { servers, asked: false, refused: false }),
        Want::Asked(servers) => Some(Race { servers, asked: true, refused: false }),
    })
}

/// The HTTP client of `server`, through the proxy of the environment.
pub fn http(server: &Server, trust: &Trust) -> Http {
    Http::new(server.clone(), dial::tls(trust.clone(), ProxyChoice::FromEnvironment))
}

/// A dialer of the node of the pair of `part`, through `race`'s servers; its
/// lines go to `-v` under `shown`.
pub fn dialer(part: &OperatorPart, race: &Race, trust: &Trust, log: &Arc<Log>, shown: &str) -> Dialer {
    let say: podssh_relay::piping::Say = {
        let (log, shown) = (log.clone(), shown.to_string());
        Arc::new(move |line: String| log.verbose(&format!("{shown}: {line}")))
    };
    let https = race.servers.iter().map(|server| http(server, trust)).collect();
    Dialer::with_servers(Secret::of_pair(&part.name, part.connect_token()), https, say)
}

/// The node of the road at `servers`, in order: the first that answers
/// holds its door.
pub fn node(secret: Arc<Secret>, servers: &[Server], trust: &Trust, say: Say) -> Node {
    let mut https = servers.iter().map(|server| Arc::new(http(server, trust)));
    let first = https.next().unwrap_or_else(|| Arc::new(http(&Server::default(), trust)));
    Node { secret, http: first, fallbacks: https.collect(), say }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn podssh_piping_is_the_fallback_unset_off_with_no_and_asked_with_yes_or_a_url() {
        for unset in [None, Some(""), Some("  ")] {
            assert_eq!(want_from(unset).unwrap(), Want::Unasked(server::public()), "{unset:?}");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(want_from(Some(off)).unwrap(), Want::Off, "{off}");
        }
        assert_eq!(want_from(Some("Yes")).unwrap(), Want::Asked(server::public()));
        assert_eq!(server::public()[0], Server::default(), "ppng.io first");
        assert!(server::public().len() >= 2, "a second public server after it (T-497)");
        // A server that the user names is kept alone, a public one too.
        let own = want_from(Some("https://pipe.example:8443/p")).unwrap();
        assert_eq!(own, Want::Asked(vec![Server::parse("https://pipe.example:8443/p").unwrap()]));
        assert_eq!(want_from(Some("https://ppng.io")).unwrap(), Want::Asked(vec![Server::default()]));
        for bad in ["maybe", "http://ppng.io", "https://ppng.io/?n=2"] {
            let refused = want_from(Some(bad)).unwrap_err();
            assert_eq!(refused.code, 78, "{bad}");
            assert!(refused.message.starts_with("PODSSH_PIPING: "), "{}", refused.message);
        }
    }

    #[test]
    fn a_race_keeps_its_server_once_a_road_found_the_upgrade_refused() {
        let race = Race { servers: server::public(), asked: false, refused: false };
        let refused = race.refused();
        assert!(refused.refused && !refused.asked);
        assert_eq!(refused.servers, race.servers);
    }
}
