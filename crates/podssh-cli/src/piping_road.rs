//! `PODSSH_PIPING` (T-437): the Piping Server road of a pair, for a proxy
//! that refuses the WebSocket upgrade. Unset or empty, the road is the
//! fallback that the operator's ruling Q65 allows, through `https://ppng.io`:
//! a node serves it once its probe finds the upgrade refused on the way, and
//! `podssh ssh node://NAME` tries it once the pair's road found the same.
//! `no` turns it off; `yes`, or a server's `https://` URL, asks for it, and
//! then a node serves it beside the pair's road and a client races it.

use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::piping::{dial, Dialer, Http, Secret, Server};
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
    /// The fallback of Q65, through this server.
    Unasked(Server),
    /// The road, through this server, as the user asked.
    Asked(Server),
}

/// [`Want`], by [`ENV`].
pub fn want() -> Result<Want, Refusal> {
    want_from(std::env::var(ENV).ok().as_deref())
}

/// Unset or empty: the fallback; no: off; yes: asked, through `ppng.io`; a
/// server's URL: asked, through it. Another word is a setting that cannot be
/// used (78).
pub fn want_from(value: Option<&str>) -> Result<Want, Refusal> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Want::Unasked(Server::default()));
    };
    match value.to_ascii_lowercase().as_str() {
        "no" | "off" | "false" | "0" => Ok(Want::Off),
        "yes" | "on" | "true" | "1" => Ok(Want::Asked(Server::default())),
        _ => Server::parse(value)
            .map(Want::Asked)
            .map_err(|why| Refusal::config(format!("{ENV}: {why}; it takes no, yes or https://HOST[:PORT][/PREFIX]"))),
    }
}

/// The road of one run of `podssh ssh node://NAME`: its server, whether the
/// user asked for it, and whether a road found the upgrade refused already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Race {
    pub server: Server,
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
        Want::Unasked(server) => Some(Race { server, asked: false, refused: false }),
        Want::Asked(server) => Some(Race { server, asked: true, refused: false }),
    })
}

/// The HTTP client of `server`, through the proxy of the environment.
pub fn http(server: &Server, trust: &Trust) -> Http {
    Http::new(server.clone(), dial::tls(trust.clone(), ProxyChoice::FromEnvironment))
}

/// A dialer of the node of the pair of `part`, through `race`'s server; its
/// lines go to `-v` under `shown`.
pub fn dialer(part: &OperatorPart, race: &Race, trust: &Trust, log: &Arc<Log>, shown: &str) -> Dialer {
    let say: podssh_relay::piping::Say = {
        let (log, shown) = (log.clone(), shown.to_string());
        Arc::new(move |line: String| log.verbose(&format!("{shown}: {line}")))
    };
    Dialer::new(Secret::of_pair(&part.name, part.connect_token()), http(&race.server, trust), say)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn podssh_piping_is_the_fallback_unset_off_with_no_and_asked_with_yes_or_a_url() {
        for unset in [None, Some(""), Some("  ")] {
            assert_eq!(want_from(unset).unwrap(), Want::Unasked(Server::default()), "{unset:?}");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(want_from(Some(off)).unwrap(), Want::Off, "{off}");
        }
        assert_eq!(want_from(Some("Yes")).unwrap(), Want::Asked(Server::default()));
        let own = want_from(Some("https://pipe.example:8443/p")).unwrap();
        assert_eq!(own, Want::Asked(Server::parse("https://pipe.example:8443/p").unwrap()));
        for bad in ["maybe", "http://ppng.io", "https://ppng.io/?n=2"] {
            let refused = want_from(Some(bad)).unwrap_err();
            assert_eq!(refused.code, 78, "{bad}");
            assert!(refused.message.starts_with("PODSSH_PIPING: "), "{}", refused.message);
        }
    }

    #[test]
    fn a_race_keeps_its_server_once_a_road_found_the_upgrade_refused() {
        let race = Race { server: Server::default(), asked: false, refused: false };
        let refused = race.refused();
        assert!(refused.refused && !refused.asked);
        assert_eq!(refused.server, race.server);
    }
}
