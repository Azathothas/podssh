//! A node's record of pkarr with each of its roads (T-445). The iroh road's
//! node keeps its home relay there (T-350), and its DERP home once its DERP
//! road is online, again each time that home moves ([`keep`]). A node with
//! no iroh endpoint, the quick tunnel's or the DERP road's alone, keeps its
//! roads there too ([`alone`]): at n0's server unless PODSSH_IROH_PKARR names
//! another or `off`, as the operator's ruling Q81 widens Q57 to such a node,
//! whose record names only public names. A build with no iroh road keeps no
//! record, and reads no variable of it.

use std::sync::Arc;

use podssh_relay::derp::Ticket;
use podssh_relay::identity::Identity;
use podssh_ws::Trust;

use crate::relay_settings::Refusal;

#[cfg(feature = "iroh")]
use podssh_iroh::pkarr::{self, Roads};
#[cfg(feature = "iroh")]
use tokio::sync::watch;

/// Where a node's lines go.
pub(crate) type Say = Arc<dyn Fn(String) + Send + Sync>;

/// Tells the keeper of the record of a road that came online or moved;
/// where no record is kept, it tells nothing.
#[derive(Clone, Default)]
pub(crate) struct Tell {
    #[cfg(feature = "iroh")]
    told: Option<watch::Sender<Roads>>,
}

#[cfg(feature = "iroh")]
impl Tell {
    /// The node's DERP home is now the one of `ticket`.
    pub(crate) fn derp(&self, ticket: &Ticket) {
        if let Some(told) = &self.told {
            told.send_modify(|roads| roads.derp = Some(ticket.clone()));
        }
    }

    /// The node's quick tunnel is `name`.
    pub(crate) fn quick(&self, name: &str) {
        if let Some(told) = &self.told {
            told.send_modify(|roads| roads.quick = Some(name.to_string()));
        }
    }
}

#[cfg(not(feature = "iroh"))]
impl Tell {
    pub(crate) fn derp(&self, _: &Ticket) {}

    pub(crate) fn quick(&self, _: &str) {}
}

/// The keeper's task, stopped when this is dropped, as the node ends.
#[derive(Default)]
pub(crate) struct Kept(Option<tokio::task::JoinHandle<()>>);

impl Drop for Kept {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

/// The server of a record of a node with no iroh endpoint.
#[cfg(feature = "iroh")]
pub(crate) type Named = pkarr::Server;

/// A build with no iroh road names none.
#[cfg(not(feature = "iroh"))]
pub(crate) enum Named {}

/// The server of the record of a node with no iroh endpoint, read before
/// anything connects: the one that PODSSH_IROH_PKARR names, n0's when it is
/// unset or empty (Q81), none when it is `off`; a bad value is a
/// configuration error (78).
#[cfg(feature = "iroh")]
pub(crate) fn named() -> Result<Option<Named>, Refusal> {
    Ok(of_choice(pkarr::choice_from_environment().map_err(Refusal::config)?))
}

/// The server of a node with no iroh endpoint for `choice`.
#[cfg(feature = "iroh")]
fn of_choice(choice: pkarr::Choice) -> Option<Named> {
    match choice {
        pkarr::Choice::At(server) => Some(server),
        pkarr::Choice::Default => Some(pkarr::Server::n0()),
        pkarr::Choice::Off => None,
    }
}

#[cfg(not(feature = "iroh"))]
pub(crate) fn named() -> Result<Option<Named>, Refusal> {
    Ok(None)
}

/// Keep the record of a node with no iroh endpoint at `server`, signed with
/// the key of `identity` (one key for each road, T-087), naming what its
/// [`Tell`] gives; `line` hears where it goes. With no server, nothing.
#[cfg(feature = "iroh")]
pub(crate) fn alone(
    server: Option<Named>,
    identity: &Identity,
    trust: &Trust,
    say: Say,
    line: impl FnOnce(String),
) -> (Kept, Tell) {
    let Some(server) = server else { return (Kept::default(), Tell::default()) };
    line(format!("the record of its roads goes to {server} ({}=off sends none)", pkarr::ENV));
    let secret = iroh::SecretKey::from_bytes(&identity.seed());
    let (told, roads) = watch::channel(Roads::default());
    let proxy = podssh_ws::ProxyChoice::FromEnvironment;
    let said = move |words: String| say(words);
    let task = tokio::spawn(pkarr::keep_roads(secret, server, trust.clone(), proxy, roads, said));
    (Kept(Some(task)), Tell { told: Some(told) })
}

#[cfg(not(feature = "iroh"))]
pub(crate) fn alone(server: Option<Named>, _: &Identity, _: &Trust, _: Say, _: impl FnOnce(String)) -> (Kept, Tell) {
    match server {
        Some(never) => match never {},
        None => (Kept::default(), Tell::default()),
    }
}

/// Keep the record of the roads of `endpoint`'s node at `server` (T-350):
/// its home relay as the endpoint has it, and what its [`Tell`] gives;
/// `line` hears where it goes. With no server, nothing.
#[cfg(feature = "iroh")]
pub(crate) fn keep(
    endpoint: &iroh::Endpoint,
    server: Option<pkarr::Server>,
    trust: &Trust,
    proxy: &podssh_ws::ProxyChoice,
    say: impl Fn(String) + Send + 'static,
    line: impl FnOnce(String),
) -> (Kept, Tell) {
    let Some(server) = server else { return (Kept::default(), Tell::default()) };
    line(format!("the record of its roads goes to {server} ({}=off sends none)", pkarr::ENV));
    let (told, others) = watch::channel(Roads::default());
    let kept = pkarr::keep(endpoint.clone(), server, trust.clone(), proxy.clone(), Some(others), say);
    (Kept(Some(tokio::spawn(kept))), Tell { told: Some(told) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_no_server_no_record_is_kept_and_a_tell_tells_nothing() {
        let identity = Identity::from_seed(&[3; 32]);
        let say: Say = Arc::new(|_: String| {});
        let mut said = Vec::new();
        let (kept, tell) = alone(None, &identity, &Trust::Default, say, |line| said.push(line));
        assert!(kept.0.is_none() && said.is_empty());
        let ticket = Ticket {
            node: identity.public(),
            derp: podssh_relay::derp::Key([1; 32]),
            server: podssh_relay::derp::Server::new("tc301a.ipn.dev", 443).unwrap(),
        };
        // Nothing listens, and nothing fails.
        tell.derp(&ticket);
        tell.quick("four-words-of-a.trycloudflare.com");
    }

    /// Q81: n0's server when nothing names another, none when off.
    #[cfg(feature = "iroh")]
    #[test]
    fn a_node_with_no_iroh_road_keeps_its_record_at_n0_s_server_unless_told_otherwise() {
        let n0 = of_choice(pkarr::Choice::Default).map(|s| s.to_string());
        assert_eq!(n0, Some(pkarr::Server::n0().to_string()));
        assert!(of_choice(pkarr::Choice::Off).is_none());
        let other = pkarr::Server::parse("https://pkarr.example/").unwrap();
        assert_eq!(of_choice(pkarr::Choice::At(other.clone())).map(|s| s.to_string()), Some(other.to_string()));
    }
}
