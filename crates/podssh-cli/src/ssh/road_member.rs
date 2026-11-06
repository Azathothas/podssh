//! The road through a member of the net with the relay role (T-434): two
//! members that reach no common road meet at a third that both reach. The
//! node keeps a pair at each such member, made by its own key
//! (`crate::node_members`); this client asks each for a leg to the node by the
//! key that the net's document names (`podssh_relay::pair::leg`), proving
//! its own key, and upgrades as an operator with the token of one leg that
//! the role drew. The end-to-end channel and the resumable layer run above,
//! as on the pair's road, so that the member sees bytes it cannot read.
//! Each member's leg races only when each road before it failed: a member
//! lends its sockets, and the roads of the two ends come first.

use std::sync::{Arc, Mutex};

use podssh_relay::identity::{Identity, KeyName, PublicKey};
use podssh_relay::pair::{leg, PairContext};
use podssh_relay::relay::{parse_relay, Relay};
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome as LegOutcome, Wire};
use podssh_relay::session::race::Start;
use podssh_ws::{ProxyChoice, Trust};
use tokio::task::JoinHandle;

use super::{Going, Kind, Road, PIPE};
use crate::layered;

/// The members whose roles a node and a client ask, at most: each is a pair
/// at the node and a race's place at the client.
pub(crate) const MOST: usize = 3;

/// The relay hosts of the net's members with the role `relay` whose host the
/// document names, at most [`MOST`], in the document's order; none with no
/// net held, or one that ended.
pub(crate) fn relays() -> Vec<Relay> {
    let Some(held) = crate::net::store::held_or_none() else { return Vec::new() };
    if held.signed.doc.expires <= crate::net::now() {
        return Vec::new();
    }
    let members = held.signed.doc.members.iter().filter(|m| m.has_role("relay"));
    let hosts = members.filter_map(|m| parse_relay(m.relay.as_deref()?).ok());
    let mut each: Vec<Relay> = Vec::new();
    for relay in hosts {
        if !each.contains(&relay) && each.len() < MOST {
            each.push(relay);
        }
    }
    each
}

/// The roads of a run through the net's relay members to the node `label`.
pub(crate) struct MemberRoads {
    node: PublicKey,
    relays: Vec<Relay>,
    /// The key of the client's end-to-end channel, which the role's mint
    /// admits as the net's member; this host's client key with none.
    identity: Option<Arc<Identity>>,
    trust: Trust,
    proxy: ProxyChoice,
    /// The last leg, kept as the pair's road keeps its own.
    legs: Mutex<Option<JoinHandle<LegOutcome>>>,
}

impl MemberRoads {
    /// The roads to `label`, a member of the net whose document names its
    /// key in full (a fingerprint alone names no pair), when the net has a
    /// relay member with a host; else none.
    pub(crate) fn new(label: &str, trust: &Trust) -> Option<MemberRoads> {
        let member = crate::net::lookup::member(label)?;
        let KeyName::Key(node) = member.key else { return None };
        let relays = relays();
        if relays.is_empty() {
            return None;
        }
        let (trust, proxy, legs) = (trust.clone(), ProxyChoice::FromEnvironment, Mutex::new(None));
        Some(MemberRoads { node, relays, identity: None, trust, proxy, legs })
    }

    /// The same roads, proving `identity`, the key of the client's channel.
    pub(crate) fn proving(self, identity: Option<Arc<Identity>>) -> MemberRoads {
        MemberRoads { identity, ..self }
    }

    /// Each member's place in the race, after each road before it failed.
    pub(super) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        for relay in &self.relays {
            list.push((Start::WhenAllFailed, Box::pin(self.link(relay))));
            kinds.push(Kind::Member);
        }
    }

    /// A leg at `relay`: a token of one leg from its role, then the upgrade.
    async fn link(&self, relay: &Relay) -> Result<Road, String> {
        let timeout = podssh_relay::open::CONNECT_TIMEOUT;
        let ctx = PairContext { relay, trust: &self.trust, proxy: &self.proxy, timeout };
        let at = podssh_relay::token::relay_name(relay);
        let drawn = leg::ask(&ctx, &self.node, self.identity.as_deref()).await.map_err(|e| format!("{at}: {e}"))?;
        let config = OperatorConfig {
            relay,
            name: &drawn.name,
            connect_token: drawn.token(),
            trust: &self.trust,
            proxy: &self.proxy,
            timeout,
            limits: OperatorLimits::default(),
            wire: Wire::Tls,
        };
        let (link, leg_end) = tokio::io::duplex(PIPE);
        // The drawn token is of one leg already, and of this member's pair:
        // the session's next token, which the node gave for another pair's
        // role, is no token here.
        let handle = operator::start(&config, leg_end).await.map_err(|e| format!("{at}: {e}"))?;
        *layered::lock(&self.legs) = Some(handle);
        Ok(Road::Pair(link))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_net_held_gives_no_member_road() {
        // A process with no net: no relay member, and no road.
        if crate::net::store::held_or_none().is_none() {
            assert!(relays().is_empty());
            assert!(MemberRoads::new("node-a", &Trust::Default).is_none());
        }
    }
}
