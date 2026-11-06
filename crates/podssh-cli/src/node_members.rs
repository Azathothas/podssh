//! A node's pairs at the net's relay members (T-434): beside its own pair,
//! the node makes a pair at each member of its net with the role `relay` and
//! a host (at most three, its own pair's relay aside), by its own key, the
//! one that the net's document names for it; and keeps a node socket on each,
//! with the one keeper of its sessions, so that a session made on one road
//! resumes on another. A member of the net that reaches the node by no other
//! road asks such a member for a leg to the pair that the node's key made
//! (`crate::ssh::roads::member`). A member that refuses the pair, or that is
//! not reached, is said once and left out: the node's own road goes on.

use std::future::Future;
use std::sync::Arc;

use podssh_relay::identity::Identity;
use podssh_relay::pair::{once, Pair, PairContext};
use podssh_relay::relay::Relay;
use podssh_relay::reverse::{self, Handler, NodeConfig, Wire};
use podssh_relay::token::relay_name;
use podssh_ws::{ProxyChoice, Trust};

use crate::node_expiry::Say;

/// Whether the net names a relay member with a host: the node's cue to make
/// its pairs there.
pub(crate) fn wanted() -> bool {
    !crate::ssh::roads::member::relays().is_empty()
}

/// A pair at each relay member of the net, made by `identity`, but at `own`,
/// the relay of the node's pair; each one made or refused is said.
pub(crate) async fn pairs(identity: &Identity, own: &Relay, trust: &Trust, say: &Say) -> Vec<Pair> {
    let proxy = ProxyChoice::FromEnvironment;
    let mut made = Vec::new();
    for relay in crate::ssh::roads::member::relays().into_iter().filter(|relay| relay != own) {
        let ctx = PairContext { relay: &relay, trust, proxy: &proxy, timeout: crate::pairs::REQUEST_LIMIT };
        let at = relay_name(&relay);
        match once::create_by(&ctx, false, Some(identity)).await {
            Ok((pair, _)) => {
                say(format!("and at the net's relay member {at}, by this node's key (T-434)"));
                made.push(pair);
            }
            Err(e) => say(format!("no pair at the net's relay member {at}: {e}")),
        }
    }
    made
}

/// `main`, the node's own road, with a node socket on each pair of `pairs`
/// beside it, each with a handler of `handler` (one keeper for all), until
/// `main` ends: its end is the node's. A member's road that ends is said,
/// and the others go on.
pub(crate) async fn alongside<P, H, M, S, F>(
    mut main: P,
    pairs: Vec<Pair>,
    handler: M,
    trust: &Trust,
    say: &Say,
    stop: S,
) -> P::Output
where
    P: Future + Unpin,
    H: Handler,
    M: Fn() -> Arc<H>,
    S: Fn() -> F,
    F: Future<Output = ()>,
{
    if pairs.is_empty() {
        return main.await;
    }
    let proxy = ProxyChoice::FromEnvironment;
    let roads = pairs.into_iter().map(|pair| {
        let (handler, stopped, proxy) = (handler(), stop(), &proxy);
        async move {
            let at = relay_name(&pair.relay);
            let line = |line: String| say(line);
            let mut config = NodeConfig {
                pair,
                // Not stored: a member's pair lives with this run.
                label: None,
                trust,
                proxy,
                timeout: crate::pairs::REQUEST_LIMIT,
                settings: reverse::Settings {
                    rejoin: crate::layered::settings().resume_deadline,
                    ..reverse::Settings::default()
                },
                // A member's pair is not taken again at its expiry: the node
                // makes new ones at its next start.
                repair: None,
                wire: Wire::Tls,
                say: Some(&line),
            };
            let exit = Box::pin(reverse::run(&mut config, handler, stopped)).await;
            say(format!("the road at the net's relay member {at} ended: {exit:?}"));
        }
    });
    let members = futures_util::future::join_all(roads);
    tokio::select! {
        out = &mut main => out,
        // Each member's road ended; the node's own goes on.
        _ = members => main.await,
    }
}
