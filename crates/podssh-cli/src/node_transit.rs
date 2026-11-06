//! The transit road of a pair (T-436): a magic-wormhole transit relay as a
//! carrier between a node and its operators that needs no relay of the
//! operator's, Least Authority's `wss://relay.mw.leastauthority.com` by
//! default, which the operator's ruling Q65 lets podssh try unasked;
//! `PODSSH_TRANSIT=no` turns it off, and a URL names another relay. The
//! meeting's token and the proof of the pair come from the pair's connect
//! token, which both ends hold, so a node that has a pair waits there too,
//! with one keeper for both roads, so that a session resumes on either; and
//! `podssh ssh node://` races it after the others, only when each one
//! before it failed. Never with `--plain` or `--no-e2e`: the relay is a
//! stranger's, so the layer and the end-to-end channel run above it.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends;
use podssh_relay::pair::{self, OperatorPart, Pair};
use podssh_relay::reverse::routes::Routes;
use podssh_relay::reverse::{self, Exit, Layered, NodeConfig, TcpHandler};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::OsEntropy;
use podssh_relay::transit::{self, far, Dialer, Keys, Setting, Side};
use podssh_ssh::Log;
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::DuplexStream;

use crate::node_expiry::Say;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// `PODSSH_TRANSIT`, read: a value that is none of its forms is a setting
/// that cannot be used (78).
pub(crate) fn setting() -> Result<Setting, Refusal> {
    transit::setting(std::env::var(transit::ENV).ok().as_deref()).map_err(Refusal::config)
}

/// The variable, checked before anything connects.
pub(crate) fn check() -> Result<(), Refusal> {
    setting().map(|_| ())
}

/// The relay of the road, when the road is on.
pub(crate) fn url() -> Option<WsUrl> {
    match setting() {
        Ok(Setting::On(url)) => Some(url),
        Ok(Setting::Off) | Err(_) => None,
    }
}

/// The pair's words now: those of `pair` until it expires, then those of a
/// later pair stored under `label` since, which the node goes on with at
/// the expiry (T-395), as its operators do.
fn keys_now(label: &str, pair: &Pair, stored: bool) -> far::KeysNow {
    let (label, first, ends_ms) = (label.to_string(), Keys::of_pair(&pair.name, pair.connect_token()), pair.expires_ms);
    Arc::new(move || {
        let now = crate::pairs::now_ms();
        if !stored || now < ends_ms {
            return first.clone();
        }
        let later = pair::load(&label).ok().flatten();
        match crate::node_expiry::next_pair(later, ends_ms, now) {
            Some(next) => Keys::of_pair(&next.name, next.connect_token()),
            None => first.clone(),
        }
    })
}

/// The trust of the transit relay at `url`: Least Authority's, a public
/// server, takes the host's trust (`SSL_CERT_FILE`, `CaFile`, else the
/// default stores), never the pair relay's `--ca-file`, which names that
/// relay's own CA; a relay that `PODSSH_TRANSIT` names takes the pair's, as
/// it may be the user's own, under the same CA.
fn trust_for(url: &WsUrl, pair: &Trust, host: Trust) -> Trust {
    match WsUrl::parse(transit::DEFAULT_URL) {
        Ok(least) if least == *url => host,
        _ => pair.clone(),
    }
}

/// The node of the transit road for the pair `pair`, at `url`, with a side
/// of this run's, and the line that says so; none when this host gives no
/// random side, which the line says.
pub(crate) fn road(label: &str, pair: &Pair, stored: bool, trust: &Trust, url: WsUrl, say: Say) -> Option<far::Node> {
    let side = match Side::random(&mut OsEntropy) {
        Ok(side) => side,
        Err(e) => {
            say(format!("no transit road: {e}"));
            return None;
        }
    };
    say(format!(
        "and through the transit relay {}, by the operator's ruling Q65 ({}=no turns it off)",
        url.shown(),
        transit::ENV
    ));
    let keys = keys_now(label, pair, stored);
    let trust = trust_for(&url, trust, crate::pairs::trust(None));
    Some(far::Node { url, keys, side, trust, proxy: ProxyChoice::FromEnvironment, say })
}

/// `pair_road` with the transit road `road` beside it, under `keeper`,
/// until the pair's road ends: its end is the node's, as the transit road's
/// token is the pair's. With no road, the pair's road alone.
pub(crate) async fn alongside<P, O, F>(
    mut pair_road: P,
    road: Option<far::Node>,
    open: O,
    keeper: Arc<Keeper<DuplexStream>>,
) -> P::Output
where
    P: Future + Unpin,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    let Some(road) = road else { return pair_road.await };
    let (settings, budget) = (crate::layered::settings(), reverse::layered::NODE_BUDGET);
    let transit_road = Box::pin(far::serve_kept(road, settings, budget, open, keeper));
    tokio::select! {
        out = &mut pair_road => out,
        // The transit road waits for ever; the pair's road ends the node.
        () = transit_road => pair_road.await,
    }
}

/// A node's transit road, and its pairs at the net's relay members (T-434),
/// beside the pair's road.
pub(crate) struct Beside<'a> {
    pub label: &'a str,
    /// The pair came from the store, whose later pair the node takes.
    pub stored: bool,
    pub trust: &'a Trust,
    /// The transit relay, unless `PODSSH_TRANSIT=no` turned it off.
    pub url: Option<WsUrl>,
    pub say: Say,
}

impl Beside<'_> {
    /// The pair's road of `config`, the transit road and the roads at the
    /// net's relay members, with one keeper, so that a session resumes on
    /// any, until the pair's road ends.
    pub(crate) async fn run(
        self,
        config: &mut NodeConfig<'_>,
        tcp: TcpHandler,
        node: ends::Node,
        routes: Option<Routes>,
    ) -> Exit {
        let (settings, budget) = (crate::layered::settings(), reverse::layered::NODE_BUDGET);
        // The upgrade's keeper: the sessions of the binary before this one,
        // and those that go to the next (T-668).
        let keeper = crate::node_upgrade::channel_keeper(&node, settings.resume_deadline);
        let members = crate::node_members::pairs(&node.identity, &config.pair.relay, self.trust, &self.say).await;
        let say = self.say.clone();
        let road = self.url.and_then(|url| road(self.label, &config.pair, self.stored, self.trust, url, say));
        let (host, port, roost) = (tcp.host.clone(), tcp.port, tcp.sshd);
        // A handler for each road at a relay member, under the same keeper.
        let member_handler = {
            let (tcp, node, routes, keeper) = (tcp.clone(), node.clone(), routes.clone(), keeper.clone());
            move || {
                let (inner, channel) = (Arc::new(tcp.clone()), Some(node.clone()));
                let piped = crate::channel::Piped { inner, channel, routes: routes.clone() };
                Arc::new(Layered::with_keeper(piped, settings, budget, keeper.clone()))
            }
        };
        let piped = crate::channel::Piped { inner: Arc::new(tcp), channel: Some(node.clone()), routes: routes.clone() };
        let layered = Layered::with_keeper(piped, settings, budget, keeper.clone());
        let own = Box::pin(reverse::run(config, Arc::new(layered), crate::node_upgrade::stop()));
        let stop = crate::node_upgrade::stop;
        let pair_road =
            Box::pin(crate::node_members::alongside(own, members, member_handler, self.trust, &self.say, stop));
        // Each session is a pipe, as on the pair's road (T-164): the target
        // is reached once the operator's key is let in.
        let target = move || {
            let host = host.clone();
            async move { reverse::tcp::dial_target(&host, port, DIAL_LIMIT, roost).await }
        };
        let open = move || {
            let (target, channel, routes) = (target.clone(), Some(node.clone()), routes.clone());
            async move { crate::channel::piped_by(channel, routes, target).await }
        };
        alongside(pair_road, road, open, keeper).await
    }
}

/// The client's dialer of the pair whose operator's part is `part`, at
/// `url`; its lines go to `-v` under `shown`. `None` when this host gives no
/// random side, which `-v` says.
pub(crate) fn dialer(url: WsUrl, part: &OperatorPart, trust: &Trust, log: &Arc<Log>, shown: &str) -> Option<Dialer> {
    let say: transit::Say = {
        let (log, shown) = (log.clone(), shown.to_string());
        Arc::new(move |line: String| log.verbose(&format!("{shown}: {line}")))
    };
    let keys = Keys::of_pair(&part.name, part.connect_token());
    let trust = trust_for(&url, trust, crate::pairs::trust(None));
    match Dialer::new(url, keys, trust, ProxyChoice::FromEnvironment, say) {
        Ok(dialer) => Some(dialer),
        Err(e) => {
            log.verbose(&format!("{shown}: no transit road: {e}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn least_authority_s_relay_takes_the_host_s_trust_and_a_named_relay_the_pair_s() {
        let pair = Trust::File("/the/pair/relay/ca.pem".into());
        let least = WsUrl::parse(transit::DEFAULT_URL).unwrap();
        assert!(matches!(trust_for(&least, &pair, Trust::Default), Trust::Default));
        let own = WsUrl::parse("wss://transit.example.test/").unwrap();
        assert!(
            matches!(trust_for(&own, &pair, Trust::Default), Trust::File(ref f) if f == std::path::Path::new("/the/pair/relay/ca.pem"))
        );
    }
}
