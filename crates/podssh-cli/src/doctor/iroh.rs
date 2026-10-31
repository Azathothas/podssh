//! The iroh road, in a build with the feature `iroh` (T-162, T-165): whether
//! a UDP socket binds here, whether each relay of the list answers `/ping`
//! through the proxy, and whether a datagram to the home relay comes back,
//! as the road's own probe finds it before it takes UDP (T-359). The first
//! relay that answers is the home relay; an endpoint with no UDP path has no
//! other way in, so with no relay that answers, the road has none.

use std::time::Duration;

use iroh::RelayUrl;
use podssh_iroh::relays::{self, Source};
use podssh_iroh::{Options, Udp};
use podssh_ws::{ProxyChoice, Trust};

use super::Report;

/// A bind says only that a socket binds: whether a datagram leaves is the
/// line `iroh UDP out`.
pub(super) fn udp(report: &mut Report<'_>) {
    match podssh_iroh::probe::udp() {
        Ok(addr) => report.ok("bind UDP", format!("bound {addr} and closed it, sending nothing")),
        Err(e) => report.ok("bind UDP", format!("refused: {e}; the iroh road then uses its relay alone")),
    }
}

/// How long the probe's endpoint may take to close.
const CLOSE_LIMIT: Duration = Duration::from_secs(3);

/// The road's own probe of UDP: an endpoint on the home relay, as `podssh
/// ssh` makes it, with a key of its own that no file keeps, and the answer
/// that the road would take. Each answer is `ok`, as the relay alone is a
/// road that works; an endpoint that cannot start is the road's failure.
async fn udp_out(report: &mut Report<'_>, home: RelayUrl, trust: &Trust) {
    let options = Options {
        relays: vec![home],
        proxy: ProxyChoice::FromEnvironment,
        trust: trust.clone(),
        udp: Udp::from_environment(),
        ..Options::default()
    };
    match podssh_iroh::endpoint::open(&options).await {
        Ok(opened) => {
            report.ok("iroh UDP out", opened.udp.to_string());
            let _ = tokio::time::timeout(CLOSE_LIMIT, opened.endpoint.close()).await;
        }
        Err(e) => report.fail("iroh UDP out", e.to_string()),
    }
}

/// `/ping` of each relay, in the order of the list, with the limit that the
/// road's own choice of a home relay gives each one; then the home relay.
pub(super) async fn relay(report: &mut Report<'_>, trust: &Trust) {
    let (list, source) = match relays::from_environment(None) {
        Ok(chosen) => chosen,
        Err(why) => {
            report.fail("iroh relays", why);
            return;
        }
    };
    let from = match source {
        Source::Table => "the built-in list".to_string(),
        Source::Variable | Source::Flag => relays::ENV.to_string(),
    };
    let mut home = None;
    for relay in &list {
        // The port too, when the URL gives one: two relays may share a host.
        let host = relay.host_str().unwrap_or_default();
        let label = match relay.port() {
            Some(port) => format!("iroh relay {host}:{port}"),
            None => format!("iroh relay {host}"),
        };
        match relays::ping(relay, trust, &ProxyChoice::FromEnvironment, relays::PING_LIMIT).await {
            Ok(pong) => {
                let ms = pong.elapsed.as_millis();
                report.ok(&label, format!("/ping answered in {ms} ms, certificate verified ({})", pong.way));
                home.get_or_insert_with(|| relay.clone());
            }
            // Each relay that does not answer is a fallback of the road that
            // does not work here.
            Err(why) => report.fail(&label, why),
        }
    }
    match home {
        Some(relay) => {
            report.ok("iroh home relay", format!("{relay}: the first of {from} that answered"));
            udp_out(report, relay, trust).await;
        }
        None => report.fail("iroh home relay", format!("no relay of {from} answered /ping")),
    }
}
