//! The iroh road, in a build with the feature `iroh` (T-162, T-165): whether
//! a UDP socket binds here, so that the road may take direct paths, and
//! whether each relay of the list answers `/ping` through the proxy. The
//! first that answers is the home relay; an endpoint with no UDP path has no
//! other way in, so with no relay that answers, the road has none.

use podssh_iroh::relays::{self, Source};
use podssh_ws::{ProxyChoice, Trust};

use super::Report;

pub(super) fn udp(report: &mut Report<'_>) {
    match podssh_iroh::probe::udp() {
        Ok(addr) => {
            report.ok("bind UDP", format!("bound {addr} and closed it, sending nothing: the iroh road may go direct"))
        }
        Err(e) => report.ok("bind UDP", format!("refused: {e}; the iroh road then uses its relay alone")),
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
        Some(relay) => report.ok("iroh home relay", format!("{relay}: the first of {from} that answered")),
        None => report.fail("iroh home relay", format!("no relay of {from} answered /ping")),
    }
}
