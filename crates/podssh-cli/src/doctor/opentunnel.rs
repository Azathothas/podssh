//! The OpenTunnel road (T-531): whether the API's host of the service,
//! `opentunnel.xyz` or the one of `PODSSH_OPENTUNNEL`, answers `/health`
//! through the proxy, its certificate verified with the host's trust. It
//! makes no tunnel, binds no CSR and sends no token: a node's tunnel is the
//! node's to make. A host that does not answer is a road that does not work
//! here; `podssh node --opentunnel` then cannot start, and the fallback of
//! Q76 has no road. The road is pure Rust, so each build has the check.

use podssh_relay::opentunnel::api::Api;
use podssh_relay::opentunnel::{dial, Service, ENV};
use podssh_ws::{ProxyChoice, Trust};
use tokio::time::Instant;

use super::Report;

/// The probe of the service's API host.
pub(super) async fn check(report: &mut Report<'_>, trust: &Trust) {
    let service = match crate::node_opentunnel::service() {
        Ok(Some(service)) => service,
        Ok(None) => {
            report.unknown("OpenTunnel", format!("{ENV}=no turns the road off, so nothing was checked"));
            return;
        }
        Err(refusal) => {
            report.fail("OpenTunnel", refusal.message);
            return;
        }
    };
    // OpenTunnel's own service is public: the host's trust, never the
    // relay's --ca-file; a service of the variable's takes the run's.
    let trust = if service == Service::hosted() { crate::pairs::trust(None) } else { trust.clone() };
    let label = format!("OpenTunnel {}", service.authority());
    let api = Api::new(service, dial::tls(trust, ProxyChoice::FromEnvironment));
    let started = Instant::now();
    match api.health().await {
        Ok(status) if (200..300).contains(&status) => {
            let ms = started.elapsed().as_millis();
            report.ok(&label, format!("/health answered {status} in {ms} ms, certificate verified; no tunnel made"));
        }
        Ok(status) => report.fail(&label, format!("/health answered {status}: the API's host does not serve here")),
        Err(why) => report.fail(&label, why),
    }
}
