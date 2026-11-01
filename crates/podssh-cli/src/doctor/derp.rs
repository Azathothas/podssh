//! The DERP road (T-379): whether each DERP server of the list answers
//! derper's probe through the proxy, with the limit that a node's choice of
//! its home gives each one, and which one a node calls home. A server that
//! does not answer is a fallback of the road that does not work here; with
//! none, `podssh node --derp` cannot start, and the fallback of Q50 has no
//! road. The road is pure Rust, so each build has the check.

use podssh_relay::derp::servers::{self, Server};
use podssh_ws::{ProxyChoice, Trust};

use super::Report;

/// The probe of each server, in the order of the list; then the home.
pub(super) async fn check(report: &mut Report<'_>, trust: &Trust) {
    let (list, named) = match servers::from_environment(None) {
        Ok(chosen) => chosen,
        Err(why) => {
            report.fail("DERP servers", format!("{}: {why}", servers::ENV));
            return;
        }
    };
    let from = if named { servers::ENV.to_string() } else { "Tailscale's tailcat fleet".to_string() };
    let mut home: Option<Server> = None;
    for server in &list {
        let label = format!("DERP server {server}");
        match servers::probe(server, trust, &ProxyChoice::FromEnvironment).await {
            Ok(took) => {
                let ms = took.as_millis();
                report.ok(&label, format!("{} answered in {ms} ms, certificate verified", servers::PROBE_PATH));
                home.get_or_insert_with(|| server.clone());
            }
            Err(why) => report.fail(&label, why),
        }
    }
    match home {
        Some(server) => report.ok(
            "DERP home server",
            format!("{server}: the first of {from} that answered, which podssh node --derp calls home"),
        ),
        None => report.fail("DERP home server", format!("no server of {from} answered {}", servers::PROBE_PATH)),
    }
}
