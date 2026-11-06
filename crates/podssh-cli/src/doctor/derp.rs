//! The DERP road (T-379): whether each DERP server of the list answers
//! derper's probe through the proxy, with the limit that a node's choice of
//! its home gives each one, and which one a node calls home. Of Tailscale's
//! main fleet, after tailcat's four (T-534), the servers are probed in
//! order until one answers, in one line, as it has 91. A server that
//! does not answer is a fallback of the road that does not work here; with
//! none, `podssh node --derp` cannot start, and the fallback of Q50 has no
//! road. The road is pure Rust, so each build has the check.

use podssh_relay::derp::servers::{self, Server};
use podssh_ws::{ProxyChoice, Trust};

use super::diagnosis::{met_of, Met, Of};
use super::Report;

/// The probe of each server, in the order of the list; then the home.
pub(super) async fn check(report: &mut Report<'_>, trust: &Trust) {
    let (list, named) = match servers::from_environment(None) {
        Ok(chosen) => chosen,
        Err(why) if why.starts_with(servers::MAIN_ENV) => {
            report.fail("DERP servers", why);
            return;
        }
        Err(why) => {
            report.fail("DERP servers", format!("{}: {why}", servers::ENV));
            return;
        }
    };
    let from = if named { servers::ENV.to_string() } else { servers::TAILCAT_FLEET.to_string() };
    let main: Vec<Server> = list.iter().filter(|s| s.fleet_name() == Some(servers::MAIN_FLEET)).cloned().collect();
    let mut home: Option<Server> = None;
    for server in list.iter().filter(|s| named || s.fleet_name() != Some(servers::MAIN_FLEET)) {
        let label = format!("DERP server {server}");
        // What its TLS met, beside the line, for the diagnosis (T-487).
        match servers::probe_kept(server, trust, &ProxyChoice::FromEnvironment).await {
            Ok(took) => {
                report.handshake(Of::Derp, &server.host, Met::Completed);
                let ms = took.as_millis();
                report.ok(&label, format!("{} answered in {ms} ms, certificate verified", servers::probe_path()));
                home.get_or_insert_with(|| server.clone());
            }
            Err(missed) => {
                report.handshake(Of::Derp, &server.host, met_of(missed.cut));
                report.fail(&label, missed.why);
            }
        }
    }
    if !named && !main.is_empty() {
        let found = main_line(report, &main, trust).await;
        if home.is_none() {
            home = found;
        }
    }
    match home {
        Some(server) => {
            let fleet = server.fleet_name().unwrap_or(&from);
            let line =
                format!("{server}, of {fleet}: the first server that answered, which podssh node --derp calls home");
            report.ok("DERP home server", line)
        }
        None => report.fail("DERP home server", format!("no server of {from} answered {}", servers::probe_path())),
    }
}

/// How long doctor looks among the main fleet: a short check.
const MAIN_LOOK: std::time::Duration = std::time::Duration::from_secs(20);

/// The main fleet in one line: its first server that answers within
/// [`MAIN_LOOK`], and how many did not before it.
async fn main_line(report: &mut Report<'_>, main: &[Server], trust: &Trust) -> Option<Server> {
    let label = servers::MAIN_FLEET;
    let mut missed = Vec::new();
    let since = std::time::Instant::now();
    for server in main.iter().take_while(|_| since.elapsed() < MAIN_LOOK) {
        match servers::probe_kept(server, trust, &ProxyChoice::FromEnvironment).await {
            Ok(took) => {
                report.handshake(Of::Derp, &server.host, Met::Completed);
                let before = match missed.len() {
                    0 => String::new(),
                    n => format!(", after {n} that did not ({})", few(&missed)),
                };
                let ms = took.as_millis();
                report.ok(label, format!("{server} answered {} in {ms} ms{before}", servers::probe_path()));
                return Some(server.clone());
            }
            Err(miss) => {
                report.handshake(Of::Derp, &server.host, met_of(miss.cut));
                missed.push(miss.why);
            }
        }
    }
    let (tried, of, path) = (missed.len(), main.len(), servers::probe_path());
    let line = format!(
        "none of the {tried} of its {of} servers tried in {} s answered {path} ({})",
        MAIN_LOOK.as_secs(),
        missed.join("; ")
    );
    report.fail(label, line);
    None
}

/// The first three misses, and how many more: a line, not a list of 91.
fn few(missed: &[String]) -> String {
    let mut shown = missed.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
    if missed.len() > 3 {
        shown.push_str(&format!("; and {} more", missed.len() - 3));
    }
    shown
}
