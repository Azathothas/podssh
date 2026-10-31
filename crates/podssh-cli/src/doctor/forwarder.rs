//! The forwarders of `--forwarder`, `PODSSH_FORWARDER` or `Forwarder` of
//! the settings file (T-369): for each, the upgrade, then GitHub's SSH port
//! through it, whose host key must be one that GitHub publishes, as the
//! relay's forward check identifies the server, never by its banner. With
//! none named, a line says whether the fallback to the forwarders that the
//! binary names is on (T-370).

use std::sync::Arc;

use podssh_relay::relay::RelayList;
use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::forwarder::Dial;
use podssh_ws::Trust;

use super::relay_checks::{github_keys, judge_unlisted, FORWARD_HOST, GITHUB_KEYS, TIMEOUT};
use super::Report;
use crate::forwarder::{fallback, Forwarder};

/// With no forwarder named: whether the run of a relay that failed falls
/// back to the forwarders that the binary names (T-370), with no dial; a
/// user who wants them asked names them with --forwarder.
pub(super) fn fallback_line(report: &mut Report<'_>, relays: &RelayList) {
    let words = podssh_ws::forwarder::builtin::words();
    match fallback::on_from(fallback::env_value(), crate::settings::here()) {
        Err(refusal) => report.fail("fallback", refusal.message),
        Ok(false) => {
            let off = format!("off ({} or ForwarderFallback): {words} are not tried", fallback::FALLBACK_ENV);
            report.ok("fallback", off)
        }
        Ok(true) if relays.explicit => {
            report.ok("fallback", format!("none for the relay hosts that the user names; else {words}, in order"))
        }
        Ok(true) => report.ok(
            "fallback",
            format!(
                "after each relay host fails: {words}, in order, other products' public forwarders (not asked here; \
                 podssh doctor --forwarder {} asks them)",
                words.replace(", ", ",")
            ),
        ),
    }
}

/// One line for each forwarder, in order.
pub(super) async fn check(report: &mut Report<'_>, forwarders: &[Forwarder], trust: &Trust) {
    let target = dial::authority(FORWARD_HOST, 22);
    for forwarder in forwarders {
        let name = &forwarder.name;
        let road = Dial {
            trust,
            proxy: &ProxyChoice::FromEnvironment,
            timeout: TIMEOUT,
            close_at_end: true,
            note: Arc::new(|_: &str| {}),
        };
        let carried = match podssh_ws::forwarder::open(&forwarder.template, FORWARD_HOST, 22, &road).await {
            Ok(carried) => carried,
            Err(e) => {
                report.fail("forwarder", format!("{target}: {}", e.line(name)));
                continue;
            }
        };
        let status = carried.status.clone();
        let key = match podssh_ssh::probe::host_key(carried.stream, TIMEOUT).await {
            Ok(key) => key,
            Err(why) => {
                let end = status.get().and_then(|end| crate::forwarder::reach::ended(name, &end));
                let end = end.map(|line| format!(" ({line})")).unwrap_or_default();
                let line = format!("{target} through the forwarder {name}: the upgrade passed, then {why}{end}");
                report.fail("forwarder", line);
                continue;
            }
        };
        let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
        let kind = podssh_ssh::known_hosts::key_type(&key);
        let shown = format!("{target} through the forwarder {name}: {kind} host key {fingerprint}");
        if GITHUB_KEYS.contains(&fingerprint.as_str()) {
            report.ok("forwarder", format!("{shown}, one of GitHub's published keys"));
            continue;
        }
        let current = github_keys(trust).await;
        report.line("forwarder", judge_unlisted(&shown, &fingerprint, current));
    }
}
