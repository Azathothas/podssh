//! The forwarders of `--forwarder`, `PODSSH_FORWARDER` or `Forwarder` of
//! the settings file (T-369): for each, the upgrade, then GitHub's SSH port
//! through it, whose host key must be one that GitHub publishes, as the
//! relay's forward check identifies the server, never by its banner.

use std::sync::Arc;

use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::forwarder::Dial;
use podssh_ws::Trust;

use super::relay_checks::{github_keys, judge_unlisted, FORWARD_HOST, GITHUB_KEYS, TIMEOUT};
use super::Report;
use crate::forwarder::Forwarder;

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
