//! The forwarders of `--forwarder`, `PODSSH_FORWARDER` or `Forwarder` of
//! the settings file (T-369): for each, the upgrade, then GitHub's SSH port
//! through it, whose host key must be one that GitHub publishes, as the
//! relay's forward check identifies the server, never by its banner. With
//! none named, a line says whether the fallback to the forwarders that the
//! binary names is on (T-370), as a line that measured nothing (T-509).

use std::sync::Arc;

use podssh_relay::relay::RelayList;
use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::forwarder::Dial;
use podssh_ws::{Trust, Verdict};

use super::relay_checks::{github_keys, judge_unlisted, FORWARD_HOST, GITHUB_KEYS, TIMEOUT};
use super::Report;
use crate::forwarder::{fallback, Forwarder};
use crate::relay_settings::Refusal;

/// With no forwarder named: whether the run of a relay that failed falls
/// back to the forwarders that the binary names (T-370), with no dial; a
/// user who wants them asked names them with --forwarder.
pub(super) fn fallback_line(report: &mut Report<'_>, relays: &RelayList) {
    let on = fallback::on_from(fallback::env_value(), crate::settings::here());
    report.line("fallback", fallback_verdict(on, relays.explicit));
}

/// The line of the fallback: a word of the setting that is neither yes nor
/// no fails; else what the fallback would do, which this line measured
/// nothing of, so it is ????, never ok (T-509), and `unknown` in --json.
pub(super) fn fallback_verdict(on: Result<bool, Refusal>, explicit: bool) -> Verdict {
    let words = podssh_ws::forwarder::builtin::words();
    let why = match on {
        Err(refusal) => return Verdict::Failed { detail: refusal.message },
        Ok(false) => format!("off ({} or ForwarderFallback): {words} are not tried", fallback::FALLBACK_ENV),
        Ok(true) if explicit => format!("none for the relay hosts that the user names; else {words}, in order"),
        Ok(true) => format!(
            "on: once each relay host failed with no word about the target, podssh sends the target to {words}, \
             in order, other products' public forwarders, {} s at most each; podssh doctor --forwarder {} asks them",
            fallback::EACH_WAIT.as_secs(),
            words.replace(", ", ",")
        ),
    };
    Verdict::Unknown { why: format!("not asked here: {why}") }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// T-509: the fallback's line measured nothing, so it is ???? in each
    /// case, outside the count of ok, and `unknown` in --json; only a word
    /// that is neither yes nor no fails.
    #[test]
    fn the_fallback_s_line_is_not_measured() {
        let on = fallback_verdict(Ok(true), false);
        let Verdict::Unknown { why } = &on else { panic!("{on:?}") };
        assert!(why.starts_with("not asked here: on: once each relay host failed with no word about the target"));
        assert!(why.contains("mudlet, ssheasy, mudix, wisp, in order") && why.contains("10 s at most each"), "{why}");
        assert!(why.ends_with("podssh doctor --forwarder mudlet,ssheasy,mudix,wisp asks them"), "{why}");
        for (verdict, says) in [
            (fallback_verdict(Ok(false), false), "not asked here: off (PODSSH_FORWARDER_FALLBACK"),
            (fallback_verdict(Ok(true), true), "not asked here: none for the relay hosts that the user names"),
        ] {
            assert!(matches!(&verdict, Verdict::Unknown { why } if why.starts_with(says)), "{verdict:?}");
        }
        let bad = fallback_verdict(Err(Refusal::config("PODSSH_FORWARDER_FALLBACK=maybe: yes or no")), false);
        assert!(matches!(bad, Verdict::Failed { .. }), "{bad:?}");
        // In the report: a ???? line, counted apart.
        let mut out = Vec::new();
        let mut report = Report::new(&mut out);
        report.line("fallback", on);
        let _ = report.finish();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("  ????  fallback       not asked here: on:"), "{text}");
        assert!(text.contains("0 ok, 0 FAIL, 1 ????"), "{text}");
    }
}
