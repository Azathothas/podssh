//! The pairs of the reverse road in the store (T-083): for each label, when it
//! expires, and whether its node is online, as `podssh relay status` asks.

use std::time::Duration;

use podssh_relay::pair::{self, Pair, PairContext};
use podssh_ws::dial::ProxyChoice;
use podssh_ws::Trust;

use super::Report;
use crate::pairs::{now_ms, utc};

/// Bound on each question to the relay, as for the other checks.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The stored pairs that can be used; a FAIL for each one that has expired or
/// cannot be read, which a node could not use either.
pub(super) fn stored(report: &mut Report<'_>) -> Vec<(String, Pair)> {
    let labels = pair::labels();
    if labels.is_empty() {
        report.ok("pairs", "none in the store");
    }
    let mut usable = Vec::new();
    for label in labels {
        let name = format!("pair {label}");
        match pair::load(&label) {
            Ok(Some(found)) if found.expires_ms > now_ms() => usable.push((label, found)),
            Ok(Some(found)) => report.fail(
                &name,
                format!("expired at {}; make a new one with podssh relay pair {label}", utc(found.expires_ms)),
            ),
            Ok(None) => {}
            Err(e) => report.fail(&name, e.to_string()),
        }
    }
    usable
}

/// Whether the node of each pair is online.
pub(super) async fn presence(report: &mut Report<'_>, pairs: &[(String, Pair)], trust: &Trust) {
    let proxy = ProxyChoice::FromEnvironment;
    for (label, found) in pairs {
        let name = format!("pair {label}");
        let until = utc(found.expires_ms);
        let ctx = PairContext { relay: &found.relay, trust, proxy: &proxy, timeout: TIMEOUT };
        match pair::status(&ctx, found).await {
            Ok(seen) if seen.online => {
                report.ok(&name, format!("node online, {} sessions; expires {until}", seen.sessions))
            }
            Ok(_) => report.ok(&name, format!("node offline; expires {until}")),
            Err(e) => report.fail(&name, e.to_string()),
        }
    }
}

/// With no network: each pair's expiry; its presence not asked.
pub(super) fn not_asked(report: &mut Report<'_>, pairs: &[(String, Pair)], why: &str) {
    for (label, found) in pairs {
        report.unknown(&format!("pair {label}"), format!("{why}; expires {}", utc(found.expires_ms)));
    }
}
