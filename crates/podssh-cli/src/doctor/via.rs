//! The second proxy of `--via` (T-439): TLS to it, through `HTTPS_PROXY`
//! as a run dials it, the version of HTTP that it chose, and its CONNECT to
//! GitHub's SSH port, whose host key must be one that GitHub publishes, as
//! the relay's forward check identifies the server, never by its banner.

use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::via::{Client, Dial};

use super::relay_checks::{github_keys, judge_unlisted, FORWARD_HOST, GITHUB_KEYS, TIMEOUT};
use super::Report;
use crate::via::Road;

/// One line for the second proxy: what carried the TLS, the version that it
/// spoke, and the host key that came through it.
pub(super) async fn check(report: &mut Report<'_>, road: &Road) {
    let target = dial::authority(FORWARD_HOST, 22);
    let shown = road.shown();
    let first = match dial::proxy_from_env(&road.via.host) {
        Ok(Some(proxy)) => format!(", through the proxy {proxy}"),
        _ => String::new(),
    };
    let (proxy, trust) = (ProxyChoice::FromEnvironment, road.trust.clone());
    let client = Client::new(road.via.clone(), Dial { trust, proxy, timeout: TIMEOUT, offer: road.offer });
    let started = std::time::Instant::now();
    let opened = match client.open(FORWARD_HOST, 22).await {
        Ok(opened) => opened,
        Err(e) => {
            report.fail("via", format!("{target} through {shown}{first}: {e}"));
            return;
        }
    };
    let ms = started.elapsed().as_millis();
    let after = opened.fell_back.as_deref().map(|why| format!(", as {why}")).unwrap_or_default();
    let version = opened.version.name();
    let reached = format!("{target} through {shown}{first}: TLS, then CONNECT over {version}{after}, in {ms} ms");
    let key = match podssh_ssh::probe::host_key(opened.stream, TIMEOUT).await {
        Ok(key) => key,
        Err(why) => {
            report.fail("via", format!("{reached}, then {why}"));
            return;
        }
    };
    let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
    let kind = podssh_ssh::known_hosts::key_type(&key);
    let line = format!("{reached}; {kind} host key {fingerprint}");
    if GITHUB_KEYS.contains(&fingerprint.as_str()) {
        report.ok("via", format!("{line}, one of GitHub's published keys"));
        return;
    }
    let current = github_keys(&road.trust).await;
    report.line("via", judge_unlisted(&line, &fingerprint, current));
}
