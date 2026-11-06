//! The servers of `--vless FILE` (T-440): for each, its link's transport,
//! and each mode of XHTTP where the link says auto, through `HTTPS_PROXY` as
//! a run dials, then a session to GitHub's SSH port, whose host key must be
//! one that GitHub publishes, as the relay's forward check identifies the
//! server, never by its banner. Each line names the transport that carried
//! it, so that the user learns which one passes here; a mode of XHTTP that
//! went over HTTP/1.1, where HTTP/2 was refused, says its second connection
//! (Q67).

use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::vless::{self, Dial};
use podssh_ws::Trust;

use super::relay_checks::{github_keys, judge_unlisted, FORWARD_HOST, GITHUB_KEYS, TIMEOUT};
use super::Report;
use crate::vless::Servers;

/// A line for each server and each transport that it is tried on.
pub(super) async fn check(report: &mut Report<'_>, servers: &Servers, trust: &Trust) {
    let target = dial::authority(FORWARD_HOST, 22);
    let road = Dial {
        trust,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: TIMEOUT,
        answer: vless::ANSWER_WAIT,
        silence_is_ready: false,
        close_at_end: true,
    };
    for server in &servers.servers {
        let shown = server.shown();
        let first = match dial::proxy_from_env(&server.host) {
            Ok(Some(proxy)) => format!(", through the proxy {proxy}"),
            _ => String::new(),
        };
        for transport in vless::modes(server.transport) {
            let started = std::time::Instant::now();
            let opened = match vless::open_as(server, transport, FORWARD_HOST, 22, &road).await {
                Ok(opened) => opened,
                Err(e) => {
                    report.fail("vless", format!("{}{first}: {}", transport.name(), e.line(&shown, &target)));
                    continue;
                }
            };
            let ms = started.elapsed().as_millis();
            let reached = format!("{target} through {shown}{first} over {}, answered in {ms} ms", opened.how);
            let key = match podssh_ssh::probe::host_key(opened.stream, TIMEOUT).await {
                Ok(key) => key,
                Err(why) => {
                    report.fail("vless", format!("{reached}, then {why}"));
                    continue;
                }
            };
            let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
            let kind = podssh_ssh::known_hosts::key_type(&key);
            let line = format!("{reached}; {kind} host key {fingerprint}");
            if GITHUB_KEYS.contains(&fingerprint.as_str()) {
                report.ok("vless", format!("{line}, one of GitHub's published keys"));
                continue;
            }
            let current = github_keys(trust).await;
            report.line("vless", judge_unlisted(&line, &fingerprint, current));
        }
    }
}
