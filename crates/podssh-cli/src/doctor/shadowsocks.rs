//! The first server of `--shadowsocks FILE` (T-373): the TCP, through the
//! proxy as a run dials it; the server's salt and first chunk, within their
//! wait; then GitHub's SSH port through it, whose host key must be one that
//! GitHub publishes, as the relay's forward check identifies the server,
//! never by its banner. A server that stays silent names the proxy as the
//! likely cause when one carried the TCP, as T-317's line does.

use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::shadowsocks::{self, Dial};
use podssh_ws::Trust;

use super::relay_checks::{github_keys, judge_unlisted, FORWARD_HOST, GITHUB_KEYS, TIMEOUT};
use super::Report;
use crate::shadowsocks::order::Order;
use crate::shadowsocks::Servers;

/// One line for the first server of the file, and one for each line of a
/// list that its fetch said.
pub(super) async fn check(report: &mut Report<'_>, servers: &Servers, trust: &Trust) {
    let target = dial::authority(FORWARD_HOST, 22);
    let mut notes: Vec<String> = Vec::new();
    let first = Order::new(servers, trust).next(&mut |line: &str| notes.push(line.to_string())).await;
    let Some(node) = first else {
        // Each list failed: its lines say why.
        for note in notes {
            report.fail("subscription", note);
        }
        report.fail("shadowsocks", "no server to check: the file's subscriptions gave none");
        return;
    };
    for note in notes {
        report.ok("subscription", note);
    }
    let shown = node.shown();
    let road = Dial {
        proxy: &ProxyChoice::FromEnvironment,
        timeout: TIMEOUT,
        answer: Some(shadowsocks::ANSWER_WAIT),
        silence_is_ready: false,
    };
    let opened = match shadowsocks::open(&node, FORWARD_HOST, 22, &road).await {
        Ok(opened) => opened,
        Err(e) => {
            report.fail("shadowsocks", e.line(&shown, &target));
            return;
        }
    };
    let ms = opened.answered_in.map_or(0, |d| d.as_millis());
    let reached = format!("{target} through {shown}: TCP, then the server's salt and first chunk in {ms} ms");
    let status = opened.carried.status.clone();
    let key = match podssh_ssh::probe::host_key(opened.carried.stream, TIMEOUT).await {
        Ok(key) => key,
        Err(why) => {
            let end = status.get().map(|end| format!(" ({})", crate::shadowsocks::reach::ended(&shown, &end)));
            report.fail("shadowsocks", format!("{reached}, then {why}{}", end.unwrap_or_default()));
            return;
        }
    };
    let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
    let kind = podssh_ssh::known_hosts::key_type(&key);
    let line = format!("{reached}; {kind} host key {fingerprint}");
    if GITHUB_KEYS.contains(&fingerprint.as_str()) {
        report.ok("shadowsocks", format!("{line}, one of GitHub's published keys"));
        return;
    }
    let current = github_keys(trust).await;
    report.line("shadowsocks", judge_unlisted(&line, &fingerprint, current));
}
