//! The line `cleartext` (T-326, GitHub #56): what a request with no TLS
//! meets on the way to a relay host's port, and to its port 80 when that is
//! 443, as podssh's cleartext road would meet it once the TLS road failed:
//! the CONNECT that the proxy takes, then `GET /health`, with nothing
//! secret in it, and what came back: a reset or a close (a hop that expects
//! TLS cuts cleartext), a record of TLS, the far end's refusal (an edge that
//! serves TLS alone answers 400; a refusal by policy, 403), a redirect, or an
//! answer, the relay's own `/health` among them. The section of the
//! forwarders asks the host of each forwarder that it names the same. The
//! probes go one after another.

use std::time::Duration;

use podssh_relay::health::SERVICE;
use podssh_relay::relay::Relay;
use podssh_ws::cleartext::Heard;
use podssh_ws::{DialError, ProxyChoice, Verdict};
use serde_json::Value;

use super::Report;

/// The line of the section relay: `relay`, the first host that answered
/// `/health` over TLS when one did (`tls`), else the first host of the list.
pub(super) async fn check(report: &mut Report<'_>, relay: &Relay, tls: bool, timeout: Duration) {
    let heard = probes(&relay.host, relay.port, timeout).await;
    report.line("cleartext", verdict(&relay.host, &heard, tls));
}

/// The line of a forwarder whose host is `host:port`.
pub(super) async fn forwarder(report: &mut Report<'_>, host: &str, port: u16, timeout: Duration) {
    let heard = probes(host, port, timeout).await;
    report.line("cleartext", forwarder_verdict(host, &heard));
}

/// The ports that a host is probed at: its own, and 80 beside 443, as #56
/// asks.
fn ports(port: u16) -> Vec<u16> {
    if port == 443 {
        vec![443, 80]
    } else {
        vec![port]
    }
}

/// What each port of `host` answered, one probe after another, through the
/// proxy of the environment, as each road dials.
async fn probes(host: &str, port: u16, timeout: Duration) -> Vec<(u16, Heard)> {
    let mut heard = Vec::new();
    for port in ports(port) {
        heard.push((port, podssh_ws::cleartext::probe(host, port, &ProxyChoice::FromEnvironment, timeout).await));
    }
    heard
}

/// The version of the relay whose `/health` answered, when one did.
fn relay_of(heard: &Heard) -> Option<String> {
    let Heard::Answered { status: 200..=299, body, .. } = heard else { return None };
    let doc: Value = serde_json::from_slice(body).ok()?;
    if doc.get("service")?.as_str()? != SERVICE {
        return None;
    }
    let version = doc.get("version").and_then(Value::as_str).map(podssh_ws::text::one_line);
    Some(version.unwrap_or_else(|| "(no version)".into()))
}

/// The words of one port's answer, a relay's `/health` named.
fn words(heard: &Heard) -> String {
    match relay_of(heard) {
        Some(version) => format!("an answer: the relay's /health, {SERVICE} {version}"),
        None => heard.words(),
    }
}

/// Whether no probe could run: the proxy setting or the name cannot be
/// used, so nothing was measured.
fn unmeasured(heard: &[(u16, Heard)]) -> bool {
    heard.iter().all(|(_, h)| matches!(h, Heard::Unreached(DialError::BadProxy(_) | DialError::InvalidTarget(_))))
}

/// Each port's words, as `HOST:PORT: WORDS; ...`.
fn said(host: &str, heard: &[(u16, Heard)]) -> String {
    let each: Vec<String> =
        heard.iter().map(|(port, h)| format!("{}: {}", podssh_ws::dial::authority(host, *port), words(h))).collect();
    each.join("; ")
}

/// The verdict of the probes of a relay host, the first at the port that
/// the cleartext road takes: a fact, `ok`, and `????` when no probe could
/// run. A reset is no fault where TLS answered.
pub(super) fn verdict(host: &str, heard: &[(u16, Heard)], tls: bool) -> Verdict {
    let said = said(host, heard);
    if unmeasured(heard) {
        return Verdict::Unknown { why: format!("not measured: {said}") };
    }
    let reached = heard.first().is_some_and(|(_, h)| relay_of(h).is_some());
    let road = match (reached, tls) {
        (true, false) => {
            "the cleartext road reaches this relay, and podssh takes it last, as its TLS failed, with a token of \
             one session"
        }
        (true, true) => "the cleartext road reaches this relay too; podssh takes it only once the TLS road failed",
        (false, true) => "the TLS road answered, and podssh needs no cleartext road here",
        (false, false) => "the cleartext road does not reach this relay either",
    };
    Verdict::Ok { detail: format!("in cleartext, {said}; {road}") }
}

/// The verdict of the probes of a forwarder's host: a fact too, with
/// whether a `ws://` form of it can pass on this path.
pub(super) fn forwarder_verdict(host: &str, heard: &[(u16, Heard)]) -> Verdict {
    let said = said(host, heard);
    if unmeasured(heard) {
        return Verdict::Unknown { why: format!("not measured: {said}") };
    }
    let road = match heard.iter().find(|(_, h)| h.passed()) {
        Some((port, _)) => format!("a ws:// form of it can pass on this path, at port {port}"),
        None => "no ws:// form of it passes on this path".to_string(),
    };
    Verdict::Ok { detail: format!("in cleartext, {said}; {road}") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_ws::Cut;

    fn health() -> Heard {
        let body = br#"{"service":"tcp-ssh-relay","version":"podssh 1.1.0"}"#.to_vec();
        Heard::Answered { status: 200, reason: "OK".into(), location: None, body }
    }

    /// A path that resets cleartext is named so, as no fault where TLS
    /// answered; one that carries it to the relay names the road.
    #[test]
    fn a_reset_and_the_relay_s_answer_are_named() {
        let reset = verdict("relay-a.test", &[(443, Heard::Cut(Cut::Reset)), (80, Heard::Cut(Cut::Reset))], true);
        let Verdict::Ok { detail } = &reset else { panic!("{reset:?}") };
        assert!(detail.starts_with("in cleartext, relay-a.test:443: reset, with no answer"), "{detail}");
        assert!(detail.ends_with("the TLS road answered, and podssh needs no cleartext road here"), "{detail}");
        let reached = verdict("relay-a.test", &[(8443, health())], false);
        let Verdict::Ok { detail } = &reached else { panic!("{reached:?}") };
        let said = "in cleartext, relay-a.test:8443: an answer: the relay's /health, tcp-ssh-relay podssh 1.1.0";
        assert!(detail.starts_with(said), "{detail}");
        assert!(detail.contains("podssh takes it last, as its TLS failed"), "{detail}");
        let neither = verdict("relay-a.test", &[(443, Heard::Tls)], false);
        assert!(matches!(&neither, Verdict::Ok { detail } if detail.ends_with("does not reach this relay either")));
        let bad = Heard::Unreached(DialError::BadProxy("HTTPS_PROXY: no host".into()));
        assert!(matches!(verdict("r", &[(443, bad)], false), Verdict::Unknown { .. }), "nothing measured");
        assert_eq!(ports(443), [443, 80]);
        assert_eq!(ports(8443), [8443]);
    }

    /// A forwarder's host: the port that passed is named.
    #[test]
    fn a_forwarder_s_host_says_where_a_ws_form_passes() {
        let refusal = Heard::Answered { status: 426, reason: "Upgrade Required".into(), location: None, body: vec![] };
        let heard = [(443, Heard::Cut(Cut::Reset)), (80, refusal)];
        let passed = forwarder_verdict("w.example", &heard);
        assert!(matches!(&passed, Verdict::Ok { detail } if detail.ends_with("can pass on this path, at port 80")));
        let none = forwarder_verdict("w.example", &[(443, Heard::Tls), (80, Heard::Cut(Cut::Closed))]);
        let Verdict::Ok { detail } = &none else { panic!("{none:?}") };
        assert!(detail.ends_with("no ws:// form of it passes on this path"), "{detail}");
    }
}
