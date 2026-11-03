//! The tests of the diagnosis (T-487): what each cut is, each case of the
//! handshakes and the runs that show none, and the line after the counts.

use super::*;
use podssh_ws::{DialError, TlsFailure};
use std::time::Duration;

fn tls(cut: Option<Cut>) -> ConnectError {
    ConnectError::Tls(TlsFailure { why: "the handshake".into(), cut })
}

/// A reset and a close with nothing are the far end's; a timeout of the
/// handshake or of the dial is the path's silence; anything else, other.
#[test]
fn each_end_of_a_connection_is_what_it_met() {
    assert_eq!(met(&tls(Some(Cut::Reset))), Met::Reset);
    assert_eq!(met(&tls(Some(Cut::Closed))), Met::Reset);
    assert_eq!(met(&tls(None)), Met::Other, "a certificate's refusal");
    let late = ConnectError::Timeout { step: "the TLS handshake", after: Duration::from_secs(10) };
    assert_eq!(met(&late), Met::TimedOut);
    let dial = DialError::Timeout { step: "connecting to r:443".into(), after: Duration::from_secs(10) };
    assert_eq!(met(&ConnectError::Dial(dial)), Met::TimedOut);
    let refused = DialError::Connect { target: "r:443".into(), detail: "refused".into(), cut: Some(Cut::Refused) };
    assert_eq!(met(&ConnectError::Dial(refused)), Met::Other, "a port that says no is no reset of TLS");
    assert_eq!(met(&ConnectError::Refused { status: 403, body: String::new() }), Met::Other);
}

fn road(of: Of, name: &str, met: Met) -> Handshake {
    Handshake { of, name: name.into(), met, through: None }
}

fn reference(met: Met, through: Option<&str>) -> Handshake {
    Handshake { of: Of::Reference, name: REFERENCE.into(), met, through: through.map(String::from) }
}

/// The reporter's host (GitHub #99): each relay host reset, github.com's
/// handshake completed; a DERP server whose name is listed completed too.
#[test]
fn each_relay_host_reset_and_the_reference_completed_is_a_list_of_names() {
    let seen = [
        road(Of::Relay, "relay-a.example", Met::Reset),
        reference(Met::Completed, None),
        road(Of::Relay, "relay-b.example", Met::Reset),
        road(Of::Derp, "derp-a.example", Met::Reset),
        road(Of::Derp, "derp-b.example", Met::Completed),
    ];
    let found = diagnose(&seen);
    assert_eq!(found.len(), 1, "{found:?}");
    let one = &found[0];
    assert_eq!(one.kind, "tls-names");
    assert!(one.detail.starts_with("this host resets TLS for each name that it does not list"), "{}", one.detail);
    assert!(one.detail.contains("(3 of the 4 handshakes of the roads), and github.com's completed"), "{}", one.detail);
    assert!(one.detail.contains("--forwarder, --via, or a relay of your own (--relay-host)"), "{}", one.detail);
    assert_eq!(one.evidence, ["github.com", "derp-b.example"]);
    // Through a proxy, the way out is the proxy's.
    let mut proxied = seen.to_vec();
    proxied[1] = reference(Met::Completed, Some("proxy.example:3128"));
    let found = diagnose(&proxied);
    assert!(found[0].detail.starts_with("the way out through the proxy proxy.example:3128 resets TLS"), "{found:?}");
}

/// Each handshake reset, github.com's too; each timed out, github.com's too.
#[test]
fn each_reset_and_each_timeout_are_cases_of_their_own() {
    let reset = [reference(Met::Reset, None), road(Of::Relay, "r", Met::Reset), road(Of::Derp, "d", Met::Reset)];
    let found = diagnose(&reset);
    assert_eq!((found.len(), found[0].kind), (1, "tls-reset"), "{found:?}");
    assert!(found[0].detail.starts_with("this host resets each TLS handshake on port 443, whatever its name"));
    assert_eq!(found[0].evidence, ["github.com", "r", "d"]);
    let late = Met::TimedOut;
    let dropped = [road(Of::Relay, "r", late), reference(late, None), road(Of::Derp, "d", late)];
    let found = diagnose(&dropped);
    assert_eq!((found.len(), found[0].kind), (1, "tls-dropped"), "{found:?}");
    assert!(found[0].detail.contains("drops each handshake on port 443 and resets none"), "{}", found[0].detail);
    assert!(found[0].detail.contains("not one that lists names"), "{}", found[0].detail);
}

/// No case where the handshakes show none: a host that works, a mix, no
/// reference, no relay host, and a list of names where a road timed out.
#[test]
fn a_run_that_shows_no_case_has_no_diagnosis() {
    let healthy = [reference(Met::Completed, None), road(Of::Relay, "r", Met::Completed)];
    assert!(diagnose(&healthy).is_empty());
    let one_of_two =
        [reference(Met::Completed, None), road(Of::Relay, "a", Met::Reset), road(Of::Relay, "b", Met::Completed)];
    assert!(diagnose(&one_of_two).is_empty(), "a relay host that completed is no list of names");
    let mixed = [reference(Met::Reset, None), road(Of::Relay, "r", Met::Reset), road(Of::Derp, "d", Met::Completed)];
    assert!(diagnose(&mixed).is_empty());
    assert!(diagnose(&[road(Of::Relay, "r", Met::Reset)]).is_empty(), "no reference");
    assert!(diagnose(&[reference(Met::Completed, None), road(Of::Derp, "d", Met::Reset)]).is_empty(), "no relay");
    let late = [reference(Met::Completed, None), road(Of::Relay, "r", Met::Reset), road(Of::Derp, "d", Met::TimedOut)];
    assert!(diagnose(&late).is_empty(), "a road that timed out is a path that drops");
    let other = [reference(Met::Other, None), road(Of::Relay, "r", Met::Reset)];
    assert!(diagnose(&other).is_empty(), "a reference that failed otherwise tells nothing");
}

/// The diagnosis comes after the counts, once, and counts as nothing; in
/// `--json` it is `diagnosis`, with its kind, detail and evidence.
#[test]
fn the_diagnosis_follows_the_counts_and_adds_none() {
    let run = |json: bool| {
        let mut out = Vec::new();
        let code = {
            let mut report = Report::new(&mut out);
            report.json = json;
            report.fail("relay", "relay.example: reset");
            report.handshake(Of::Relay, "relay.example", Met::Reset);
            report.handshakes.push(reference(Met::Completed, None));
            report.finish()
        };
        (code, String::from_utf8(out).unwrap())
    };
    let (code, text) = run(false);
    assert_eq!(code, super::super::EXIT_FAILED);
    let lines: Vec<&str> = text.lines().collect();
    let counts = lines.iter().position(|l| l.starts_with("0 ok, 1 FAIL, 0 ????")).expect(&text);
    assert!(lines[counts + 1].starts_with("diagnosis: this host resets TLS for each name"), "{text}");
    assert_eq!(lines.len(), counts + 2, "one line: {text}");
    let (_, json) = run(true);
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(doc["counts"], serde_json::json!({ "ok": 0, "fail": 1, "unknown": 0 }));
    let found = &doc["diagnosis"][0];
    assert_eq!(found["kind"], "tls-names", "{json}");
    assert_eq!(found["evidence"], serde_json::json!(["github.com"]));
    assert!(found["detail"].as_str().unwrap().starts_with("this host resets TLS"), "{json}");
    // A run with no handshakes gives an empty list.
    let mut out = Vec::new();
    let mut report = Report::new(&mut out);
    report.json = true;
    let _ = report.finish();
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["diagnosis"], serde_json::json!([]));
}
