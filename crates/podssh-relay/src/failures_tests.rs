use std::time::Duration;

use podssh_ws::dial::DialError;
use podssh_ws::ConnectError;

use super::*;

const NOW: i64 = 1_760_000_000_000;

fn relays(names: &[&str]) -> Vec<Relay> {
    names.iter().map(|n| Relay { host: n.to_string(), port: 443 }).collect()
}

fn failed_at(host: &str, at_ms: i64, reason: &str) -> Records {
    let mut records = Records::default();
    records.hosts.insert(host.into(), Record { at_ms, reason: reason.into() });
    records
}

#[test]
fn a_host_that_failed_lately_is_tried_last_and_says_so() {
    let hosts = relays(&["a", "b", "c"]);
    let records = failed_at("a", NOW - 30_000, "no answer within 45 s");
    let (tried, notes) = order(&hosts, &records, NOW);
    assert_eq!(tried, [1, 2, 0]);
    assert_eq!(notes, ["trying a last: it failed 30 s ago (no answer within 45 s)"]);
    // Two hosts moved keep their order, at the end.
    let mut records = records;
    records.hosts.insert("b".into(), Record { at_ms: NOW - 1000, reason: "TLS failed".into() });
    assert_eq!(order(&hosts, &records, NOW).0, [2, 0, 1]);
    // Each host failed: the list as it was.
    records.hosts.insert("c".into(), Record { at_ms: NOW, reason: "x".into() });
    assert_eq!(order(&hosts, &records, NOW).0, [0, 1, 2]);
    // One host is never moved: it is tried, with no note.
    let (tried, notes) = order(&relays(&["a"]), &records, NOW);
    assert_eq!((tried, notes.len()), (vec![0], 0));
}

#[test]
fn a_record_holds_for_its_window_and_not_from_the_future() {
    let window = WINDOW.as_millis() as i64;
    assert!(failed_at("a", NOW - window + 1, "x").fresh("a", NOW).is_some());
    assert!(failed_at("a", NOW - window, "x").fresh("a", NOW).is_none());
    assert!(failed_at("a", NOW + 1, "x").fresh("a", NOW).is_none(), "a clock that moved");
    let hosts = relays(&["a", "b"]);
    assert_eq!(order(&hosts, &failed_at("a", NOW + 60_000, "x"), NOW).0, [0, 1]);
}

#[test]
fn a_round_records_its_failures_and_clears_the_host_that_opened() {
    let mut records = failed_at("old", NOW - WINDOW.as_millis() as i64 - 1, "x");
    records.hosts.insert("b".into(), Record { at_ms: NOW - 5000, reason: "TLS failed".into() });
    let failed = [("a".to_string(), "no connection".to_string())];
    assert!(records.update(&failed, Some("b"), NOW));
    assert_eq!(records.hosts.keys().collect::<Vec<_>>(), ["a"], "old dropped, b cleared");
    assert_eq!(records.hosts["a"], Record { at_ms: NOW, reason: "no connection".into() });
    assert!(!records.update(&[], Some("c"), NOW), "nothing changed, nothing written");
}

#[test]
fn only_a_hosts_own_failure_is_recorded() {
    let connect = |error| OpenError::Connect { error, origin: crate::token::Origin::Minted };
    let refused = |status, body: &str| connect(ConnectError::Refused { status, body: body.into() });
    assert_eq!(reason(&OpenError::Deadline).as_deref(), Some("no answer within 45 s"));
    assert_eq!(reason(&refused(503, "busy")).as_deref(), Some("it answered 503"));
    let timeout = connect(ConnectError::Timeout { step: "TLS handshake", after: Duration::from_secs(20) });
    assert_eq!(reason(&timeout).as_deref(), Some("TLS handshake timed out after 20 s"));
    assert_eq!(reason(&connect(ConnectError::Tls("bad".into()))).as_deref(), Some("TLS failed"));
    // The relay could not reach the target, a policy, a token that each
    // host refuses, a proxy that wants credentials: not the host's.
    for e in [
        refused(502, "connect refused"),
        refused(403, "not in the ALLOW list"),
        refused(401, "missing or wrong token"),
        connect(ConnectError::Dial(DialError::ProxyRefused {
            proxy: "p".into(),
            target: "t".into(),
            status: 407,
            reason: String::new(),
        })),
        OpenError::Offline,
    ] {
        assert_eq!(reason(&e), None, "{e:?}");
    }
}

#[test]
fn the_record_is_a_private_file_of_the_cache() {
    let dir = std::env::temp_dir().join(format!("podssh-failures-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let dirs = vec![dir.clone()];
    assert_eq!(Records::load_from(&dirs), Records::default());
    let records = failed_at("a", NOW, "no connection");
    records.store_in(&dirs);
    assert_eq!(Records::load_from(&dirs), records);
    let text = std::fs::read_to_string(dir.join(FILE)).unwrap();
    assert!(text.contains("\"reason\":\"no connection\""), "{text}");
    std::fs::write(dir.join(FILE), "not json").unwrap();
    assert_eq!(Records::load_from(&dirs), Records::default(), "a record that does not read is none");
    let _ = std::fs::remove_dir_all(&dir);
}
