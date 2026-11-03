use std::collections::BTreeMap;
use std::time::Duration;

use podssh_ws::dial::DialError;
use podssh_ws::ConnectError;

use super::*;

const NOW: i64 = 1_760_000_000_000;
const WS: &str = WEBSOCKET;

fn relays(names: &[&str]) -> Vec<Relay> {
    names.iter().map(|n| Relay { host: n.to_string(), port: 443 }).collect()
}

fn failed_at(host: &str, at_ms: i64, reason: &str) -> Records {
    let mut records = Records::default();
    records.hosts.insert(host.into(), Record { at_ms, reason: reason.into(), ..Record::default() });
    records
}

#[test]
fn a_host_that_failed_lately_is_tried_last_and_says_so() {
    let hosts = relays(&["a", "b", "c"]);
    let records = failed_at("a", NOW - 30_000, "no answer within 45 s");
    let (tried, notes) = order(WS, &hosts, &records, NOW);
    assert_eq!(tried, [1, 2, 0]);
    assert_eq!(notes, ["trying a last: it failed 30 s ago (no answer within 45 s)"]);
    // Two hosts moved keep their order, at the end.
    let mut records = records;
    records.hosts.insert("b".into(), Record { at_ms: NOW - 1000, reason: "TLS failed".into(), ..Record::default() });
    assert_eq!(order(WS, &hosts, &records, NOW).0, [2, 0, 1]);
    // Each host failed: the list as it was.
    records.hosts.insert("c".into(), Record { at_ms: NOW, reason: "x".into(), ..Record::default() });
    assert_eq!(order(WS, &hosts, &records, NOW).0, [0, 1, 2]);
    // One host is never moved: it is tried, with no note.
    let (tried, notes) = order(WS, &relays(&["a"]), &records, NOW);
    assert_eq!((tried, notes.len()), (vec![0], 0));
}

#[test]
fn a_record_holds_for_its_window_and_not_from_the_future() {
    let window = WINDOW.as_millis() as i64;
    assert!(failed_at("a", NOW - window + 1, "x").fresh(WS, "a", NOW).is_some());
    assert!(failed_at("a", NOW - window, "x").fresh(WS, "a", NOW).is_none());
    assert!(failed_at("a", NOW + 1, "x").fresh(WS, "a", NOW).is_none(), "a clock that moved");
    let hosts = relays(&["a", "b"]);
    assert_eq!(order(WS, &hosts, &failed_at("a", NOW + 60_000, "x"), NOW).0, [0, 1]);
}

/// A round records its failures, keeps the host that opened with its open
/// and no failure (T-563: before, the open removed it), and drops a stale
/// entry; a round of nothing writes nothing.
#[test]
fn a_round_records_its_failures_and_keeps_the_host_that_opened() {
    let mut records = failed_at("old", NOW - WINDOW.as_millis() as i64 - 1, "x");
    records.hosts.insert("b".into(), Record { at_ms: NOW - 5000, reason: "TLS failed".into(), ..Record::default() });
    let failed = [("a".to_string(), "no connection".to_string())];
    assert!(records.update(WS, &failed, Some("b"), NOW));
    assert_eq!(records.hosts.keys().collect::<Vec<_>>(), ["a", "b"], "old dropped, b kept");
    assert_eq!(records.hosts["a"], Record { at_ms: NOW, reason: "no connection".into(), ..Record::default() });
    let b = &records.hosts["b"];
    assert_eq!((b.at_ms, b.reason.as_str(), b.opened_ms, b.opens), (0, "", NOW, 1), "its failure cleared");
    assert!(records.update(WS, &[], Some("b"), NOW + 1000));
    assert_eq!(records.hosts["b"].opens, 2);
    assert!(!records.update(WS, &[], None, NOW + 1000), "nothing changed, nothing written");
}

/// A host that opened lately goes before one that merely did not fail, and
/// says nothing of it; a host that opened and failed since does not.
#[test]
fn a_host_that_opened_lately_is_tried_first() {
    let hosts = relays(&["a", "b", "c"]);
    let mut records = Records::default();
    assert!(records.update(WS, &[], Some("b"), NOW - 4000));
    let (tried, notes) = order(WS, &hosts, &records, NOW);
    assert_eq!((tried, notes.len()), (vec![1, 0, 2], 0));
    // Two that opened keep the list's order between them.
    records.update(WS, &[], Some("c"), NOW - 2000);
    assert_eq!(order(WS, &hosts, &records, NOW).0, [1, 2, 0]);
    // One that failed after its open goes last.
    records.update(WS, &[("b".into(), "TLS failed".into())], Some("c"), NOW - 1000);
    assert_eq!(order(WS, &hosts, &records, NOW).0, [2, 0, 1]);
    // An open older than the window puts it first no more, and its entry goes.
    let later = NOW + WINDOW.as_millis() as i64;
    assert_eq!(order(WS, &hosts, &records, later).0, [0, 1, 2]);
    assert!(records.update(WS, &[], None, later));
    assert!(records.hosts.is_empty(), "{records:?}");
}

/// Two sessions in a row cut on the host's side within SHORT of their open
/// rest the host for REST, with a note; a session that held, or that the
/// client ended, breaks the row; a cut that came late is no strike.
#[test]
fn two_short_sessions_in_a_row_rest_the_host() {
    let hosts = relays(&["a", "b"]);
    let (short, held) = (Duration::from_secs(5), SHORT + Duration::from_secs(1));
    let mut records = Records::default();
    records.update(WS, &[], Some("a"), NOW - 60_000);
    assert!(records.end(WS, "a", short, true, NOW - 55_000));
    assert_eq!(records.hosts["a"].strikes, 1);
    // One strike: not first any more, and not last yet.
    assert_eq!(order(WS, &hosts, &records, NOW).0, [0, 1]);
    records.update(WS, &[], Some("b"), NOW - 50_000);
    assert_eq!(order(WS, &hosts, &records, NOW).0, [1, 0], "b worked, a was cut");
    records.update(WS, &[], Some("a"), NOW - 40_000);
    assert!(records.end(WS, "a", short, true, NOW - 35_000));
    let (tried, notes) = order(WS, &hosts, &records, NOW);
    assert_eq!(tried, [1, 0]);
    assert_eq!(notes, ["trying a last: its last 2 sessions were cut within 300 s of their open, the last 35 s ago"]);
    let rest_over = NOW - 35_000 + REST.as_millis() as i64;
    assert!(!records.hosts["a"].resting(rest_over) && records.hosts["a"].resting(rest_over - 1));
    // A session that held, then one that the client ended: each breaks it.
    let mut held_once = records.clone();
    assert!(held_once.end(WS, "a", held, true, NOW));
    assert_eq!(held_once.hosts["a"].strikes, 0);
    assert!(records.end(WS, "a", short, false, NOW));
    assert_eq!((records.hosts["a"].strikes, records.hosts["a"].struck_ms), (0, 0));
    // The end of a host with no entry that is no strike writes nothing.
    assert!(!records.end(WS, "z", short, false, NOW));
    assert!(records.end(WS, "z", short, true, NOW), "a strike is kept");
}

/// One road's verdict stays on that road: a failure on the iroh road leaves
/// the WebSocket road's order alone, and is kept apart in the file.
#[test]
fn a_failure_on_one_road_leaves_the_other_road_s_order_alone() {
    let hosts = relays(&["a", "b"]);
    let mut records = Records::default();
    assert!(records.update("iroh", &[("a".into(), "no connection".into())], None, NOW - 1000));
    assert_eq!(order(WS, &hosts, &records, NOW), (vec![0, 1], vec![]));
    assert_eq!(order("iroh", &hosts, &records, NOW).0, [1, 0]);
    assert!(records.hosts.is_empty() && records.roads["iroh"].contains_key("a"));
    assert!(records.end("iroh", "b", Duration::from_secs(1), true, NOW));
    assert!(records.get(WS, "b").is_none(), "an end on one road is that road's");
    // A road whose entries all went leaves no trace.
    assert!(records.update(WS, &[], None, NOW + 2 * WINDOW.as_millis() as i64));
    assert!(records.roads.is_empty(), "{records:?}");
}

/// What `status` and `doctor` show: "failed 30 s ago" beside "opened 4 s
/// ago", the WebSocket road first; a rest says its strikes.
#[test]
fn the_recent_entries_say_both_what_failed_and_what_opened() {
    let mut records = failed_at("a", NOW - 30_000, "no connection");
    records.update(WS, &[], Some("b"), NOW - 4000);
    records.update("iroh", &[], Some("a"), NOW - 1000);
    records.end("iroh", "a", Duration::from_secs(1), true, NOW - 900);
    records.end("iroh", "a", Duration::from_secs(1), true, NOW - 800);
    let seen = recent(&records, NOW);
    let shown: Vec<_> = seen.iter().map(|s| (s.road.as_str(), s.host.as_str(), s.last.clone(), s.opened)).collect();
    let rest = "its last 2 sessions were cut within 300 s of their open".to_string();
    assert_eq!(
        shown,
        [
            (WS, "a", Some((30, "no connection".to_string())), None),
            (WS, "b", None, Some((4, 1))),
            ("iroh", "a", Some((0, rest)), Some((1, 1))),
        ]
    );
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
    assert!(!text.contains("\"roads\""), "no road but the WebSocket's, no roads: {text}");
    std::fs::write(dir.join(FILE), "not json").unwrap();
    assert_eq!(Records::load_from(&dirs), Records::default(), "a record that does not read is none");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The record of a podssh before T-563, as it wrote it.
#[derive(Debug, serde::Deserialize)]
struct OldRecords {
    hosts: BTreeMap<String, OldRecord>,
}

#[derive(Debug, serde::Deserialize)]
struct OldRecord {
    at_ms: i64,
    #[allow(dead_code)]
    reason: String,
}

/// One cache file for an older podssh and this one: the older file reads,
/// each new field at its default; and the older podssh reads this one, a host
/// that opened as a failure long ago, which it drops.
#[test]
fn an_older_file_reads_and_an_older_podssh_reads_this_one() {
    let old = format!(r#"{{"hosts":{{"a":{{"at_ms":{},"reason":"TLS failed"}}}}}}"#, NOW - 30_000);
    let records: Records = serde_json::from_str(&old).expect("an older file reads");
    assert_eq!(records, failed_at("a", NOW - 30_000, "TLS failed"));
    assert_eq!(order(WS, &relays(&["a", "b"]), &records, NOW).0, [1, 0]);
    let mut records = records;
    records.update(WS, &[], Some("a"), NOW);
    records.update("iroh", &[("b".into(), "no connection".into())], None, NOW);
    let text = serde_json::to_string(&records).unwrap();
    let read: OldRecords = serde_json::from_str(&text).expect("an older podssh reads this file");
    assert_eq!(read.hosts["a"].at_ms, 0, "{text}");
    assert_eq!(read.hosts.len(), 1, "the other roads are not the older podssh's: {text}");
}
