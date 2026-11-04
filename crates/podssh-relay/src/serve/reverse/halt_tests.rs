//! The tests of a pair's halt (T-647), in a file of their own.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::frame::{self, Frame};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use tokio::io::DuplexStream;

use super::super::outbox::Outbox;
use super::super::pairs::{NodeLink, Role};
use super::*;
use crate::reverse::control::{self, NodeInbound};

#[test]
fn a_halts_body_is_nothing_or_a_short_reason() {
    assert_eq!(reason(b""), Ok(None));
    assert_eq!(reason(b" {} "), Ok(None));
    assert_eq!(reason(br#"{"reason": null}"#), Ok(None));
    assert_eq!(reason(br#"{"reason": "  "}"#), Ok(None), "blank words are none");
    assert_eq!(reason(br#"{"reason": " a new disk "}"#), Ok(Some("a new disk".into())));
    let longest = format!(r#"{{"reason": "{}"}}"#, "a".repeat(REASON_MAX));
    assert_eq!(reason(longest.as_bytes()), Ok(Some("a".repeat(REASON_MAX))));
    let longer = format!(r#"{{"reason": "{}"}}"#, "a".repeat(REASON_MAX + 1));
    for bad in [longer.as_bytes(), br#"{"reason": "two\nlines"}"#, br#"{"reason": 7}"#, b"[]", b"no json"] {
        assert!(reason(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn a_node_of_before_skips_halted_and_resumed() {
    let halt = Halt { since_ms: 5, why: Some("a new disk".into()) };
    for text in [halt.frame(), resumed()] {
        let read = control::parse_inbound(text.as_bytes()).expect("JSON that a node reads");
        assert!(matches!(read, NodeInbound::Unknown), "{text}: {read:?}");
    }
    let frame: Value = serde_json::from_str(&halt.frame()).unwrap();
    assert_eq!((frame["type"].as_str(), frame["reason"].as_str()), (Some("halted"), Some("a new disk")));
    assert_eq!(halt.refusal(), "reverse: the pair's owner halted it: a new disk");
    assert_eq!(Halt { since_ms: 5, why: None }.refusal(), "reverse: the pair's owner halted it");
}

#[test]
fn the_status_says_the_halt_beside_the_contracts_fields() {
    let mut body = json!({ "online": true, "sessions": 0 });
    status(&mut body, None);
    assert_eq!(body, json!({ "online": true, "sessions": 0, "halted": false }));
    status(&mut body, Some(&Halt { since_ms: 9, why: Some("why".into()) }));
    let said = (&body["halted"], &body["halted_since"], &body["halt_reason"]);
    assert_eq!(said, (&json!(true), &json!(9), &json!("why")));
}

/// A socket of the role on a pipe: its writer, and its peer's end.
fn socket(pairs: &Pairs) -> (Outbox, RelaySession<DuplexStream>) {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let outbox = Outbox::start(Arc::new(podssh_ws::server::session(ours, Vec::new(), None)), pairs.writers.clone());
    (outbox, RelaySession::new(theirs, Vec::new(), None, Duration::from_secs(10)))
}

/// The next frame that `peer` reads, within 10 s.
async fn frame_of(peer: &RelaySession<DuplexStream>) -> Frame {
    let read = tokio::time::timeout(Duration::from_secs(10), peer.read_frame()).await;
    read.expect("a frame in time").expect("a frame")
}

/// A halt closes each session once and keeps the node; its ids stay in
/// flight, so that a frame of the node that crosses it is dropped, not a
/// fault of the node's (T-421); a second halt changes nothing; a resume
/// says so once; a pair that ended is neither halted nor resumed.
#[tokio::test]
async fn a_halt_is_idempotent_and_its_ids_stay_in_flight() {
    let pairs = Pairs::default();
    let made = pairs.make(1_000).unwrap();
    let pair = pairs.find(&made.name, Role::Node, Some(&made.node), 2_000).unwrap();
    let ((node, node_end), (operator, operator_end)) = (socket(&pairs), socket(&pairs));
    pair.lock().node = Some(NodeLink { serial: 1, outbox: Some(node) });
    let id = SessionId::parse(b"0123456789abcdef0123456789abcdef").unwrap();
    pair.lock().sessions.insert(id, Session { operator, ready: true, answer: None, bytes: 0 });

    let first = pairs.halt(&made.name, Some("a new disk".into()), 5_000).expect("a halt");
    assert_eq!((first.sessions, first.already, first.halt.since_ms), (1, false, 5_000));
    assert!(pair.lock().sessions.is_empty(), "each session ended");
    assert!(pair.lock().node.is_some(), "the node keeps its socket");
    assert_eq!(pair.lock().in_flight(&id), Some(true), "a frame that crosses the halt is dropped");
    let again = pairs.halt(&made.name, None, 9_000).expect("a second halt");
    assert_eq!((again.sessions, again.already, &again.halt), (0, true, &first.halt), "a second halt changes nothing");

    let closed = frame_of(&operator_end).await;
    assert_eq!(closed.opcode, frame::OPCODE_CLOSE);
    assert_eq!(close_code_and_reason(&closed.payload), (Some(CODE), HALTED.to_string()));
    let mut told: Vec<Value> = Vec::new();
    for _ in 0..2 {
        told.push(serde_json::from_slice(&frame_of(&node_end).await.payload).expect("a text frame of JSON"));
    }
    // `halted` goes before what waits, a session's `close` after its bytes.
    let mut seen: Vec<&str> = told.iter().map(|v| v["type"].as_str().unwrap_or_default()).collect();
    seen.sort_unstable();
    assert_eq!(seen, ["close", "halted"], "{told:?}");
    let close = told.iter().find(|v| v["type"] == "close").unwrap();
    assert_eq!((close["id"].as_str(), close["reason"].as_str()), (Some(id.as_str()), Some(HALTED)));

    assert_eq!(pairs.resume(&made.name), Some(true));
    assert!(pair.halted().is_none());
    assert_eq!(pairs.resume(&made.name), Some(false), "a pair that is not halted");
    let resumed: Value = serde_json::from_slice(&frame_of(&node_end).await.payload).unwrap();
    assert_eq!(resumed["type"], "resumed", "once");
    pairs.end(&made.name, 1001, "operator stopped reverse relay");
    assert_eq!(pairs.halt(&made.name, None, 10_000), None, "a pair that ended");
    assert_eq!(pairs.resume(&made.name), None);
    assert_eq!(pairs.halt("p-other", None, 10_000), None, "no such pair");
}
