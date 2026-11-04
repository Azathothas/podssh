//! The role's mailbox table of T-086, command by command, as
//! magic-wormhole-mailbox-server's `server_websocket.py` answers them: the
//! bind of podssh's AppID alone, a nameplate allocated and claimed, the
//! messages of a mailbox to each of its sides, a third side refused, and a
//! nameplate and a mailbox gone once each side let them go.

use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::*;

/// A client of `table`, bound as `side`, and what it hears outside its
/// answers.
fn client(table: &Table, side: &str) -> (Conn, mpsc::Receiver<String>) {
    let (outbox, heard) = mpsc::channel(OUTBOX);
    let mut conn = table.connection(outbox);
    let answers = table.handle(&mut conn, &json!({ "type": "bind", "appid": APPID, "side": side, "id": "0001" }));
    assert_eq!(answers, vec![json!({ "type": "ack", "id": "0001" })], "a bind has its ack alone");
    (conn, heard)
}

/// The answer after the ack of `command`.
fn answer(table: &Table, conn: &mut Conn, command: Value) -> Value {
    let answers = table.handle(conn, &command);
    assert_eq!(answers[0]["type"], "ack", "{answers:?}");
    answers.get(1).cloned().unwrap_or(Value::Null)
}

fn heard(from: &mut mpsc::Receiver<String>) -> Vec<Value> {
    let mut all = Vec::new();
    while let Ok(text) = from.try_recv() {
        all.push(serde_json::from_str(&text).unwrap());
    }
    all
}

#[test]
fn another_appid_and_each_command_before_a_bind_are_refused() {
    let table = Table::default();
    let (outbox, _heard) = mpsc::channel(OUTBOX);
    let mut conn = table.connection(outbox);
    let refused = answer(&table, &mut conn, json!({ "type": "allocate" }));
    assert_eq!((refused["type"].as_str(), refused["error"].as_str()), (Some("error"), Some("must bind first")));
    assert_eq!(refused["orig"]["type"], "allocate");
    let other = json!({ "type": "bind", "appid": "lothar.com/wormhole/text-or-file-xfer", "side": "abc" });
    assert!(answer(&table, &mut conn, other)["error"].as_str().unwrap().contains("alone"));
    let bad_side = json!({ "type": "bind", "appid": APPID, "side": "a b" });
    assert!(answer(&table, &mut conn, bad_side)["error"].as_str().unwrap().contains("letters and digits"));
    assert_eq!(answer(&table, &mut conn, json!({ "type": "ping", "ping": 7 })), json!({ "type": "pong", "pong": 7 }));
    assert_eq!(answer(&table, &mut conn, json!({ "type": "nope" }))["error"], "must bind first");
}

#[test]
fn two_sides_meet_at_a_nameplate_and_each_hears_each_message() {
    let table = Table::default();
    let (mut giver, mut giver_heard) = client(&table, "aaaa");
    let allocated = answer(&table, &mut giver, json!({ "type": "allocate" }));
    let nameplate = allocated["nameplate"].as_str().unwrap().to_string();
    assert_eq!(nameplate, "1", "the shortest free nameplate");
    let listed = answer(&table, &mut giver, json!({ "type": "list" }));
    assert_eq!(listed["nameplates"], json!([{ "id": "1" }]));
    let id = answer(&table, &mut giver, json!({ "type": "claim", "nameplate": nameplate }))["mailbox"].clone();
    let id = id.as_str().unwrap().to_string();
    assert_eq!(id.len(), 32, "16 random bytes");
    let answers = table.handle(&mut giver, &json!({ "type": "open", "mailbox": id }));
    assert_eq!(answers.len(), 1, "an empty mailbox: the ack alone");
    table.handle(&mut giver, &json!({ "type": "add", "phase": "pake", "body": "53ab", "id": "0005" }));
    let echo = heard(&mut giver_heard);
    assert_eq!((echo.len(), echo[0]["side"].as_str(), echo[0]["phase"].as_str()), (1, Some("aaaa"), Some("pake")));

    let (mut taker, mut taker_heard) = client(&table, "bbbb");
    let claimed = answer(&table, &mut taker, json!({ "type": "claim", "nameplate": nameplate }));
    assert_eq!(claimed["mailbox"].as_str(), Some(id.as_str()));
    let answers = table.handle(&mut taker, &json!({ "type": "open", "mailbox": id }));
    assert_eq!(answers.len(), 2, "the ack, then the message kept");
    assert_eq!((answers[1]["type"].as_str(), answers[1]["body"].as_str()), (Some("message"), Some("53ab")));
    assert_eq!(answers[1]["id"], "0005");
    table.handle(&mut taker, &json!({ "type": "add", "phase": "pake", "body": "53cd" }));
    assert_eq!(heard(&mut giver_heard)[0]["body"], "53cd");
    assert_eq!(heard(&mut taker_heard)[0]["side"], "bbbb", "the sender hears its own");

    for conn in [&mut giver, &mut taker] {
        assert_eq!(answer(&table, conn, json!({ "type": "release" }))["type"], "released");
    }
    assert_eq!(answer(&table, &mut giver, json!({ "type": "list" }))["nameplates"], json!([]));
    for conn in [&mut giver, &mut taker] {
        assert_eq!(answer(&table, conn, json!({ "type": "close", "mood": "happy" }))["type"], "closed");
    }
    let (mut late, _) = client(&table, "cccc");
    let gone = answer(&table, &mut late, json!({ "type": "open", "mailbox": id }));
    assert_eq!(gone["error"], "no such mailbox", "a mailbox that each side closed is gone");
}

#[test]
fn a_third_side_of_a_code_is_refused_while_two_hold_it() {
    let table = Table::default();
    let (mut one, _a) = client(&table, "aaaa");
    let nameplate = answer(&table, &mut one, json!({ "type": "allocate" }))["nameplate"].clone();
    let (mut two, _b) = client(&table, "bbbb");
    let id = answer(&table, &mut two, json!({ "type": "claim", "nameplate": nameplate }))["mailbox"].clone();
    assert!(id.is_string());
    let (mut three, _c) = client(&table, "cccc");
    let crowded = answer(&table, &mut three, json!({ "type": "claim", "nameplate": nameplate }));
    assert_eq!(crowded["error"], "crowded");
    let (mut four, _d) = client(&table, "dddd");
    assert_eq!(answer(&table, &mut four, json!({ "type": "open", "mailbox": id }))["error"], "crowded");
}

#[test]
fn a_side_that_released_a_nameplate_cannot_claim_it_again() {
    let table = Table::default();
    let (mut one, _a) = client(&table, "aaaa");
    let nameplate = answer(&table, &mut one, json!({ "type": "allocate" }))["nameplate"].clone();
    let (mut two, _b) = client(&table, "bbbb");
    answer(&table, &mut two, json!({ "type": "claim", "nameplate": nameplate }));
    answer(&table, &mut one, json!({ "type": "release", "nameplate": nameplate }));
    let (mut again, _c) = client(&table, "aaaa");
    assert_eq!(answer(&table, &mut again, json!({ "type": "claim", "nameplate": nameplate }))["error"], "reclaimed");
}

#[test]
fn each_command_once_and_each_body_bounded() {
    let table = Table::default();
    let (mut conn, _heard) = client(&table, "aaaa");
    answer(&table, &mut conn, json!({ "type": "allocate" }));
    assert!(answer(&table, &mut conn, json!({ "type": "allocate" }))["error"].as_str().unwrap().contains("greedy"));
    let early = answer(&table, &mut conn, json!({ "type": "add", "phase": "0", "body": "00" }));
    assert!(early["error"].as_str().unwrap().contains("must open"), "{early}");
    let id = answer(&table, &mut conn, json!({ "type": "claim", "nameplate": "1" }))["mailbox"].clone();
    table.handle(&mut conn, &json!({ "type": "open", "mailbox": id }));
    let long = "00".repeat(BODY_MOST);
    for body in ["0", "zz", long.as_str()] {
        let refused = answer(&table, &mut conn, json!({ "type": "add", "phase": "0", "body": body }));
        assert!(refused["error"].as_str().unwrap().contains("a body is hex"), "{refused}");
    }
    for n in 0..MESSAGES {
        let added = table.handle(&mut conn, &json!({ "type": "add", "phase": n.to_string(), "body": "00" }));
        assert_eq!(added.len(), 1, "message {n}: the ack alone");
    }
    let full = answer(&table, &mut conn, json!({ "type": "add", "phase": "x", "body": "00" }));
    assert!(full["error"].as_str().unwrap().contains("messages at most"), "{full}");
    let again = answer(&table, &mut conn, json!({ "type": "claim", "nameplate": "2" }));
    assert_eq!(again["error"], "only one claim per connection");
}
