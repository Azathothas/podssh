//! The tests of the sessions readied ahead (T-650), on the pair's state and
//! the role's writers on pipes, with the times of each look given.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::frame::{self, Frame};
use podssh_ws::session::RelaySession;
use serde_json::{json, Value};
use tokio::io::DuplexStream;
use tokio::sync::oneshot;

use super::super::pairs::{NodeLink, Role};
use super::*;
use crate::reverse::control::{self, NodeInbound};

const HOUR: Duration = Duration::from_secs(3600);

/// A socket of the role on a pipe: its writer, and its peer's end.
fn socket(pairs: &Pairs) -> (Outbox, RelaySession<DuplexStream>) {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    let outbox = Outbox::start(Arc::new(podssh_ws::server::session(ours, Vec::new(), None)), pairs.writers.clone());
    (outbox, RelaySession::new(theirs, Vec::new(), None, Duration::from_secs(10)))
}

/// A pair whose node is joined on a pipe: the pairs, the pair, its name and
/// the node's end.
fn joined() -> (Pairs, Arc<Pair>, String, RelaySession<DuplexStream>) {
    let pairs = Pairs::default();
    let made = pairs.make(1_000).unwrap();
    let pair = pairs.find(&made.name, Role::Node, Some(&made.node), 2_000).unwrap();
    let (node, node_end) = socket(&pairs);
    pair.lock().node = Some(NodeLink { serial: 1, outbox: Some(node) });
    (pairs, pair, made.name, node_end)
}

/// The next frame that `peer` reads, within 10 s.
async fn frame_of(peer: &RelaySession<DuplexStream>) -> Frame {
    let read = tokio::time::timeout(Duration::from_secs(10), peer.read_frame()).await;
    read.expect("a frame in time").expect("a frame")
}

/// The next `n` text frames of `peer`, as JSON.
async fn texts(peer: &RelaySession<DuplexStream>, n: usize) -> Vec<Value> {
    let mut out = Vec::new();
    while out.len() < n {
        let f = frame_of(peer).await;
        assert_eq!(f.opcode, frame::OPCODE_TEXT, "{:?}", String::from_utf8_lossy(&f.payload));
        out.push(serde_json::from_slice(&f.payload).expect("JSON"));
    }
    out
}

fn id_of(frame: &Value) -> SessionId {
    SessionId::parse(frame["id"].as_str().expect("an id").as_bytes()).unwrap()
}

/// A session id of the test's: `n` in 32 hex digits.
fn numbered(n: usize) -> SessionId {
    SessionId::parse(format!("{n:032x}").as_bytes()).unwrap()
}

fn ask(want: u64) -> Value {
    json!({ "type": "spares", "want": want })
}

/// A leg of `operator` with the new id `id`: what `admit` found.
fn leg(pair: &Pair, operator: &Outbox, id: SessionId) -> Result<(SessionId, bool), &'static str> {
    let (told, _answered) = oneshot::channel();
    admit(pair, operator, id, told).map(|(id, _, spare)| (id, spare))
}

fn ready(pair: &Pair, id: &SessionId) {
    answered(&mut pair.lock(), id, "ready");
}

/// The role says that it keeps them in its `hello`, as an offer: `true`.
#[test]
fn the_roles_hello_offers_spares_beside_its_other_offers() {
    match control::parse_inbound(super::super::hello(true).as_bytes()).unwrap() {
        NodeInbound::Hello(hello) => assert!(crate::reverse::spares::offered(&hello), "{hello:?}"),
        other => panic!("{other:?}"),
    }
    match control::parse_inbound(super::super::hello(false).as_bytes()).unwrap() {
        NodeInbound::Hello(hello) => assert!(!crate::reverse::spares::offered(&hello), "a carrier's offers none"),
        other => panic!("{other:?}"),
    }
}

/// A node's number is a whole number, 16 at most; anything else closes its
/// socket as a fault of its bytes.
#[tokio::test]
async fn a_nodes_ask_is_a_whole_number_sixteen_at_most() {
    let (_pairs, pair, _name, _node_end) = joined();
    assert_eq!(asked(&pair, &json!({ "type": "spares" })), Err((1003, "invalid spares frame")));
    assert_eq!(asked(&pair, &json!({ "type": "spares", "want": "4" })), Err((1003, "invalid spares frame")));
    assert_eq!(asked(&pair, &ask(40)), Ok(16));
    assert_eq!(pair.lock().spares.len(), 16);
    assert_eq!(asked(&pair, &ask(0)), Ok(0));
    assert!(pair.lock().spares.is_empty(), "0 asks for none, and closes those kept");
}

/// A leg takes the youngest spare that the node readied, with no `open`, and
/// its operator hears `ready` first; never one still opening, which would
/// hand it a dead session: a leg that finds none opens one of its own.
#[tokio::test]
async fn a_leg_takes_the_youngest_readied_spare_and_never_one_still_opening() {
    let (pairs, pair, _name, node_end) = joined();
    let (operator, operator_end) = socket(&pairs);
    assert_eq!(asked(&pair, &ask(3)), Ok(3));
    let opens = texts(&node_end, 3).await;
    for open in &opens {
        assert_eq!((open["type"].as_str(), open["spare"].as_bool()), (Some("open"), Some(true)), "{open}");
    }
    let ids: Vec<SessionId> = opens.iter().map(id_of).collect();
    // The node readies two; the first is the older.
    {
        let mut state = pair.lock();
        let older = state.spares.each.get_mut(&ids[0]).unwrap();
        older.opened = older.opened.checked_sub(Duration::from_secs(5)).unwrap();
    }
    ready(&pair, &ids[0]);
    ready(&pair, &ids[1]);
    assert_eq!(leg(&pair, &operator, numbered(1)), Ok((ids[1], true)), "the youngest readied one");
    let heard = texts(&operator_end, 1).await;
    assert_eq!((heard[0]["type"].as_str(), id_of(&heard[0])), (Some("ready"), ids[1]));
    assert!(pair.lock().sessions.get(&ids[1]).is_some_and(|s| s.ready), "a session of its own, readied");
    assert_eq!(leg(&pair, &operator, numbered(2)), Ok((ids[0], true)));
    // The third is still opening: the leg goes the way of before.
    assert_eq!(leg(&pair, &operator, numbered(3)), Ok((numbered(3), false)));
    assert!(pair.lock().spares.holds(&ids[2]), "a spare still opening is left as it is");
}

/// The spares and the legs' sessions together stay inside the node's 64;
/// a leg that finds no room takes the place of a spare, never the reverse.
#[tokio::test]
async fn the_spares_stay_inside_the_nodes_sessions_and_give_a_leg_their_place() {
    let (pairs, pair, _name, node_end) = joined();
    let (operator, _operator_end) = socket(&pairs);
    for n in 0..MAX_SESSIONS - 2 {
        let session = Session { operator: operator.clone(), ready: true, answer: None, bytes: 0 };
        pair.lock().sessions.insert(numbered(1000 + n), session);
    }
    assert_eq!(asked(&pair, &ask(4)), Ok(4));
    assert_eq!(pair.lock().spares.len(), 2, "64 in all");
    for n in 0..2 {
        assert_eq!(leg(&pair, &operator, numbered(n)), Ok((numbered(n), false)));
        refill(&pair);
    }
    {
        let state = pair.lock();
        assert_eq!((state.sessions.len(), state.spares.len()), (MAX_SESSIONS, 0));
    }
    assert_eq!(leg(&pair, &operator, numbered(9)).err(), Some("node unavailable"));
    let told = texts(&node_end, 4).await;
    let kinds: Vec<&str> = told.iter().map(|t| t["type"].as_str().unwrap_or_default()).collect();
    assert_eq!(kinds, ["open", "open", "close", "close"], "{told:?}");
    assert_eq!(told[2]["reason"], YIELDS);
}

/// A tick with no take falls to the floor and closes those past it; each leg
/// that finds none asks for one more, up to the node's number; a tick with a
/// take keeps the number.
#[tokio::test]
async fn a_tick_with_no_take_falls_to_the_floor_and_each_miss_asks_for_one_more() {
    let (pairs, pair, _name, _node_end) = joined();
    let (operator, _operator_end) = socket(&pairs);
    let tick = Spacing { check: Duration::from_millis(1), tick: Duration::ZERO, age: HOUR };
    assert_eq!(asked(&pair, &ask(4)), Ok(4));
    keep(&pair, tick);
    {
        let state = pair.lock();
        assert_eq!((state.spares.level, state.spares.len()), (FLOOR, 1), "the floor");
    }
    for n in 0..2 {
        assert_eq!(leg(&pair, &operator, numbered(n)), Ok((numbered(n), false)), "the one left is still opening");
        refill(&pair);
    }
    {
        let state = pair.lock();
        assert_eq!((state.spares.level, state.spares.len()), (3, 3), "two misses, two more");
    }
    let one = *pair.lock().spares.each.keys().next().unwrap();
    ready(&pair, &one);
    assert_eq!(leg(&pair, &operator, numbered(5)), Ok((one, true)));
    refill(&pair);
    keep(&pair, tick);
    assert_eq!(pair.lock().spares.level, 3, "a tick with a take keeps the number");
    keep(&pair, tick);
    assert_eq!(pair.lock().spares.level, FLOOR, "the next one, with none, falls");
}

/// A spare that waited its age closes, its id in flight for a frame that
/// crosses the close, and another is drawn.
#[tokio::test]
async fn a_spare_that_waited_its_age_closes_and_another_is_drawn() {
    let (_pairs, pair, _name, node_end) = joined();
    assert_eq!(asked(&pair, &ask(1)), Ok(1));
    let first = id_of(&texts(&node_end, 1).await[0]);
    ready(&pair, &first);
    keep(&pair, Spacing { check: Duration::from_millis(1), tick: HOUR, age: Duration::ZERO });
    let told = texts(&node_end, 2).await;
    let closed = (told[0]["type"].as_str(), id_of(&told[0]), told[0]["reason"].as_str());
    assert_eq!(closed, (Some("close"), first, Some(AGED)));
    assert_eq!((told[1]["type"].as_str(), told[1]["spare"].as_bool()), (Some("open"), Some(true)));
    let mut state = pair.lock();
    assert!(!state.spares.holds(&first) && state.spares.holds(&id_of(&told[1])));
    assert_eq!(state.in_flight(&first), Some(true), "a ready that crossed the close is dropped");
}

/// A spare that the node refused stops the drawing until the next tick; one
/// that it closed is drawn again.
#[tokio::test]
async fn a_refused_spare_stops_the_drawing_until_the_tick_and_a_closed_one_is_drawn_again() {
    let (_pairs, pair, _name, node_end) = joined();
    assert_eq!(asked(&pair, &ask(2)), Ok(2));
    let ids: Vec<SessionId> = texts(&node_end, 2).await.iter().map(id_of).collect();
    answered(&mut pair.lock(), &ids[0], "reject");
    refill(&pair);
    assert_eq!(pair.lock().spares.len(), 1, "no spare drawn after a refusal");
    pair.lock().spares.taken = true;
    keep(&pair, Spacing { check: Duration::from_millis(1), tick: Duration::ZERO, age: HOUR });
    assert_eq!(pair.lock().spares.len(), 2, "the tick forgives it");
    answered(&mut pair.lock(), &ids[1], "close");
    assert_eq!(pair.lock().spares.len(), 1, "a spare that its target ended is not counted");
    refill(&pair);
    assert_eq!(pair.lock().spares.len(), 2, "and is drawn again");
}

/// The node's bytes on a spare wait for the leg that takes it, after its
/// `ready`; bytes before `ready` are the node's fault; past 64 KiB the spare
/// closes.
#[tokio::test]
async fn a_spares_bytes_wait_for_its_leg_and_too_many_close_it() {
    let (pairs, pair, _name, node_end) = joined();
    let (operator, operator_end) = socket(&pairs);
    let node = pair.lock().node_outbox().unwrap();
    assert_eq!(asked(&pair, &ask(2)), Ok(2));
    let ids: Vec<SessionId> = texts(&node_end, 2).await.iter().map(id_of).collect();
    assert_eq!(data(&mut pair.lock(), &node, &ids[0], b"x"), Err((1003, "data before ready")));
    ready(&pair, &ids[0]);
    ready(&pair, &ids[1]);
    assert_eq!(data(&mut pair.lock(), &node, &ids[0], b"SSH-2.0-banner\r\n"), Ok(()));
    let flood = vec![0u8; HELD + 1];
    assert_eq!(data(&mut pair.lock(), &node, &ids[1], &flood), Ok(()));
    assert!(!pair.lock().spares.holds(&ids[1]), "past 64 KiB it closed");
    assert_eq!(leg(&pair, &operator, numbered(1)), Ok((ids[0], true)));
    assert_eq!(id_of(&texts(&operator_end, 1).await[0]), ids[0], "ready first");
    let banner = frame_of(&operator_end).await;
    assert_eq!((banner.opcode, banner.payload.as_slice()), (frame::OPCODE_BINARY, &b"SSH-2.0-banner\r\n"[..]));
    let counted = pair.lock().sessions.get(&ids[0]).map(|s| s.bytes);
    assert_eq!(counted, Some(16), "the bytes held count against the session's cap");
}

/// A halt closes the spares, none is drawn while it holds, and a resume
/// draws them again.
#[tokio::test]
async fn a_halt_closes_the_spares_and_a_resume_draws_them_again() {
    let (pairs, pair, name, _node_end) = joined();
    assert_eq!(asked(&pair, &ask(2)), Ok(2));
    assert!(pairs.halt(&name, None, 5_000).is_some());
    assert!(pair.lock().spares.is_empty(), "closed with the halt");
    refill(&pair);
    assert!(pair.lock().spares.is_empty(), "none while it holds");
    assert_eq!(pairs.resume(&name), Some(true));
    assert_eq!(pair.lock().spares.len(), 2);
}
