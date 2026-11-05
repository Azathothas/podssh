//! Sessions readied ahead for a node that asks (T-650, GitHub #148), against
//! podssh's relay role on the loopback: a node of the test's own script asks,
//! readies a spare or leaves it, and reads what the role sends it, as a
//! client of the contract that podssh did not shape; then podssh's own node
//! and operator carry their bytes through the spares whole. Each look at the
//! spares is 50 ms here, and each test gives its own tick and age.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::pair::Pair;
use podssh_relay::reverse::{self, operator, Exit, Handler, NodeConfig, Opening, OperatorConfig, OperatorLimits};
use podssh_relay::reverse::{Outcome, SessionId, Settings, Wire};
use podssh_relay::serve::reverse::spares::Spacing;
use podssh_relay::serve::reverse::{Pairs, MAX_SESSIONS};
use podssh_relay::serve::Mint;
use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE, OPCODE_TEXT};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use podssh_ws::{ProxyChoice, Trust};
use role_harness::{closed, next, next_text, Role, LIMIT};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

/// A tick or an age that no test reaches.
const LONG: Duration = Duration::from_secs(3600);

/// A role whose nodes' spares are looked at each 50 ms, with `tick` and `age`.
async fn role_with(tick: Duration, age: Duration) -> Role {
    let spacing = Spacing { check: Duration::from_millis(50), tick, age };
    Role::with_pairs(Mint::Anyone, Pairs::default().with_spacing(spacing)).await
}

/// A node of the test's own script on its pair's socket.
struct Node(RelaySession<TcpStream>);

impl Node {
    /// Joined, its `hello` read: one that offers spares.
    async fn join(role: &Role, pair: &Pair) -> Node {
        let path = format!("/v1/node/{}", pair.name);
        let node = Node(role.socket(&path, pair.node_token()).await.expect("the node's socket"));
        let hello = node.text().await;
        assert_eq!((hello["type"].as_str(), hello["spares"].as_bool()), (Some("hello"), Some(true)), "{hello}");
        node
    }

    async fn send(&self, frame: Value) {
        self.0.send_text(&frame.to_string()).await.expect("a frame to the role");
    }

    async fn ask(&self, want: u64) {
        self.send(json!({ "type": "spares", "want": want })).await;
    }

    async fn ready(&self, id: &str) {
        self.send(json!({ "type": "ready", "id": id })).await;
    }

    async fn data(&self, id: &str, payload: &[u8]) {
        let mut frame = id.as_bytes().to_vec();
        frame.extend_from_slice(payload);
        self.0.send_binary(&frame).await.expect("data to the role");
    }

    /// The next text or binary frame within `wait`; `None` when none came.
    async fn within(&self, wait: Duration) -> Option<(u8, Vec<u8>)> {
        let until = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(until, self.0.read_frame()).await {
                Ok(Ok(f)) if f.opcode == OPCODE_TEXT || f.opcode == OPCODE_BINARY => {
                    return Some((f.opcode, f.payload))
                }
                Ok(Ok(f)) if f.opcode == OPCODE_CLOSE => {
                    panic!("the role closed the node: {:?}", close_code_and_reason(&f.payload))
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => panic!("the node's socket: {e:?}"),
                Err(_) => return None,
            }
        }
    }

    async fn text(&self) -> Value {
        match self.within(LIMIT).await {
            Some((OPCODE_TEXT, payload)) => serde_json::from_slice(&payload).expect("JSON"),
            other => panic!("not a text frame: {other:?}"),
        }
    }

    /// Ask again, and wait for the role's line of it: each frame that the
    /// node sent before it was taken, as the role reads them in order.
    async fn settle(&self, role: &Role, want: u64) {
        let said = format!("reverse spares {want}");
        let count = || role.events.lock().unwrap().iter().filter(|line| **line == said).count();
        let before = count();
        self.ask(want).await;
        let until = Instant::now() + LIMIT;
        while count() <= before {
            assert!(Instant::now() < until, "the role never took the ask");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// An operator's leg on the pair, as a client of the contract opens one.
async fn leg(role: &Role, pair: &Pair) -> RelaySession<TcpStream> {
    let path = format!("/v1/connect/{}", pair.name);
    role.socket(&path, pair.connect_token()).await.expect("an operator's leg")
}

fn id_of(frame: &Value) -> String {
    frame["id"].as_str().expect("an id").to_string()
}

/// A node frame as the role carries it: the session's id, then its payload.
fn framed(id: &str, payload: &[u8]) -> Vec<u8> {
    let mut frame = id.as_bytes().to_vec();
    frame.extend_from_slice(payload);
    frame
}

/// With one spare readied, an operator's leg hears `ready` at once, then the
/// target's banner that waited for it, and its first byte reaches the node on
/// the spare's id, with no `open` for the leg: each open that the node sees
/// is a spare's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leg_takes_a_readied_spare_and_its_first_byte_reaches_the_node_with_no_open() {
    let role = role_with(LONG, LONG).await;
    let pair = role.pair();
    let node = Node::join(&role, &pair).await;
    node.ask(1).await;
    let open = node.text().await;
    assert_eq!((open["type"].as_str(), open["spare"].as_bool()), (Some("open"), Some(true)), "{open}");
    let spare = id_of(&open);
    node.ready(&spare).await;
    node.data(&spare, b"SSH-2.0-target\r\n").await;
    node.settle(&role, 1).await;

    let leg = leg(&role, &pair).await;
    let ready = next_text(&leg).await;
    assert_eq!((ready["type"].as_str(), id_of(&ready)), (Some("ready"), spare.clone()), "{ready}");
    assert_eq!(next(&leg).await, Some((OPCODE_BINARY, b"SSH-2.0-target\r\n".to_vec())), "the banner waited for it");
    leg.send_binary(b"SSH-2.0-client\r\n").await.unwrap();
    loop {
        match node.within(LIMIT).await.expect("the leg's byte") {
            (OPCODE_TEXT, payload) => {
                let told: Value = serde_json::from_slice(&payload).unwrap();
                assert_eq!((told["type"].as_str(), told["spare"].as_bool()), (Some("open"), Some(true)), "{told}");
                assert_ne!(id_of(&told), spare, "the spare's replacement");
            }
            (_, payload) => {
                assert_eq!(payload, framed(&spare, b"SSH-2.0-client\r\n"), "on the spare's id");
                break;
            }
        }
    }
    assert!(role.said("reverse spare taken"), "{:?}", role.events.lock().unwrap());
    assert!(!role.said("reverse open"), "an open for the leg: {:?}", role.events.lock().unwrap());
}

/// A node whose answer to `hello` has no word gets no spare, through a few
/// looks and ticks, and its leg goes the way of before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_that_does_not_ask_gets_no_spare_and_its_leg_goes_as_before() {
    let role = role_with(Duration::from_millis(200), Duration::from_millis(200)).await;
    let pair = role.pair();
    let node = Node::join(&role, &pair).await;
    assert_eq!(node.within(Duration::from_millis(700)).await, None, "no spare for a node that did not ask");
    let leg = leg(&role, &pair).await;
    let open = node.text().await;
    assert_eq!((open["type"].as_str(), open.get("spare")), (Some("open"), None), "{open}");
    node.ready(&id_of(&open)).await;
    assert_eq!(id_of(&next_text(&leg).await), id_of(&open));
    leg.send_binary(b"ping").await.unwrap();
    assert_eq!(node.within(LIMIT).await, Some((OPCODE_BINARY, framed(&id_of(&open), b"ping"))));
    node.data(&id_of(&open), b"pong").await;
    assert_eq!(next(&leg).await, Some((OPCODE_BINARY, b"pong".to_vec())));
    assert!(!role.said("reverse spare"), "{:?}", role.events.lock().unwrap());
}

/// A spare that the node has not readied is never handed out: the leg opens
/// a session of its own and waits for its `ready`, as an early one would
/// hand the operator a dead session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leg_never_takes_a_spare_that_the_node_has_not_readied() {
    let role = role_with(LONG, LONG).await;
    let pair = role.pair();
    let node = Node::join(&role, &pair).await;
    node.ask(1).await;
    let unready = id_of(&node.text().await);
    node.settle(&role, 1).await;
    let leg = leg(&role, &pair).await;
    let open = node.text().await;
    assert_eq!((open["type"].as_str(), open.get("spare")), (Some("open"), None), "the leg's own open: {open}");
    assert_ne!(id_of(&open), unready);
    node.ready(&id_of(&open)).await;
    assert_eq!(id_of(&next_text(&leg).await), id_of(&open), "its ready is its own session's");
    leg.send_binary(b"x").await.unwrap();
    assert_eq!(node.within(LIMIT).await, Some((OPCODE_BINARY, framed(&id_of(&open), b"x"))));
}

/// A tick with no take leaves the floor, one spare: the others close with
/// their reason, and the one left still serves a leg.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tick_with_no_take_leaves_the_floor_and_the_one_left_serves() {
    let role = role_with(Duration::from_millis(800), LONG).await;
    let pair = role.pair();
    let node = Node::join(&role, &pair).await;
    node.ask(4).await;
    let mut live = HashSet::new();
    for _ in 0..4 {
        let id = id_of(&node.text().await);
        node.ready(&id).await;
        live.insert(id);
    }
    let mut closes = 0;
    while let Some((opcode, payload)) = node.within(Duration::from_millis(2_500)).await {
        assert_eq!(opcode, OPCODE_TEXT);
        let told: Value = serde_json::from_slice(&payload).unwrap();
        let said = (told["type"].as_str(), told["reason"].as_str());
        assert_eq!(said, (Some("close"), Some("a spare that no operator needs")), "{told}");
        assert!(live.remove(&id_of(&told)), "{told}");
        closes += 1;
    }
    assert_eq!((closes, live.len()), (3, 1));
    let left = live.into_iter().next().unwrap();
    let leg = leg(&role, &pair).await;
    assert_eq!(id_of(&next_text(&leg).await), left);
}

/// Two legs that find no readied spare open sessions of their own, and each
/// asks for one more spare, up to the node's number.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legs_that_find_no_spare_ask_for_one_more_each() {
    let role = role_with(Duration::from_millis(1_500), LONG).await;
    let pair = role.pair();
    let node = Node::join(&role, &pair).await;
    node.ask(4).await;
    for _ in 0..4 {
        assert_eq!(node.text().await["spare"].as_bool(), Some(true));
    }
    // None readied: the tick leaves one, still opening.
    for _ in 0..3 {
        assert_eq!(node.text().await["type"], "close");
    }
    let (mut more, mut legs) = (0, Vec::new());
    for _ in 0..2 {
        let leg = leg(&role, &pair).await;
        loop {
            let open = node.text().await;
            assert_eq!(open["type"], "open", "{open}");
            if open["spare"].as_bool() == Some(true) {
                more += 1;
                continue;
            }
            node.ready(&id_of(&open)).await;
            break;
        }
        assert_eq!(next_text(&leg).await["type"], "ready");
        legs.push(leg);
    }
    while let Some((_, payload)) = node.within(Duration::from_millis(400)).await {
        let open: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!((open["type"].as_str(), open["spare"].as_bool()), (Some("open"), Some(true)), "{open}");
        more += 1;
    }
    assert_eq!(more, 2, "one more for each leg that found none");
}

/// The spares and the operators' sessions stay inside the node's 64: a node
/// with 62 gets two spares of the four that it asks for, two legs take them
/// with no spare after, and a leg past them is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_spares_stay_inside_the_nodes_sessions_and_a_leg_past_them_is_refused() {
    let role = role_with(LONG, LONG).await;
    let pair = role.pair();
    let node = Node::join(&role, &pair).await;
    let mut legs = Vec::new();
    for _ in 0..MAX_SESSIONS - 2 {
        let leg = leg(&role, &pair).await;
        let open = node.text().await;
        assert_eq!(open.get("spare"), None, "{open}");
        node.ready(&id_of(&open)).await;
        assert_eq!(next_text(&leg).await["type"], "ready");
        legs.push(leg);
    }
    node.ask(4).await;
    let mut spares = Vec::new();
    for _ in 0..2 {
        let open = node.text().await;
        assert_eq!(open["spare"].as_bool(), Some(true), "{open}");
        spares.push(id_of(&open));
    }
    assert_eq!(node.within(Duration::from_millis(300)).await, None, "two spares fill the node's 64");
    for id in &spares {
        node.ready(id).await;
    }
    node.settle(&role, 4).await;
    for _ in 0..2 {
        let leg = leg(&role, &pair).await;
        let ready = next_text(&leg).await;
        assert!(spares.contains(&id_of(&ready)), "{ready}");
        legs.push(leg);
    }
    let past = leg(&role, &pair).await;
    assert_eq!(closed(&past).await, (Some(1011), "node unavailable".to_string()));
    assert_eq!(node.within(Duration::from_millis(300)).await, None, "no open past the node's 64");
}

/// A spare that waited its age closes with its reason, and another is drawn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spare_that_waited_its_age_closes_and_another_is_drawn() {
    let role = role_with(LONG, Duration::from_millis(300)).await;
    let pair = role.pair();
    let node = Node::join(&role, &pair).await;
    node.ask(1).await;
    let first = id_of(&node.text().await);
    node.ready(&first).await;
    let closed = node.text().await;
    let said = (closed["type"].as_str(), id_of(&closed), closed["reason"].as_str());
    assert_eq!(said, (Some("close"), first.clone(), Some("a spare that no operator took in time")));
    let next = node.text().await;
    assert_eq!((next["type"].as_str(), next["spare"].as_bool()), (Some("open"), Some(true)), "{next}");
    assert_ne!(id_of(&next), first);
}

/// Each session echoes what it takes; the sessions opened are counted.
#[derive(Default)]
struct Echo {
    opened: Arc<AtomicUsize>,
}

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(ours)
        })
    }
}

/// podssh's node for `pair`, which asks for `spares`, until `stop`.
async fn podssh_node(pair: Pair, spares: u8, handler: Echo, stop: oneshot::Receiver<()>) -> Exit {
    let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
    let settings = Settings { spares, ..Settings::default() };
    let mut config = NodeConfig {
        pair,
        label: None,
        trust: &trust,
        proxy: &proxy,
        timeout: LIMIT,
        settings,
        repair: None,
        wire: Wire::PlainLoopback,
        say: None,
    };
    reverse::run(&mut config, Arc::new(handler), async {
        let _ = stop.await;
    })
    .await
}

/// podssh's operator on `name`: `sent` up, the same back, then the end.
async fn echoed(role: &Role, name: &str, token: &str, sent: &[u8]) -> (Outcome, Vec<u8>) {
    let config = OperatorConfig {
        relay: &role.relay,
        name,
        connect_token: token,
        trust: &Trust::Default,
        proxy: &ProxyChoice::Direct,
        timeout: LIMIT,
        limits: OperatorLimits::default(),
        wire: Wire::PlainLoopback,
    };
    let (app, leg) = tokio::io::duplex(64 * 1024);
    let (mut r, mut w) = tokio::io::split(app);
    let carry = async {
        let mut got = vec![0; sent.len()];
        if w.write_all(sent).await.is_ok() {
            let _ = r.read_exact(&mut got).await;
        }
        let _ = w.shutdown().await;
        got
    };
    let (outcome, got) = tokio::join!(operator::run(&config, leg), carry);
    (outcome.expect("the operator's socket"), got)
}

/// podssh's node asks for two, and podssh's operators take them: each
/// session's bytes come back whole; a node that asks for none gets none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn podssh_s_node_asks_and_its_operators_carry_their_bytes_through_the_spares() {
    for asked in [2u8, 0] {
        let role = Role::start().await;
        let pair = role.pair();
        let (name, token) = (pair.name.clone(), pair.connect_token().to_string());
        let echo = Echo::default();
        let opened = echo.opened.clone();
        let (stop, stopped) = oneshot::channel();
        let test = async {
            role.until_said("reverse node").await;
            // Its spares opened by its handler, and their `ready` on the way.
            let until = Instant::now() + LIMIT;
            while opened.load(Ordering::SeqCst) < usize::from(asked) {
                assert!(Instant::now() < until, "the node opened no spare");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut each = Vec::new();
            for n in 0..3u8 {
                let sent = vec![n; 16 * 1024];
                let (outcome, got) = echoed(&role, &name, &token, &sent).await;
                assert!(got == sent, "session {n} came back changed: {outcome:?}");
                each.push(outcome);
            }
            let _ = stop.send(());
            each
        };
        // The node's future boxed: a worker's stack of 2 MiB holds it in debug.
        let both = async { tokio::join!(test, Box::pin(podssh_node(pair, asked, echo, stopped))) };
        let (each, exit) = tokio::time::timeout(4 * LIMIT, both).await.expect("in time");
        assert!(each.iter().all(Outcome::is_success), "{each:?}");
        assert!(matches!(exit, Exit::Stopped), "{exit:?}");
        let taken = role.events.lock().unwrap().iter().filter(|line| *line == "reverse spare taken").count();
        match asked {
            0 => assert!(taken == 0 && !role.said("reverse spares"), "{:?}", role.events.lock().unwrap()),
            _ => assert!(taken >= 1 && role.said("reverse spares 2"), "{:?}", role.events.lock().unwrap()),
        }
        assert!(!role.said("reverse node closed"), "{:?}", role.events.lock().unwrap());
    }
}
