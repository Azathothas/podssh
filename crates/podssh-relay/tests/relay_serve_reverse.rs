//! podssh's own node (T-079) and operator (T-080) against podssh's relay
//! role (T-427), as they run against the live relay and the stand-in: two
//! sessions at once carry their bytes whole; a slow operator meets the
//! contract's bound, `1011 relay backpressure` at 1 MiB, while the node's
//! other session goes on (T-336); a planned stop's `1012` sends the node
//! back to its pair (T-255); a role that mints for keys keeps a share of its
//! pairs for each (T-630); and the role's frames to a node give each session
//! a turn (T-648).
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::identity::Identity;
use podssh_relay::pair::Pair;
use podssh_relay::reverse::{self, operator, Exit, Handler, NodeConfig, Opening, OperatorConfig, OperatorLimits};
use podssh_relay::reverse::{Outcome, SessionId, Settings, Wire};
use podssh_relay::serve::reverse::{carrier, Pairs};
use podssh_relay::serve::Mint;
use podssh_ws::frame::{Frame, OPCODE_BINARY, OPCODE_TEXT};
use podssh_ws::session::RelaySession;
use podssh_ws::{ProxyChoice, Trust};
use role_harness::{Role, LIMIT};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;

const MIB: usize = 1 << 20;
/// The most bytes of an echoed session in flight at once: under each bound
/// of the road (the operator's 1 MiB before the node is ready, the node's
/// queue for its local side, the role's backpressure), as the layer's window
/// keeps a session under them, so that a slow host meets none of them; each
/// bound has its own test (T-602).
const WINDOW: usize = 256 * 1024;

/// Bytes from a fixed xorshift, so that a byte out of place shows.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Each session echoes what it takes; with `flood`, the first one opened
/// sends `flood` bytes as fast as the node takes them, and reads nothing.
struct Local {
    opened: AtomicUsize,
    flood: Option<usize>,
}

impl Handler for Local {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        let first = self.opened.fetch_add(1, Ordering::SeqCst) == 0;
        let flood = self.flood.filter(|_| first);
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(256 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                match flood {
                    Some(len) => {
                        for chunk in pattern(len, 9).chunks(64 * 1024) {
                            if w.write_all(chunk).await.is_err() {
                                return;
                            }
                        }
                    }
                    None => {
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    }
                }
            });
            Ok(ours)
        })
    }
}

/// podssh's node for `pair`, on the plain wire, until `stop`.
async fn node(pair: Pair, handler: Local, stop: oneshot::Receiver<()>) -> (Exit, Pair) {
    let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
    let mut config = NodeConfig {
        pair,
        label: None,
        trust: &trust,
        proxy: &proxy,
        timeout: LIMIT,
        settings: Settings::default(),
        repair: None,
        wire: Wire::PlainLoopback,
        say: None,
    };
    let exit = reverse::run(&mut config, Arc::new(handler), async {
        let _ = stop.await;
    })
    .await;
    (exit, config.pair)
}

/// podssh's operator on `name`. With no `pace`, `sent` goes up and the
/// same count comes back, then the input ends; with a `pace`, nothing goes
/// up, the input stays open, and 16 KiB is read at a time with a pause after
/// each read, until the session ends. Its outcome, and what came back.
async fn operate(role: &Role, name: &str, token: &str, sent: Vec<u8>, pace: Option<Duration>) -> (Outcome, Vec<u8>) {
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
        let mut got = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        match pace {
            // The slow reader keeps a count, not the bytes.
            Some(pause) => loop {
                match r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.resize(got.len() + n, 0),
                }
                tokio::time::sleep(pause).await;
            },
            // An echoed session keeps WINDOW at most in flight.
            None => {
                let mut at = 0;
                while got.len() < sent.len() {
                    let room = at < sent.len() && at - got.len() < WINDOW;
                    let piece = &sent[at..(at + 16 * 1024).min(sent.len())];
                    tokio::select! {
                        written = w.write(piece), if room => match written {
                            Ok(n) => at += n,
                            Err(_) => break,
                        },
                        read = r.read(&mut buf) => match read {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        },
                    }
                }
            }
        }
        // The end of the input ends an echoed session.
        let _ = w.shutdown().await;
        got
    };
    let (outcome, got) = tokio::join!(operator::run(&config, leg), carry);
    (outcome.expect("the operator's socket"), got)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sessions_carry_their_bytes_whole_through_the_role() {
    let role = Role::start().await;
    let pair = role.pair();
    let (name, token) = (pair.name.clone(), pair.connect_token().to_string());
    let (stop, stopped) = oneshot::channel();
    let test = async {
        role.until_said("reverse node").await;
        let (a, b) = tokio::join!(
            operate(&role, &name, &token, pattern(2 * MIB, 1), None),
            operate(&role, &name, &token, pattern(2 * MIB, 2), None),
        );
        let _ = stop.send(());
        (a, b)
    };
    let (((a, got_a), (b, got_b)), (exit, _)) = tokio::time::timeout(4 * LIMIT, async {
        tokio::join!(test, node(pair, Local { opened: 0.into(), flood: None }, stopped))
    })
    .await
    .expect("in time");
    assert_eq!(Sha256::digest(&got_a), Sha256::digest(pattern(2 * MIB, 1)), "session a: {a:?}");
    assert_eq!(Sha256::digest(&got_b), Sha256::digest(pattern(2 * MIB, 2)), "session b: {b:?}");
    assert!(a.is_success() && b.is_success(), "{a:?} {b:?}");
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
    assert!(!role.said("reverse node closed"), "{:?}", role.events.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_operator_meets_the_bound_and_the_nodes_other_session_goes_on() {
    let role = Role::start().await;
    let pair = role.pair();
    let (name, token) = (pair.name.clone(), pair.connect_token().to_string());
    let (stop, stopped) = oneshot::channel();
    let test = async {
        role.until_said("reverse node").await;
        // The first session floods 48 MiB to an operator that reads 16 KiB
        // each 5 ms, about 3 MiB/s: more than 1 MiB waits at the role.
        let slow = operate(&role, &name, &token, Vec::new(), Some(Duration::from_millis(5)));
        let slow = tokio::time::timeout(2 * LIMIT, slow);
        let (slow, ()) = tokio::join!(slow, role.until_said("reverse backpressure"));
        // The node's socket carried it all: a second session goes through.
        let other = operate(&role, &name, &token, pattern(MIB, 3), None).await;
        let _ = stop.send(());
        (slow, other)
    };
    let local = Local { opened: 0.into(), flood: Some(48 * MIB) };
    let ((slow, (other, got)), (exit, _)) =
        tokio::time::timeout(4 * LIMIT, async { tokio::join!(test, node(pair, local, stopped)) })
            .await
            .expect("in time");
    let (slow, _) = slow.expect("the slow session ends, as the contract's bound ends it");
    assert!(
        matches!(&slow, Outcome::Ended { code: 1011, reason } if reason == "relay backpressure"),
        "the slow operator: {slow:?}"
    );
    assert_eq!(Sha256::digest(&got), Sha256::digest(pattern(MIB, 3)), "the other session: {other:?}");
    assert!(other.is_success(), "{other:?}");
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
    assert!(!role.said("reverse node closed"), "no 1003 for the node: {:?}", role.events.lock().unwrap());
}

/// T-592: the pair's owner renews it by its stop token, and each token
/// holds past the end that it had, on the role's wall clock, which a paused
/// clock of tokio does not move: so the pair is one made 72 h less 3 s
/// before. The node's socket, joined before the renewal, is not ended at the
/// old end; the status names the new one; an operator's session opens after
/// it. Another token gets the 403 of each failed authentication, and a GET
/// the 405 of a POST.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renewal_by_the_stop_token_extends_the_pair_and_keeps_its_tokens() {
    let role = Role::start().await;
    let (lifetime, now) = (podssh_relay::serve::reverse::pairs::LIFETIME_MS, podssh_relay::serve::tokens::now_ms());
    let pair = role.pair_made_at(now + 3_000 - lifetime);
    let (name, connect) = (pair.name.clone(), pair.connect_token().to_string());
    let (node_token, stop_token) = (pair.node_token().to_string(), pair.stop_token().to_string());
    let path = format!("/v1/renew/{name}");
    let (stop, stopped) = oneshot::channel();
    let test = async {
        role.until_said("reverse node").await;
        for other in [connect.as_str(), node_token.as_str()] {
            assert_eq!(role.http("POST", &path, Some(other)).await.0, 403, "the stop token alone renews");
        }
        assert_eq!(role.http("GET", &path, Some(stop_token.as_str())).await.0, 405, "a renewal is a POST");
        let renewed = role.http("POST", &path, Some(stop_token.as_str())).await;
        // Past the old end.
        tokio::time::sleep(Duration::from_secs(4)).await;
        let status = role.http("GET", &format!("/v1/status/{name}"), Some(connect.as_str())).await;
        let session = operate(&role, &name, &connect, pattern(64 * 1024, 5), None).await;
        let _ = stop.send(());
        (renewed, status, session)
    };
    let ((renewed, (status, body), (outcome, got)), (exit, _)) = tokio::time::timeout(2 * LIMIT, async {
        tokio::join!(test, node(pair, Local { opened: 0.into(), flood: None }, stopped))
    })
    .await
    .expect("in time");
    assert_eq!(renewed.0, 200, "{}", renewed.1);
    let until = serde_json::from_str::<serde_json::Value>(&renewed.1).unwrap()["expires"].as_u64().unwrap();
    assert!(until >= now + lifetime, "72 h from the renewal: {}", renewed.1);
    assert!(role.said("reverse renew"), "{:?}", role.events.lock().unwrap());
    assert!(!role.said("reverse expired"), "the role ended the renewed pair at its old end");
    assert_eq!(status, 200, "the connect token past the old end: {body}");
    let presence: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!((presence["online"].as_bool(), presence["expires"].as_u64()), (Some(true), Some(until)), "{body}");
    assert_eq!(Sha256::digest(&got), Sha256::digest(pattern(64 * 1024, 5)), "{outcome:?}");
    assert!(outcome.is_success(), "{outcome:?}");
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_planned_stops_1012_the_node_joins_its_pair_again() {
    let role = Role::start().await;
    let pair = role.pair();
    let (stop, stopped) = oneshot::channel();
    let test = async {
        role.until_said("reverse node").await;
        assert!(role.cfg.pairs.restart(Duration::from_secs(5)).await, "each Close went out, and was answered");
        // The node connects again to the pair it holds: at once, or after
        // its backoff when the stop's `503` met it (T-255).
        let deadline = std::time::Instant::now() + LIMIT;
        while role.events.lock().unwrap().iter().filter(|l| *l == "reverse node").count() < 2 {
            assert!(std::time::Instant::now() < deadline, "{:?}", role.events.lock().unwrap());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = stop.send(());
    };
    let ((), (exit, _)) = tokio::time::timeout(2 * LIMIT, async {
        tokio::join!(test, node(pair, Local { opened: 0.into(), flood: None }, stopped))
    })
    .await
    .expect("in time");
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
}

/// A list of the keys of `seeds`, in a private scratch file that goes when
/// the test ends, pass or fail: the gate counts what tests leave.
struct Keys {
    dir: PathBuf,
    path: PathBuf,
}

impl Keys {
    fn of(seeds: &[u8]) -> Keys {
        let dir = std::env::temp_dir().join(format!("podssh-share-{}", std::process::id()));
        podssh_relay::cache::private_dir(&dir).unwrap();
        let path = dir.join("allow");
        let print = |seed: u8| Identity::from_seed(&[seed; 32]).public().fingerprint();
        let lines: String = seeds.iter().map(|&seed| format!("{} the key of seed {seed}\n", print(seed))).collect();
        std::fs::write(&path, lines).unwrap();
        Keys { dir, path }
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `POST /v1/pair` by the key of `seed`, as podssh's client sends it to a
/// role that mints for keys (T-448): the contract's `{}`, then the key's
/// proof of the role's challenge, signed for the `Host` that it sends. The
/// status and the body.
async fn pair_by_key(role: &Role, seed: u8) -> (u16, String) {
    let (status, body) = role.http_body("POST", "/v1/pair", None, "{}").await;
    assert_eq!(status, 401, "a challenge: {body}");
    let asked: serde_json::Value = serde_json::from_str(&body).expect("the challenge's JSON");
    let challenge = asked["challenge"].as_str().expect("a challenge");
    let proof = podssh_relay::keyed::proof(&Identity::from_seed(&[seed; 32]), "127.0.0.1", "/v1/pair", challenge);
    role.http_body("POST", "/v1/pair", None, std::str::from_utf8(&proof).unwrap()).await
}

/// T-630: a role that mints for three keys, with a table of 6 places, keeps
/// one for each: the first key pairs past its own, then meets its share in
/// words that name its own count and share and no other key; each other key
/// still pairs; then the table is full, in the table's own words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_past_its_share_hears_its_own_words_and_each_other_key_still_pairs() {
    let list = Keys::of(&[1, 2, 3]);
    let role = Role::with_pairs(Mint::Keys(list.path.clone()), Pairs::default().with_room(6)).await;
    let mut made = 0;
    let (status, body) = loop {
        let (status, body) = pair_by_key(&role, 1).await;
        if status != 200 {
            break (status, body);
        }
        made += 1;
        assert!(made <= 6, "the table's bound held nothing back");
    };
    assert_eq!((status, made), (429, 4), "{body}");
    assert_eq!(body.trim_end(), "/v1/pair: this key holds 4 pairs, past its share of 1 while others wait");
    for seed in [2, 3] {
        let print = Identity::from_seed(&[seed; 32]).public().fingerprint();
        assert!(!body.contains(&print), "another key's name: {body}");
    }
    assert!(role.said("/v1/pair: a key past its share of 1 pairs"), "{:?}", role.events.lock().unwrap());
    for seed in [2, 3] {
        let (status, body) = pair_by_key(&role, seed).await;
        assert_eq!(status, 200, "the reserve of the key of seed {seed}: {body}");
    }
    let (status, body) = pair_by_key(&role, 3).await;
    assert_eq!((status, body.trim_end()), (429, "/v1/pair: this relay keeps 6 pairs already"));
}

/// The turns of the other tasks that a still count waits through: each step
/// of a task on the test's one thread takes one.
const QUIET_TURNS: usize = 1000;

/// The node's next text or binary frame on its socket.
async fn node_frame(node: &RelaySession<DuplexStream>) -> Frame {
    loop {
        let f = tokio::time::timeout(LIMIT, node.read_frame()).await.expect("a frame in time").expect("a frame");
        if f.opcode == OPCODE_TEXT || f.opcode == OPCODE_BINARY {
            return f;
        }
    }
}

async fn node_text(node: &RelaySession<DuplexStream>) -> serde_json::Value {
    let f = node_frame(node).await;
    assert_eq!(f.opcode, OPCODE_TEXT, "{:?}", String::from_utf8_lossy(&f.payload));
    serde_json::from_slice(&f.payload).expect("JSON")
}

/// An operator's leg of the carrier's role, once the node readied its
/// session: the leg, and the session's id as the node heard it.
async fn leg(role: &carrier::Role, node: &RelaySession<DuplexStream>) -> (RelaySession<DuplexStream>, String) {
    let path = podssh_relay::relay::operator_path(carrier::NAME).unwrap();
    let leg = role.open(&path, LIMIT).await.expect("an operator's leg");
    let open = node_text(node).await;
    let id = open["id"].as_str().expect("an open with its id").to_string();
    node.send_text(&format!(r#"{{"type":"ready","id":"{id}"}}"#)).await.unwrap();
    let ready = tokio::time::timeout(LIMIT, leg.read_frame()).await.expect("ready in time").expect("ready");
    assert_eq!(ready.opcode, OPCODE_TEXT, "the operator's ready");
    (leg, id)
}

/// Until `count` stays still while each other task of this thread runs: its
/// sender waits, as each queue on its way is full.
async fn until_still(count: &AtomicUsize) {
    let (mut last, mut still) = (count.load(Ordering::SeqCst), 0);
    while still < QUIET_TURNS {
        tokio::task::yield_now().await;
        let now = count.load(Ordering::SeqCst);
        (last, still) = if now == last { (last, still + 1) } else { (now, 0) };
    }
}

/// T-648: the relay role's side of a node's socket, on pipes with no kernel
/// between (a carrier's, T-595, which runs the role's own code), and a node
/// that reads nothing while operator A uploads: A's frames fill the role's
/// line to the node. Operator B's four bytes then reach the node before 512
/// KiB more of A's; one queue for all held 1 MiB of A ahead of them.
#[tokio::test]
async fn an_operators_bytes_reach_a_slow_node_before_anothers_backlog() {
    let role = carrier::Role::new("a test's pipe", None, None).expect("the carrier's role");
    let (link, node_end) = tokio::io::duplex(64 * 1024);
    role.attach(Box::new(link)).expect("the node's socket");
    let node = carrier::node_socket(node_end);
    carrier::greet(&node).await.unwrap();
    assert_eq!(node_text(&node).await["type"], "hello");
    let (a, id_a) = leg(&role, &node).await;
    let (b, id_b) = leg(&role, &node).await;
    let (a, sent) = (Arc::new(a), Arc::new(AtomicUsize::new(0)));
    let flood = {
        let (a, sent) = (a.clone(), sent.clone());
        tokio::spawn(async move {
            let payload = vec![b'a'; 60_000];
            for _ in 0..64 {
                if a.send_binary(&payload).await.is_err() {
                    return;
                }
                sent.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    until_still(&sent).await;
    let waited = sent.load(Ordering::SeqCst);
    assert!(waited < 64, "A's sender never waited: the role took 3.8 MB for a node that reads nothing");
    b.send_binary(b"to b").await.unwrap();
    let mut before = 0;
    loop {
        let f = node_frame(&node).await;
        assert_eq!(f.opcode, OPCODE_BINARY);
        let (id, payload) = f.payload.split_at(32);
        if id == id_b.as_bytes() {
            assert_eq!(payload, b"to b");
            break;
        }
        assert_eq!(id, id_a.as_bytes());
        before += payload.len();
        assert!(before < 512 * 1024, "{before} bytes of A came before B's four");
    }
    flood.abort();
}
