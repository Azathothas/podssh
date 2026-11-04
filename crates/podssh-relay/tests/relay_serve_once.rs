//! A pair of podssh's relay role whose connect token takes one upgrade
//! alone (T-226): `POST /v1/pair?once=1` says so, and its connect token is
//! refused at its second upgrade and at the status, while the node's token
//! stays; a pair of before takes each upgrade; `/relays.json` offers it.
//!
//! The tokens of one leg and the stop token's rotation (T-615): a token that
//! a node registered takes one upgrade, its node hearing which before the
//! session's `open`, and a replay of it is refused, also once the node
//! registered it again; a token waits while its node is away; through
//! podssh's own node and operator, a session of a pair of `once` resumes on
//! the next token that the node gave, and the one that it spent is refused
//! after; a rotated stop token ends the one before at the first use of the
//! new one.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::e2e::ends::{self, Node};
use podssh_relay::e2e::legs;
use podssh_relay::identity::Identity;
use podssh_relay::pair::Pair;
use podssh_relay::relay::Relay;
use podssh_relay::reverse::{self, operator, E2e, Exit, Handler, Layered, NodeConfig, Opening, OperatorConfig};
use podssh_relay::reverse::{OperatorLimits, Outcome as LegOutcome, SessionId, Wire};
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::resume::{self, Next};
use podssh_relay::session::{Ask, End, Ended, OsEntropy, Settings};
use podssh_ws::{ConnectError, ProxyChoice, Trust};
use role_harness::{next_text, Role, LIMIT};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Each direction of a pipe between a leg, the layer and the application.
const PIPE: usize = 256 * 1024;

/// A new pair of the role's, as its answer gives it.
async fn pair(role: &Role, path: &str) -> Value {
    let (status, body) = role.http("POST", path, None).await;
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).expect("JSON")
}

fn field<'a>(pair: &'a Value, name: &str) -> &'a str {
    pair[name].as_str().expect("a field of the pair")
}

#[tokio::test]
async fn a_connect_token_of_one_use_is_refused_at_its_second_upgrade() {
    let role = Role::start().await;
    let made = pair(&role, "/v1/pair?once=1").await;
    assert_eq!(made["once"], true, "the answer says that its token takes one upgrade");
    let (name, connect) = (field(&made, "name"), field(&made, "connect_token"));
    let (status, _) = role.http("GET", &format!("/v1/status/{name}"), Some(connect)).await;
    assert_eq!(status, 200, "the status before the upgrade spends nothing");
    let path = format!("/v1/connect/{name}");
    if let Err(e) = role.socket(&path, connect).await {
        panic!("the first upgrade: {e}");
    }
    assert!(role.socket(&path, connect).await.is_err(), "the second upgrade of a token of one use");
    let (status, body) = role.http("GET", &format!("/v1/status/{name}"), Some(connect)).await;
    assert_eq!((status, body.contains("reverse: forbidden")), (403, true), "the status after its use: {body}");
    assert!(role.socket(&format!("/v1/node/{name}"), field(&made, "node_token")).await.is_ok(), "the node's token");
}

#[tokio::test]
async fn a_pair_of_before_takes_each_upgrade_and_the_role_offers_one_of_once() {
    let role = Role::start().await;
    let made = pair(&role, "/v1/pair").await;
    assert!(made.get("once").is_none(), "the contract's answer, with no word of once");
    let path = format!("/v1/connect/{}", field(&made, "name"));
    for n in 0..2 {
        assert!(role.socket(&path, field(&made, "connect_token")).await.is_ok(), "upgrade {n}");
    }
    let (status, body) = role.http("GET", "/relays.json", None).await;
    let doc: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!((status, &doc["reverse"]["pair_once"]), (200, &Value::Bool(true)), "{body}");
    // The tokens of one leg and the stop token's rotation (T-615).
    assert_eq!((&doc["reverse"]["leg_tokens"], &doc["reverse"]["rotate"]), (&Value::Bool(true), &Value::Bool(true)));
}

/// The SHA-256 of a token in hex, as a node's frame names it.
fn hex_digest(token: &str) -> String {
    Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// A node's frame that registers `token` for a minute, or with `0`
/// withdraws it.
fn register(token: &str, expires_ms: u64) -> String {
    serde_json::json!({ "type": "token", "digest": hex_digest(token), "expires": expires_ms }).to_string()
}

fn now_ms() -> u64 {
    podssh_relay::serve::tokens::now_ms()
}

/// Until `holds`, [`LIMIT`] at most.
async fn until(what: &str, holds: impl Fn() -> bool) {
    let deadline = Instant::now() + LIMIT;
    while !holds() {
        assert!(Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// T-615: a token that the node registered takes one upgrade; the node hears
/// which before the session's `open`; a replay is refused, also after the
/// node registers it again; a token of one leg gives no status; a withdrawn
/// one is refused. The pair is one of `once`, whose own token the tokens of
/// one leg leave as it is.
#[tokio::test]
async fn a_token_of_one_leg_takes_one_upgrade_and_its_node_hears_which() {
    let role = Role::start().await;
    let made = pair(&role, "/v1/pair?once=1").await;
    let name = field(&made, "name").to_string();
    let node = role.socket(&format!("/v1/node/{name}"), field(&made, "node_token")).await.expect("the node's socket");
    let hello = next_text(&node).await;
    assert_eq!((&hello["legTokens"], &hello["stopRotation"]), (&Value::Bool(true), &Value::Bool(true)), "{hello}");
    let (first, second) = ("a".repeat(64), "b".repeat(64));
    let live = |token: &str| role.cfg.pairs.find_leg(&name, Some(token), now_ms()).is_some();
    node.send_text(&register(&first, now_ms() + 60_000)).await.expect("a registration");
    until("the role holds the first token", || live(&first)).await;
    let path = format!("/v1/connect/{name}");
    let _operator = role.socket(&path, &first).await.expect("the first upgrade of the token");
    let spent = next_text(&node).await;
    let want = hex_digest(&first);
    assert_eq!((&spent["type"], spent["digest"].as_str()), (&Value::from("spent"), Some(want.as_str())), "{spent}");
    assert_eq!(next_text(&node).await["type"], "open", "the session's open after the word of its token");
    assert!(matches!(role.socket(&path, &first).await, Err(ConnectError::Refused { status: 403, .. })), "a replay");
    // Registered again, then the second token: the role took the frames in order.
    node.send_text(&register(&first, now_ms() + 60_000)).await.expect("the spent token again");
    node.send_text(&register(&second, now_ms() + 60_000)).await.expect("a second token");
    until("the role holds the second token", || live(&second)).await;
    assert!(!live(&first), "a spent token is never taken again");
    let status = format!("/v1/status/{name}");
    assert_eq!(role.http("GET", &status, Some(second.as_str())).await.0, 403, "a token of one leg gives no status");
    node.send_text(&register(&second, 0)).await.expect("a withdrawal");
    until("the role withdrew the second token", || !live(&second)).await;
    assert!(role.socket(&path, &second).await.is_err(), "a withdrawn token");
    assert!(role.said("reverse leg token"), "{:?}", role.events.lock().unwrap());
}

/// T-615: while no node is joined, a token of one leg gets `503` and is not
/// taken, as the node would not hear of it; once its node is back, it opens.
#[tokio::test]
async fn a_token_of_one_leg_waits_while_its_node_is_away() {
    let role = Role::start().await;
    let made = pair(&role, "/v1/pair").await;
    let (name, node_token, connect) = (field(&made, "name"), field(&made, "node_token"), field(&made, "connect_token"));
    let token = "c".repeat(64);
    let node = role.socket(&format!("/v1/node/{name}"), node_token).await.expect("the node's socket");
    let _ = next_text(&node).await;
    node.send_text(&register(&token, now_ms() + 60_000)).await.expect("a registration");
    until("the role holds the token", || role.cfg.pairs.find_leg(name, Some(token.as_str()), now_ms()).is_some()).await;
    drop(node);
    let status = format!("/v1/status/{name}");
    let deadline = Instant::now() + LIMIT;
    while role.http("GET", &status, Some(connect)).await.1.contains("\"online\":true") {
        assert!(Instant::now() < deadline, "the role never saw the node go");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let path = format!("/v1/connect/{name}");
    let away = role.socket(&path, &token).await;
    assert!(matches!(away, Err(ConnectError::Refused { status: 503, .. })), "no node: {:?}", away.err());
    let node = role.socket(&format!("/v1/node/{name}"), node_token).await.expect("the node again");
    let _ = next_text(&node).await;
    assert!(role.socket(&path, &token).await.is_ok(), "the token waited for its node");
}

/// T-615: a rotation names the digest of the next stop token; the one before
/// still renews until the new one's first use, which makes it the stop token
/// and ends the one before, at the renewal and at the stop too.
#[tokio::test]
async fn a_rotated_stop_token_ends_the_one_before_at_the_first_use_of_the_new_one() {
    let role = Role::start().await;
    let made = pair(&role, "/v1/pair").await;
    let (name, old, node_token) = (field(&made, "name"), field(&made, "stop_token"), field(&made, "node_token"));
    let next = "d".repeat(64);
    let body = serde_json::json!({ "digest": hex_digest(&next) }).to_string();
    let (rotate, renew, stop) = (format!("/v1/rotate/{name}"), format!("/v1/renew/{name}"), format!("/v1/stop/{name}"));
    assert_eq!(role.http_body("POST", &rotate, Some(node_token), &body).await.0, 403, "the node's token rotates none");
    assert_eq!(role.http_body("POST", &rotate, Some(old), "{}").await.0, 400, "a body with no digest");
    assert_eq!(role.http("GET", &rotate, Some(old)).await.0, 405, "a rotation is a POST");
    let (status, answer) = role.http_body("POST", &rotate, Some(old), &body).await;
    assert_eq!((status, answer.contains("\"rotated\":true")), (200, true), "{answer}");
    assert_eq!(role.http("POST", &renew, Some(old)).await.0, 200, "the one before, until the new one's use");
    // The new one's first use: a rotation to itself.
    assert_eq!(role.http_body("POST", &rotate, Some(next.as_str()), &body).await.0, 200);
    assert_eq!(role.http("POST", &renew, Some(old)).await.0, 403, "the one before, after the new one's use");
    assert_eq!(role.http("POST", &stop, Some(old)).await.0, 403);
    assert_eq!(role.http("POST", &renew, Some(next.as_str())).await.0, 200, "the new one");
    assert!(role.said("reverse rotate"), "{:?}", role.events.lock().unwrap());
}

/// The layer's settings on the pair's road, as podssh's node and client run.
fn layer() -> Settings {
    Settings::default().on_the_pair()
}

/// Each session echoes what it takes.
struct Echo;

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async {
            let (ours, theirs) = tokio::io::duplex(PIPE);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(ours)
        })
    }
}

/// podssh's node for `pair`, with the layer and the channel, on the plain
/// wire, until `stop`.
async fn layered_node(pair: Pair, stop: oneshot::Receiver<()>) -> Exit {
    let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
    let mut config = NodeConfig {
        pair,
        label: None,
        trust: &trust,
        proxy: &proxy,
        timeout: LIMIT,
        settings: reverse::Settings::default(),
        repair: None,
        wire: Wire::PlainLoopback,
        say: None,
    };
    let say: Arc<dyn Fn(String) + Send + Sync> = Arc::new(|_| {});
    let channel = Node::open_to_all(Arc::new(Identity::from_seed(&[2; 32])), say);
    let handler = Arc::new(Layered::new(E2e::new(Echo, channel), layer(), reverse::layered::NODE_BUDGET));
    reverse::run(&mut config, handler, async {
        let _ = stop.await;
    })
    .await
}

/// The legs of one session, as `podssh operator` opens them: the first with
/// the pair's connect token, each next one by [`reverse::legs::start`].
struct Opener {
    relay: Relay,
    name: String,
    token: String,
    trust: Trust,
    proxy: ProxyChoice,
    current: Mutex<Option<JoinHandle<LegOutcome>>>,
}

impl Opener {
    fn config(&self) -> OperatorConfig<'_> {
        OperatorConfig {
            relay: &self.relay,
            name: &self.name,
            connect_token: &self.token,
            trust: &self.trust,
            proxy: &self.proxy,
            timeout: LIMIT,
            // A leg of the layer: the node ends it (T-388).
            limits: OperatorLimits { node_ends: Some(Duration::from_secs(35)), ..OperatorLimits::default() },
            wire: Wire::PlainLoopback,
        }
    }

    async fn first(&self) -> DuplexStream {
        let (link, leg) = tokio::io::duplex(PIPE);
        let handle = operator::start(&self.config(), leg).await.expect("the first leg, by the pair's token");
        *self.current.lock().unwrap() = Some(handle);
        link
    }

    /// The next leg after a loss; a move keeps its leg.
    async fn next(&self, moving: bool) -> Next<DuplexStream> {
        let lost = if moving { None } else { self.current.lock().unwrap().take() };
        if let Some(handle) = lost {
            let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
        }
        let (link, leg) = tokio::io::duplex(PIPE);
        match reverse::legs::start(&self.config(), leg).await {
            Ok(handle) => {
                *self.current.lock().unwrap() = Some(handle);
                Next::Link(link)
            }
            Err(e) => Next::Retry(e.to_string()),
        }
    }

    /// The leg that carries the session ends with no Close: a lost link.
    fn cut(&self) {
        if let Some(handle) = self.current.lock().unwrap().as_ref() {
            handle.abort();
        }
    }
}

/// `bytes` up, and the same bytes back.
async fn echoed(r: &mut tokio::io::ReadHalf<DuplexStream>, w: &mut tokio::io::WriteHalf<DuplexStream>, bytes: &[u8]) {
    w.write_all(bytes).await.expect("the bytes up");
    let mut back = vec![0u8; bytes.len()];
    tokio::time::timeout(LIMIT, r.read_exact(&mut back)).await.expect("the echo in time").expect("the echo");
    assert_eq!(back, bytes);
}

/// T-615, through podssh's own node and operator: a session of a pair of
/// `once` opens by the pair's token, its leg is cut, and it resumes on the
/// next token that the node gave in its verdict, as the pair's own is spent;
/// the token that the resume took is refused after, as is the pair's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resume_takes_the_next_token_that_the_node_gave_and_a_replayed_one_is_refused() {
    let role = Role::start().await;
    let made = pair(&role, "/v1/pair?once=1").await;
    let client_pair = podssh_relay::pair::parse(&role.relay, made.to_string().as_bytes(), now_ms() as i64).unwrap();
    let (name, connect) = (field(&made, "name").to_string(), field(&made, "connect_token").to_string());
    let (relay, token, current) = (role.relay.clone(), connect.clone(), Mutex::new(None));
    let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
    let opener = Opener { relay, name: name.clone(), token, trust, proxy, current };
    let (stop_node, node_stops) = oneshot::channel();
    let test = async {
        role.until_said("reverse node").await;
        let carried = legs::during(async {
            let mut entropy = OsEntropy;
            let first = opener.first().await;
            let client =
                Box::pin(client::start(first, Ask::New, layer(), &mut entropy)).await.expect("the layer's handshake");
            let (app, app_end) = tokio::io::duplex(PIPE);
            let (cipher, channel) = ends::operator(app_end, Arc::new(Identity::from_seed(&[1; 32])), |_| Ok(()));
            let connect = |ended: &Ended| opener.next(matches!(ended.end, End::Moving));
            let session = Box::pin(resume::run(client, cipher, connect, |_| {}, &mut entropy));
            let steps = Box::pin(async {
                let (mut r, mut w) = tokio::io::split(app);
                echoed(&mut r, &mut w, b"before the cut").await;
                let taker = legs::current().expect("a taker of the session");
                assert!(taker.holds(), "the node's verdict gave the seed of the session's tokens");
                opener.cut();
                echoed(&mut r, &mut w, b"after the cut").await;
                w.shutdown().await.expect("the end of the input");
                let mut rest = Vec::new();
                let _ = tokio::time::timeout(LIMIT, r.read_to_end(&mut rest)).await;
                taker.token_at(1).expect("the first token of one leg")
            });
            let (outcome, reached, replay) = tokio::join!(session, channel, steps);
            (outcome, reached.is_ok(), replay)
        })
        .await;
        let _ = stop_node.send(());
        carried
    };
    // On the heap: the node and the operator's session together outgrow the
    // stack of a test's thread in a build with no optimization.
    let (test, node) = (Box::pin(test), Box::pin(layered_node(client_pair, node_stops)));
    let ((outcome, reached, replay), exit) =
        tokio::time::timeout(4 * LIMIT, async { tokio::join!(test, node) }).await.expect("in time");
    assert!(
        matches!(&outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd | End::Closed(_))),
        "{outcome:?}"
    );
    assert!(reached, "the channel reached the node");
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
    assert!(role.said("reverse leg token"), "the resume took a token of one leg: {:?}", role.events.lock().unwrap());
    let path = format!("/v1/connect/{name}");
    let replayed = role.socket(&path, &replay).await;
    assert!(matches!(replayed, Err(ConnectError::Refused { status: 403, .. })), "{:?}", replayed.err());
    assert!(role.socket(&path, &connect).await.is_err(), "the pair's token of once, spent by the first leg");
}
