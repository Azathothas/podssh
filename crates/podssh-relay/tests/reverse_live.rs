//! The runners of the reverse road against the live relay (T-079, T-080), on
//! request only: `cargo test -p podssh-relay --features pair --test
//! reverse_live -- --ignored`. Each test makes a pair, runs a node, opens
//! operator sessions with the operator runner, and stops the node and the
//! pair. No test prints a token.
#![cfg(feature = "pair")]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::pair::{self, Pair, PairContext};
use podssh_relay::relay::{Relay, DEFAULT_RELAY_HOST};
use podssh_relay::reverse::SessionId;
use podssh_relay::reverse::{
    operator, run, Exit, Handler, NodeConfig, Opening, OperatorConfig, OperatorLimits, Outcome, Settings, Wire,
};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

const MIB: usize = 1024 * 1024;
const LIMIT: Duration = Duration::from_secs(30);

/// Each session echoes its bytes.
struct Echo;

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async {
            let (node_end, mut echo_end) = tokio::io::duplex(256 * 1024);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match echo_end.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if echo_end.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            Ok(node_end)
        })
    }
}

/// Each session is refused with this reason.
struct Refuse(String);

impl Handler for Refuse {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        let reason = self.0.clone();
        Box::pin(async move { Err(reason) })
    }
}

fn relay() -> Relay {
    Relay { host: DEFAULT_RELAY_HOST.into(), port: 443 }
}

/// A pair, and a second copy of it for the operator's side.
async fn paired(relay: &Relay) -> (Pair, Pair) {
    let ctx = PairContext { relay, trust: &Trust::Default, proxy: &ProxyChoice::FromEnvironment, timeout: LIMIT };
    let made = pair::create(&ctx).await.expect("a pair");
    let copy = pair::parse(relay, &body_of(&made), now_ms()).expect("the same pair");
    (made, copy)
}

/// Run a node with `handler` until the returned notify is notified.
fn node<H: Handler>(made: Pair, handler: H) -> (tokio::task::JoinHandle<Exit>, Arc<Notify>) {
    let stop = Arc::new(Notify::new());
    let stopper = stop.clone();
    let task = tokio::spawn(async move {
        let mut config = NodeConfig {
            pair: made,
            label: None,
            trust: &Trust::Default,
            proxy: &ProxyChoice::FromEnvironment,
            timeout: LIMIT,
            settings: Settings::default(),
            repair: None,
            wire: Wire::Tls,
            say: None,
        };
        run(&mut config, Arc::new(handler), async move { stopper.notified().await }).await
    });
    (task, stop)
}

/// One operator session over the operator runner: send `payload`, read as
/// many bytes back, then end the input.
async fn operator_echo(pair: &Pair, payload: Vec<u8>) -> (Vec<u8>, Outcome) {
    let (io, mut user) = tokio::io::duplex(4 * MIB);
    let relay = pair.relay.clone();
    let (name, token) = (pair.name.clone(), pair.connect_token().to_string());
    let session = tokio::spawn(async move {
        let config = OperatorConfig {
            relay: &relay,
            name: &name,
            connect_token: &token,
            trust: &Trust::Default,
            proxy: &ProxyChoice::FromEnvironment,
            timeout: LIMIT,
            limits: OperatorLimits::default(),
            wire: Wire::Tls,
        };
        operator::run(&config, io).await.expect("the operator's socket")
    });
    let (mut from_user, mut to_user) = tokio::io::split(&mut user);
    let sent = payload.len();
    let (_, back) = tokio::join!(async move { to_user.write_all(&payload).await.unwrap() }, async move {
        let mut back = vec![0u8; sent];
        tokio::time::timeout(LIMIT, from_user.read_exact(&mut back)).await.expect("the echo in time").unwrap();
        back
    });
    user.shutdown().await.unwrap();
    let outcome = tokio::time::timeout(LIMIT, session).await.expect("an outcome").unwrap();
    (back, outcome)
}

fn pattern(seed: u8) -> Vec<u8> {
    (0..MIB).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "the live relay: run with --ignored"]
async fn node_serves_two_sessions_at_once() {
    let relay = relay();
    let (made, copy) = paired(&relay).await;
    let (task, stop) = node(made, Echo);
    tokio::time::sleep(Duration::from_secs(2)).await;

    let ((one, first), (two, second)) =
        tokio::join!(operator_echo(&copy, pattern(1)), operator_echo(&copy, pattern(2)));
    assert!(one == pattern(1), "the first session's bytes came back changed");
    assert!(two == pattern(2), "the second session's bytes came back changed");
    assert!(first.is_success() && second.is_success(), "{first:?} {second:?}");
    eprintln!("two sessions, 1 MiB each way, came back whole: {first:?}, {second:?}");

    stop.notify_one();
    let exit = tokio::time::timeout(LIMIT, task).await.expect("the node stops").unwrap();
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
    stop_pair(&relay, &copy).await;
}

/// The relay cuts the reason of its Close to 123 bytes; the operator still
/// gets the node's 200 bytes, from the text `reject`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "the live relay: run with --ignored"]
async fn operator_sees_reject_with_full_reason() {
    let relay = relay();
    let (made, copy) = paired(&relay).await;
    let reason: String = (0..200).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
    let (task, stop) = node(made, Refuse(reason.clone()));
    tokio::time::sleep(Duration::from_secs(2)).await;

    let (io, _user) = tokio::io::duplex(1024);
    let config = OperatorConfig {
        relay: &copy.relay,
        name: &copy.name,
        connect_token: copy.connect_token(),
        trust: &Trust::Default,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: LIMIT,
        limits: OperatorLimits::default(),
        wire: Wire::Tls,
    };
    let outcome = operator::run(&config, io).await.expect("the operator's socket");
    eprintln!("outcome: {outcome:?}");
    assert_eq!(outcome, Outcome::NeverReady { code: Some(1011), reason: reason.clone() }, "all 200 bytes");
    assert!(!outcome.is_success());

    stop.notify_one();
    let _ = tokio::time::timeout(LIMIT, task).await;
    stop_pair(&relay, &copy).await;
}

async fn stop_pair(relay: &Relay, pair: &Pair) {
    let ctx = PairContext { relay, trust: &Trust::Default, proxy: &ProxyChoice::FromEnvironment, timeout: LIMIT };
    let stopped = pair::stop(&ctx, pair).await.expect("the pair stops");
    eprintln!("pair: {stopped:?}");
}

/// The pair as a body of `/v1/pair`, to give the operator its own copy.
fn body_of(pair: &Pair) -> Vec<u8> {
    format!(
        r#"{{"name":"{}","node_token":"{}","connect_token":"{}","stop_token":"{}","expires":{}}}"#,
        pair.name,
        pair.node_token(),
        pair.connect_token(),
        pair.stop_token(),
        pair.expires_ms
    )
    .into_bytes()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}
