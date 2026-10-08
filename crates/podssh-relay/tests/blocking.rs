//! The blocking facade (T-081), with no network: each call from a thread that
//! runs a tokio runtime is refused, and nothing panics, also when a client is
//! made and dropped there; and no token is in a debug text or an error.
#![cfg(feature = "blocking")]

use podssh_relay::blocking::{Client, Config, Error, Forward, Local, NodeOptions, Operator, Stopper};
use podssh_relay::pair::{self, Pair, PairError};
use podssh_relay::relay::{Relay, RelayList};

const NAME: &str = "podssh-test-pair-0123456789abcdef0";
const NODE: &str = "testonlynode0000000000000000000000000000000000000000000000000000";
const CONNECT: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";
const STOP: &str = "testonlystop0000000000000000000000000000000000000000000000000000";

fn relay() -> Relay {
    Relay { host: "relay.invalid".into(), port: 443 }
}

fn test_pair(relay: &Relay) -> Pair {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let body = format!(
        r#"{{"name":"{NAME}","node_token":"{NODE}","connect_token":"{CONNECT}","stop_token":"{STOP}","expires":{}}}"#,
        now + 72 * 3600 * 1000
    );
    pair::parse(relay, body.as_bytes(), now).expect("a test pair")
}

fn refuse(_: &str) -> Result<Local, String> {
    Err("no session in this test".into())
}

/// Each call of `client` is refused here, and the caller keeps its pair.
fn each_call_is_refused(client: &Client) {
    let relay = relay();
    let mut pair = test_pair(&relay);
    let relays = RelayList { hosts: vec![relay.clone()], explicit: true };
    assert!(matches!(client.pair(&relay), Err(Error::InsideRuntime)), "pair");
    assert!(matches!(client.status(&pair), Err(Error::InsideRuntime)), "status");
    assert!(matches!(client.stop(&pair), Err(Error::InsideRuntime)), "stop");
    let node = client.run_node(&mut pair, refuse, &NodeOptions::default(), &Stopper::new());
    assert!(matches!(node, Err(Error::InsideRuntime)), "run_node: {node:?}");
    let operator = client.run_operator(&Operator::of(&pair), std::io::empty(), std::io::sink());
    assert!(matches!(operator, Err(Error::InsideRuntime)), "run_operator: {operator:?}");
    assert!(matches!(client.open_forward(&relays, "example.org", 22), Err(Error::InsideRuntime)), "open_forward");
    assert_eq!((pair.name.as_str(), pair.node_token()), (NAME, NODE), "the pair is still the caller's");
}

/// `Runtime::block_on` panics on a thread that runs a runtime; the facade
/// checks first. On a runtime of each kind, and on a thread of
/// `spawn_blocking`, which carries the runtime's context too.
#[test]
fn each_call_from_inside_a_runtime_is_refused_and_nothing_panics() {
    let current = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    current.block_on(async {
        let client = Client::new(Config::default()).expect("a client may be made here");
        each_call_is_refused(&client);
        // A drop inside an async context must not panic either.
        drop(client);
    });
    let multi = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    multi.block_on(async {
        let client = Client::new(Config::default()).unwrap();
        each_call_is_refused(&client);
        let client = tokio::task::spawn_blocking(move || {
            each_call_is_refused(&client);
            client
        })
        .await
        .unwrap();
        drop(client);
    });
}

#[test]
fn a_client_and_a_forward_stream_may_be_shared_between_threads() {
    fn shared<T: Send + Sync>() {}
    shared::<Client>();
    shared::<Forward<'static>>();
    shared::<Stopper>();
}

#[test]
fn a_stopper_keeps_a_stop_that_came_first() {
    let stopper = Stopper::new();
    let clone = stopper.clone();
    assert!(!stopper.is_stopped());
    clone.stop();
    assert!(stopper.is_stopped(), "a clone stops the same node");
}

#[test]
fn no_token_is_in_a_debug_text_or_an_error() {
    let relay = relay();
    let pair = test_pair(&relay);
    let client = Client::new(Config::default()).unwrap();
    let texts = [
        format!("{:?}", Operator::of(&pair)),
        format!("{client:?}"),
        format!("{:?}", NodeOptions::default()),
        Error::Pair(PairError::Forbidden).to_string(),
        Error::InsideRuntime.to_string(),
    ];
    for text in texts {
        for token in [NODE, CONNECT, STOP] {
            assert!(!text.contains(token), "a token is in {text:?}");
        }
    }
    assert!(format!("{:?}", Operator::of(&pair)).contains("<redacted>"));
}

#[test]
fn a_target_that_the_relay_cannot_take_is_refused_before_any_connection() {
    let client = Client::new(Config::default()).unwrap();
    let relays = RelayList { hosts: vec![relay()], explicit: true };
    for (host, port) in [("example.org/../x", 22), ("example.org", 0), ("a b", 22)] {
        let refused = client.open_forward(&relays, host, port);
        assert!(matches!(refused, Err(Error::BadTarget(_))), "{host}:{port}: {refused:?}");
    }
}
