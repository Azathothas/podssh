//! A pair of podssh's relay role that its owner halts and resumes (T-647,
//! GitHub #145), frame by frame on raw sockets, as a client that podssh did
//! not shape would see it: an operator's upgrade gets `503` with the owner's
//! words and no `Retry-After`, and the status says the halt; each session
//! hears one `1011`, and the node one `close` of each and `halted`; the node
//! keeps its socket, a second node is still `409`, and a resume takes the
//! next operator on that socket; a connect token of `once` and a token of
//! one leg are unspent after a halt's refusal.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::session::RelaySession;
use podssh_ws::ConnectError;
use role_harness::{closed, next, next_text, Role, LIMIT};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The owner's words of each halt.
const WHY: &str = "a new disk, back at 14:00";
/// What each session of a halted pair hears.
const HALTED: &str = "the pair's owner halted it";

/// The node's socket of `name` with `token`, past its `hello`, which offers
/// the halt.
async fn joined(role: &Role, name: &str, token: &str) -> RelaySession<TcpStream> {
    let node = role.socket(&format!("/v1/node/{name}"), token).await.expect("the node's socket");
    let hello = next_text(&node).await;
    assert_eq!((hello["type"].as_str(), hello["halt"].as_bool()), (Some("hello"), Some(true)), "{hello}");
    node
}

/// An operator's session on `name` with `token`, readied by `node`: the
/// operator's socket and the session's id.
async fn readied(
    role: &Role,
    name: &str,
    token: &str,
    node: &RelaySession<TcpStream>,
) -> (RelaySession<TcpStream>, String) {
    let operator = role.socket(&format!("/v1/connect/{name}"), token).await.expect("the operator's socket");
    let open = next_text(node).await;
    assert_eq!(open["type"], "open", "{open}");
    let id = open["id"].as_str().expect("an id").to_string();
    node.send_text(&format!(r#"{{"type":"ready","id":"{id}"}}"#)).await.unwrap();
    assert_eq!(next_text(&operator).await["type"], "ready");
    (operator, id)
}

/// `POST /v1/WHAT/NAME` with `token` and `body`: the status and the answer,
/// as JSON where it is.
async fn owner(role: &Role, what: &str, name: &str, token: &str, body: &str) -> (u16, Value) {
    let (status, text) = role.http_body("POST", &format!("/v1/{what}/{name}"), Some(token), body).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

/// The whole answer to an operator's upgrade that the role refuses, its head
/// too.
async fn refused_upgrade(role: &Role, name: &str, token: &str) -> String {
    let mut tcp = TcpStream::connect(("127.0.0.1", role.relay.port)).await.unwrap();
    let head = format!(
        "GET /v1/connect/{name} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Relay-Token: {token}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tcp.write_all(head.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await.expect("an answer, and the end").unwrap();
    String::from_utf8_lossy(&answer).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_halted_pair_refuses_an_operator_before_the_upgrade_and_says_why() {
    let role = Role::start().await;
    let pair = role.pair();
    let name = pair.name.clone();
    let _node = joined(&role, &name, pair.node_token()).await;
    let body = format!(r#"{{"reason": "{WHY}"}}"#);
    // The stop token alone: each other gets the 403 of a failed authentication.
    for token in [pair.connect_token(), pair.node_token(), "wrong"] {
        assert_eq!(owner(&role, "halt", &name, token, &body).await.0, 403);
    }
    let (status, answer) = owner(&role, "halt", &name, pair.stop_token(), &body).await;
    let halted = (status, answer["halted"].as_bool(), answer["sessions"].as_u64());
    assert_eq!(halted, (200, Some(true), Some(0)), "{answer}");
    assert!(role.said("reverse halt"), "{:?}", role.events.lock().unwrap());

    let refused = refused_upgrade(&role, &name, pair.connect_token()).await;
    assert!(refused.starts_with("HTTP/1.1 503 "), "{refused}");
    assert!(!refused.to_ascii_lowercase().contains("retry-after"), "no second ends a halt: {refused}");
    assert!(refused.contains(&format!("reverse: {HALTED}: {WHY}")), "{refused}");
    // podssh's client reads the owner's words in the refusal.
    match role.socket(&format!("/v1/connect/{name}"), pair.connect_token()).await {
        Err(ConnectError::Refused { status: 503, body }) => assert!(body.contains(WHY), "{body}"),
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the upgrade of a halted pair was taken"),
    }
    let (status, text) = role.http("GET", &format!("/v1/status/{name}"), Some(pair.connect_token())).await;
    let told: Value = serde_json::from_str(&text).unwrap();
    assert_eq!((status, told["online"].as_bool(), told["halted"].as_bool()), (200, Some(true), Some(true)), "{text}");
    assert_eq!(told["halt_reason"].as_str(), Some(WHY), "{text}");

    // The owner's words are short and plain; the halt is a POST.
    let long = format!(r#"{{"reason": "{}"}}"#, "a".repeat(201));
    assert_eq!(owner(&role, "halt", &name, pair.stop_token(), &long).await.0, 400);
    assert_eq!(role.http("GET", &format!("/v1/halt/{name}"), Some(pair.stop_token())).await.0, 405);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_halt_closes_each_session_once_and_a_resume_takes_the_next_on_the_same_socket() {
    let role = Role::start().await;
    let pair = role.pair();
    let name = pair.name.clone();
    let node = joined(&role, &name, pair.node_token()).await;
    let (first, first_id) = readied(&role, &name, pair.connect_token(), &node).await;
    let (second, second_id) = readied(&role, &name, pair.connect_token(), &node).await;
    let (status, answer) = owner(&role, "halt", &name, pair.stop_token(), "{}").await;
    assert_eq!((status, answer["sessions"].as_u64()), (200, Some(2)), "{answer}");
    for operator in [&first, &second] {
        assert_eq!(closed(operator).await, (Some(1011), HALTED.to_string()));
    }
    // The node: one `close` of each session with the owner's words, and
    // `halted`; its socket stays.
    let mut told = Vec::new();
    for _ in 0..3 {
        told.push(next_text(&node).await);
    }
    let mut ids: Vec<&str> = told.iter().filter(|t| t["type"] == "close").filter_map(|t| t["id"].as_str()).collect();
    ids.sort_unstable();
    let mut both = [first_id.as_str(), second_id.as_str()];
    both.sort_unstable();
    assert_eq!(ids, both, "{told:?}");
    assert!(told.iter().filter(|t| t["type"] == "close").all(|t| t["reason"] == HALTED), "{told:?}");
    assert!(told.iter().any(|t| t["type"] == "halted"), "{told:?}");
    // The name is still the first node's.
    match role.socket(&format!("/v1/node/{name}"), pair.node_token()).await {
        Err(ConnectError::Refused { status: 409, .. }) => {}
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("a second node took the name of a halted pair"),
    }
    let again = owner(&role, "halt", &name, pair.stop_token(), "{}").await.1;
    assert_eq!((again["already"].as_bool(), again["sessions"].as_u64()), (Some(true), Some(0)), "{again}");

    let (status, answer) = owner(&role, "resume", &name, pair.stop_token(), "{}").await;
    assert_eq!((status, answer["resumed"].as_bool()), (200, Some(true)), "{answer}");
    assert_eq!(next_text(&node).await["type"], "resumed", "and no second close of a halted session");
    let (operator, id) = readied(&role, &name, pair.connect_token(), &node).await;
    operator.send_binary(b"after the resume").await.unwrap();
    assert_eq!(next(&node).await, Some((OPCODE_BINARY, [id.as_bytes(), b"after the resume"].concat())));
    let status = role.http("GET", &format!("/v1/status/{name}"), Some(pair.connect_token())).await.1;
    assert!(status.contains("\"halted\":false") && status.contains("\"sessions\":1"), "{status}");
    let (_, answer) = owner(&role, "resume", &name, pair.stop_token(), "{}").await;
    assert_eq!(answer["resumed"].as_bool(), Some(false), "a pair that is not halted: {answer}");
}

/// The check of a halt goes before a token of `once` is spent (T-226): its
/// refusal leaves the token for the one upgrade after the resume.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_halt_does_not_spend_a_once_pairs_one_upgrade() {
    let role = Role::start().await;
    let (status, text) = role.http("POST", "/v1/pair?once=1", None).await;
    assert_eq!(status, 200, "{text}");
    let made: Value = serde_json::from_str(&text).unwrap();
    let field = |key: &str| made[key].as_str().expect("a field of the pair").to_string();
    let (name, connect, stop) = (field("name"), field("connect_token"), field("stop_token"));
    let node = joined(&role, &name, &field("node_token")).await;
    assert_eq!(owner(&role, "halt", &name, &stop, "{}").await.0, 200);
    assert_eq!(next_text(&node).await["type"], "halted");
    let refused = refused_upgrade(&role, &name, &connect).await;
    assert!(refused.starts_with("HTTP/1.1 503 ") && refused.contains(HALTED), "{refused}");
    // A spent token of `once` gets the 403 of the status too.
    let unspent = role.http("GET", &format!("/v1/status/{name}"), Some(connect.as_str())).await.0;
    assert_eq!(unspent, 200, "the connect token of once, unspent by the refusal");
    assert_eq!(owner(&role, "resume", &name, &stop, "{}").await.0, 200);
    assert_eq!(next_text(&node).await["type"], "resumed");
    let _once = role.socket(&format!("/v1/connect/{name}"), &connect).await.expect("the one upgrade of once");
    assert_eq!(next_text(&node).await["type"], "open");
}

/// The check of a halt goes before a token of one leg is taken (T-615).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_halt_does_not_take_a_token_of_one_leg() {
    let role = Role::start().await;
    let pair = role.pair();
    let name = pair.name.clone();
    let node = joined(&role, &name, pair.node_token()).await;
    let operator = role.socket(&format!("/v1/connect/{name}"), pair.connect_token()).await.expect("an operator");
    let open = next_text(&node).await;
    let id = open["id"].as_str().expect("an id").to_string();
    // The node registers a token of one leg, then readies the session: the
    // operator's `ready` says that the role read the token before it.
    let leg = "1".repeat(64);
    let digest: String = Sha256::digest(leg.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    let expires = podssh_relay::serve::tokens::now_ms() + 600_000;
    node.send_text(&format!(r#"{{"type":"token","digest":"{digest}","expires":{expires}}}"#)).await.unwrap();
    node.send_text(&format!(r#"{{"type":"ready","id":"{id}"}}"#)).await.unwrap();
    assert_eq!(next_text(&operator).await["type"], "ready");

    assert_eq!(owner(&role, "halt", &name, pair.stop_token(), "{}").await.0, 200);
    assert_eq!(closed(&operator).await, (Some(1011), HALTED.to_string()));
    let told = [next_text(&node).await, next_text(&node).await];
    assert!(told.iter().any(|t| t["type"] == "halted") && told.iter().any(|t| t["id"] == id.as_str()), "{told:?}");
    let refused = refused_upgrade(&role, &name, &leg).await;
    assert!(refused.starts_with("HTTP/1.1 503 ") && refused.contains(HALTED), "{refused}");

    assert_eq!(owner(&role, "resume", &name, pair.stop_token(), "{}").await.0, 200);
    assert_eq!(next_text(&node).await["type"], "resumed");
    let _by_leg = role.socket(&format!("/v1/connect/{name}"), &leg).await.expect("the token of one leg, untaken");
    let spent = next_text(&node).await;
    assert_eq!((spent["type"].as_str(), spent["digest"].as_str()), (Some("spent"), Some(digest.as_str())), "{spent}");
    assert_eq!(next_text(&node).await["type"], "open");
}
