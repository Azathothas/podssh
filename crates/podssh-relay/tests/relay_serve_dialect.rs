//! The dialect of the reverse road at podssh's relay role (T-643, GitHub
//! #141), on raw sockets, as a client that podssh did not shape would see
//! it: an upgrade that states a dialect that the role does not read
//! (`X-Podssh-Proto`) gets `426` with one sentence that names both and whom
//! to update, and the role's own dialect in `X-Podssh-Proto`, once its token
//! passed; a wrong token gets the `403` of each failed authentication, which
//! says nothing of a dialect; an upgrade that states none is the dialect of
//! before, and joins; and the refusal comes before a pair's `409` and leaves
//! a connect token of `once` unspent.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use podssh_relay::reverse::control;
use role_harness::{next_text, Role, LIMIT};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// An upgrade of `path` with `token` that states `proto`, or none: the
/// answer, read to its end, or its head alone when the role took it (101),
/// and the connection, which a node's socket keeps open while it is held.
async fn upgrade(role: &Role, path: &str, token: &str, proto: Option<&str>) -> (String, TcpStream) {
    let mut tcp = TcpStream::connect(("127.0.0.1", role.relay.port)).await.unwrap();
    let stated = proto.map(|p| format!("X-Podssh-Proto: {p}\r\n")).unwrap_or_default();
    let head = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Relay-Token: {token}\r\n{stated}Upgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tcp.write_all(head.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(LIMIT, tcp.read(&mut chunk)).await.expect("an answer in time").unwrap();
        answer.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&answer).into_owned();
        // A refusal ends the connection; a 101 keeps it, so its head is all.
        if n == 0 || (text.starts_with("HTTP/1.1 101 ") && text.contains("\r\n\r\n")) {
            return (text, tcp);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upgrade_of_another_dialect_gets_426_with_both_once_its_token_passed() {
    let role = Role::start().await;
    let pair = role.pair();
    let node_path = format!("/v1/node/{}", pair.name);
    let (refused, _) = upgrade(&role, &node_path, pair.node_token(), Some("2")).await;
    assert!(refused.starts_with("HTTP/1.1 426 "), "{refused}");
    assert!(refused.contains("\r\nX-Podssh-Proto: 1\r\n"), "the role's own dialect: {refused}");
    assert!(refused.contains("reverse: the node speaks the reverse road's dialect 2"), "{refused}");
    assert!(refused.contains("the relay reads dialect 1"), "{refused}");
    assert!(refused.trim_end().ends_with(": update the relay"), "{refused}");
    // A wrong token, or another role's: each failed authentication looks
    // the same, and says nothing of a dialect.
    for token in ["wrong", pair.connect_token()] {
        let (refused, _) = upgrade(&role, &node_path, token, Some("2")).await;
        assert!(refused.starts_with("HTTP/1.1 403 ") && refused.contains("reverse: forbidden"), "{refused}");
        assert!(!refused.to_ascii_lowercase().contains("x-podssh-proto"), "{refused}");
        assert!(!refused.contains("dialect"), "{refused}");
    }
    // An operator's upgrade alike, with its own words; a value that is no
    // number is no dialect.
    let connect_path = format!("/v1/connect/{}", pair.name);
    let (refused, _) = upgrade(&role, &connect_path, pair.connect_token(), Some("v2")).await;
    assert!(refused.starts_with("HTTP/1.1 426 "), "{refused}");
    assert!(refused.contains("reverse: the operator speaks the reverse road's dialect \"v2\""), "{refused}");
    assert!(refused.trim_end().ends_with(": update the relay or the operator"), "{refused}");
}

/// No header is the dialect of before, as each client of the contract
/// sends its upgrade, and joins; the role's own joins too. The refusal of
/// another dialect comes before the name's `409`, and before a connect
/// token of `once` is spent: that token then takes its one upgrade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_dialect_joins_and_a_refusal_spends_no_token_of_once() {
    let role = Role::start().await;
    let (status, text) = role.http("POST", "/v1/pair?once=1", None).await;
    assert_eq!(status, 200, "{text}");
    let made: Value = serde_json::from_str(&text).unwrap();
    let field = |key: &str| made[key].as_str().expect("a field of the pair").to_string();
    let (name, node_token, connect) = (field("name"), field("node_token"), field("connect_token"));
    let node_path = format!("/v1/node/{name}");
    let (joined, _node) = upgrade(&role, &node_path, &node_token, None).await;
    assert!(joined.starts_with("HTTP/1.1 101 "), "no header is the dialect of before: {joined}");
    let (refused, _) = upgrade(&role, &node_path, &node_token, Some("2")).await;
    assert!(refused.starts_with("HTTP/1.1 426 "), "the dialect before the name: {refused}");
    let (refused, _) = upgrade(&role, &node_path, &node_token, Some("1")).await;
    assert!(refused.starts_with("HTTP/1.1 409 "), "the role's own dialect meets the name: {refused}");
    let (refused, _) = upgrade(&role, &format!("/v1/connect/{name}"), &connect, Some("3")).await;
    assert!(refused.starts_with("HTTP/1.1 426 "), "{refused}");
    // A spent token of `once` gets the 403 of the status too.
    let (status, text) = role.http("GET", &format!("/v1/status/{name}"), Some(connect.as_str())).await;
    assert_eq!(status, 200, "the connect token of once, unspent by the refusal: {text}");
    assert!(text.contains("\"online\":true"), "the node of no header holds its socket: {text}");
    // podssh's operator states the role's dialect, and takes the one upgrade.
    let _operator = role.socket(&format!("/v1/connect/{name}"), &connect).await.expect("the one upgrade of once");
}

/// podssh's own node states the role's dialect, and reads the `hello`'s
/// `version`, which is the role's dialect too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn podssh_s_node_and_the_role_speak_one_dialect() {
    let role = Role::start().await;
    let pair = role.pair();
    let node = role.socket(&format!("/v1/node/{}", pair.name), pair.node_token()).await.expect("the node's socket");
    let hello = next_text(&node).await;
    assert_eq!((hello["type"].as_str(), hello["version"].as_i64()), (Some("hello"), Some(1)), "{hello}");
    let read: control::Hello = serde_json::from_value(hello).expect("the node reads it");
    assert_eq!(control::accept(read.version.as_ref()), Ok(control::PROTO));
}
