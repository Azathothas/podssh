//! The reverse road of podssh's relay role (T-427) against the contract
//! `2026-10-03-r2` (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`),
//! frame by frame: raw sockets speak for a node and an operator, as a client
//! that podssh did not shape would, and each answer is the contract's, as
//! `scripts/fake_reverse.py` and the live relay give it: the statuses of the
//! paths, `hello`, `open`, `ready` before the first byte, a `reject` with
//! its whole reason, the rows of the close table for each fault of a node or
//! of an operator, and a frame in flight for a session just closed (T-421).
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::time::Duration;

use podssh_relay::serve::Mint;
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::ConnectError;
use role_harness::{closed, next, next_text, Role};

/// The node's socket of a new pair, past its `hello`, and the pair.
async fn joined(role: &Role) -> (podssh_relay::pair::Pair, podssh_ws::session::RelaySession<tokio::net::TcpStream>) {
    let pair = role.pair();
    let node = role.socket(&format!("/v1/node/{}", pair.name), pair.node_token()).await.expect("the node's socket");
    let hello = next_text(&node).await;
    assert_eq!(hello["type"], "hello", "{hello}");
    assert_eq!((hello["maxSessions"].as_u64(), hello["maxFrameBytes"].as_u64()), (Some(64), Some(65536)));
    (pair, node)
}

/// An operator's socket on `pair`, and the id that the node was given for
/// its session.
async fn opened(
    role: &Role,
    pair: &podssh_relay::pair::Pair,
    node: &podssh_ws::session::RelaySession<tokio::net::TcpStream>,
) -> (podssh_ws::session::RelaySession<tokio::net::TcpStream>, String) {
    let operator =
        role.socket(&format!("/v1/connect/{}", pair.name), pair.connect_token()).await.expect("the operator's socket");
    let open = next_text(node).await;
    assert_eq!(open["type"], "open", "{open}");
    let id = open["id"].as_str().expect("an id").to_string();
    assert!(id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{id}");
    (operator, id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_paths_answer_with_the_contracts_statuses() {
    let role = Role::start().await;
    let (pair, node) = joined(&role).await;
    let name = pair.name.clone();
    let refused = |r: Result<_, ConnectError>| match r {
        Err(ConnectError::Refused { status, body }) => (status, body),
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the upgrade was taken"),
    };
    let (status, body) = refused(role.socket(&format!("/v1/node/{name}"), pair.connect_token()).await);
    assert_eq!(status, 403, "the operator's token on the node's path");
    assert!(body.contains("reverse: forbidden"), "{body}");
    let (status, _) = refused(role.socket(&format!("/v1/node/{name}"), pair.node_token()).await);
    assert_eq!(status, 409, "a second node of one name, refused before the upgrade");
    assert_eq!(role.http("GET", &format!("/v1/node/{name}"), Some(pair.node_token())).await.0, 426, "no upgrade");
    let (status, body) = role.http("GET", &format!("/v1/status/{name}"), Some(pair.connect_token())).await;
    assert_eq!(status, 200, "{body}");
    let presence: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!((presence["online"].as_bool(), presence["sessions"].as_u64()), (Some(true), Some(0)), "{body}");
    for token in [pair.node_token(), pair.stop_token(), "wrong"] {
        assert_eq!(
            role.http("GET", &format!("/v1/status/{name}"), Some(token)).await.0,
            403,
            "status takes the connect token alone"
        );
    }
    assert_eq!(role.http("GET", "/v1/pair", None).await.0, 405);
    let (status, body) = role.http("POST", "/v1/pair", None).await;
    assert_eq!(status, 200, "{body}");
    let made: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(made["name"].as_str().is_some_and(|n| n.len() == 34) && made["stop_token"].as_str().is_some(), "{body}");

    let (status, body) = role.http("POST", &format!("/v1/stop/{name}"), Some(pair.stop_token())).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"stopped\":true"), "a node was online: {body}");
    assert_eq!(closed(&node).await, (Some(1001), "operator stopped reverse relay".into()));
    for (path, token) in [("status", pair.connect_token()), ("stop", pair.stop_token())] {
        let method = if path == "stop" { "POST" } else { "GET" };
        assert_eq!(role.http(method, &format!("/v1/{path}/{name}"), Some(token)).await.0, 403, "{path} after the stop");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_mints_for_no_one_makes_no_pair() {
    let role = Role::with(Mint::Nobody).await;
    let (status, body) = role.http("POST", "/v1/pair", None).await;
    assert_eq!(status, 503, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_operator_hears_ready_before_the_first_byte_and_the_node_hears_its_end() {
    let role = Role::start().await;
    let (pair, node) = joined(&role).await;
    let (operator, id) = opened(&role, &pair, &node).await;
    // The node's `ready` and its first bytes, back to back.
    node.send_text(&format!(r#"{{"type":"ready","id":"{id}"}}"#)).await.unwrap();
    node.send_binary(&[id.as_bytes(), b"SSH-2.0-banner\r\n"].concat()).await.unwrap();
    let ready = next_text(&operator).await;
    assert_eq!((ready["type"].as_str(), ready["id"].as_str()), (Some("ready"), Some(id.as_str())));
    assert_eq!(
        next(&operator).await,
        Some((OPCODE_BINARY, b"SSH-2.0-banner\r\n".to_vec())),
        "no id on the operator's leg"
    );
    operator.send_binary(b"up").await.unwrap();
    assert_eq!(next(&node).await, Some((OPCODE_BINARY, [id.as_bytes(), b"up"].concat())), "the id before the payload");
    let status = role.http("GET", &format!("/v1/status/{}", pair.name), Some(pair.connect_token())).await.1;
    assert!(status.contains("\"sessions\":1"), "{status}");
    operator.send_close(1000, "").await.unwrap();
    assert_eq!(closed(&operator).await.0, Some(1000), "the role answers the operator's Close");
    let close = next_text(&node).await;
    assert_eq!((close["type"].as_str(), close["id"].as_str()), (Some("close"), Some(id.as_str())), "{close}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reject_reaches_the_operator_whole_and_its_close_cut() {
    let role = Role::start().await;
    let (pair, node) = joined(&role).await;
    let (operator, id) = opened(&role, &pair, &node).await;
    let reason = "no such route here; ".repeat(10);
    let reject = serde_json::json!({ "type": "reject", "id": id, "reason": reason });
    node.send_text(&reject.to_string()).await.unwrap();
    let heard = next_text(&operator).await;
    assert_eq!((heard["type"].as_str(), heard["reason"].as_str()), (Some("reject"), Some(reason.as_str())));
    let (code, why) = closed(&operator).await;
    assert_eq!(code, Some(1011));
    assert!(why.len() <= 123 && reason.starts_with(why.trim_end()), "{why:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operators_text_frame_closes_it_with_1003_and_ends_its_session() {
    let role = Role::start().await;
    let (pair, node) = joined(&role).await;
    let (operator, id) = opened(&role, &pair, &node).await;
    node.send_text(&format!(r#"{{"type":"ready","id":"{id}"}}"#)).await.unwrap();
    assert_eq!(next_text(&operator).await["type"], "ready");
    operator.send_text("hello").await.unwrap();
    assert_eq!(closed(&operator).await, (Some(1003), "binary frames required".into()));
    let close = next_text(&node).await;
    assert_eq!((close["type"].as_str(), close["id"].as_str()), (Some("close"), Some(id.as_str())), "{close}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_fault_of_a_nodes_bytes_gets_its_row_and_its_operators_hear_it() {
    // What the node sends, and the row of the close table that it meets.
    let faults: [(&str, u16, &str); 7] = [
        ("text:not json", 1003, "invalid control json"),
        (r#"text:{"type":"hello","id":"ID"}"#, 1003, "unknown control type"),
        (r#"text:{"type":"ready","id":"ABC"}"#, 1003, "invalid session id"),
        ("binary:short", 1009, "bad multiplex frame"),
        ("binary:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXdata", 1003, "bad multiplex id"),
        ("binary:IDdata", 1003, "data before ready"),
        ("binary:0123456789abcdef0123456789abcdefdata", 1003, "unknown session id"),
    ];
    for (send, code, why) in faults {
        let role = Role::start().await;
        let (pair, node) = joined(&role).await;
        let (operator, id) = opened(&role, &pair, &node).await;
        match send.split_once(':').unwrap() {
            ("text", text) => node.send_text(&text.replace("ID", &id)).await.unwrap(),
            (_, bytes) => node.send_binary(bytes.replacen("ID", &id, 1).as_bytes()).await.unwrap(),
        }
        assert_eq!(closed(&node).await, (Some(code), why.to_string()), "{send}");
        // The relay closed the node for cause: its operator hears that cause.
        assert_eq!(closed(&operator).await, (Some(code), why.to_string()), "{send}, at the operator");
    }
    let role = Role::start().await;
    let (_, node) = joined(&role).await;
    node.send_text(&"x".repeat(5000)).await.unwrap();
    assert_eq!(closed(&node).await, (Some(1009), "control frame byte cap".into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_in_flight_is_dropped_and_an_id_never_given_closes_the_node() {
    let role = Role::start().await;
    let (pair, node) = joined(&role).await;
    let (operator, id) = opened(&role, &pair, &node).await;
    node.send_text(&format!(r#"{{"type":"ready","id":"{id}"}}"#)).await.unwrap();
    assert_eq!(next_text(&operator).await["type"], "ready");
    // The operator's link is lost, with no Close: the node hears of it only
    // from the relay's `close`, and its next frame was on its way.
    drop(operator);
    let close = next_text(&node).await;
    assert_eq!(close["id"].as_str(), Some(id.as_str()), "{close}");
    node.send_binary(&[id.as_bytes(), b"late bytes"].concat()).await.unwrap();
    role.until_said("reverse in flight").await;
    // The node's socket lives: the next session opens on it.
    let (_second, _) = opened(&role, &pair, &node).await;
    assert!(!role.said("reverse node closed"), "{:?}", role.events.lock().unwrap());
    // Past the grace, the same id is one that the relay forgot.
    tokio::time::sleep(Duration::from_millis(2_200)).await;
    node.send_binary(&[id.as_bytes(), b"much later"].concat()).await.unwrap();
    assert_eq!(closed(&node).await, (Some(1003), "unknown session id".into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_that_the_node_never_answers_ends_in_15_s() {
    let role = Role::start().await;
    let (pair, node) = joined(&role).await;
    let (operator, id) = opened(&role, &pair, &node).await;
    let started = std::time::Instant::now();
    assert_eq!(closed(&operator).await, (Some(1013), "node open timeout".into()));
    assert!(started.elapsed() >= Duration::from_secs(14), "{:?}", started.elapsed());
    let close = next_text(&node).await;
    assert_eq!((close["id"].as_str(), close["reason"].as_str()), (Some(id.as_str()), Some("node open timeout")));
    // A `ready` that comes late, in the grace, is dropped as one in flight,
    // and the node's socket goes on.
    node.send_text(&format!(r#"{{"type":"ready","id":"{id}"}}"#)).await.unwrap();
    role.until_said("reverse in flight").await;
    let (_next, _) = opened(&role, &pair, &node).await;
    assert!(!role.said("reverse node closed"), "{:?}", role.events.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operator_with_no_node_is_node_unavailable() {
    let role = Role::start().await;
    let pair = role.pair();
    let operator = role.socket(&format!("/v1/connect/{}", pair.name), pair.connect_token()).await.unwrap();
    assert_eq!(closed(&operator).await, (Some(1011), "node unavailable".into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_planned_stop_closes_each_socket_with_1012() {
    let role = Role::start().await;
    let (pair, node) = joined(&role).await;
    let (operator, id) = opened(&role, &pair, &node).await;
    node.send_text(&format!(r#"{{"type":"ready","id":"{id}"}}"#)).await.unwrap();
    assert_eq!(next_text(&operator).await["type"], "ready");
    assert!(role.cfg.pairs.restart(Duration::from_secs(5)).await, "each Close went out");
    assert_eq!(closed(&operator).await, (Some(1012), "relay restarting".into()));
    assert_eq!(closed(&node).await, (Some(1012), "relay restarting".into()));
    // The pair stays: the node comes back to it, once the role let the old
    // socket go.
    for _ in 0..100 {
        match role.socket(&format!("/v1/node/{}", pair.name), pair.node_token()).await {
            Ok(_) => return,
            Err(ConnectError::Refused { status: 409, .. }) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(other) => panic!("the pair outlives a planned stop: {other}"),
        }
    }
    panic!("the old node's socket was held for 5 s");
}
