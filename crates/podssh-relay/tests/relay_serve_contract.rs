//! The reverse road of podssh's relay role (T-427) against the contract
//! `2026-10-03-r2` (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`),
//! frame by frame: raw sockets speak for a node and an operator, as a client
//! that podssh did not shape would, and each answer is the contract's, as
//! `scripts/fake_reverse.py` and the live relay give it: the statuses of the
//! paths, `hello`, `open`, `ready` before the first byte, a `reject` with
//! its whole reason, the rows of the close table for each fault of a node or
//! of an operator, and a frame in flight for a session just closed (T-421).
//! And its forward road through its host's proxy (T-457), a stand-in proxy
//! of the test's: a target reached by the CONNECT of its checked address, or
//! of its name where nothing is checked; the proxy's refusal as the role's
//! `502` with its status; `/trace` with the proxy's leg. And the forward
//! road's half-close (T-671): a target's answer after the client's Close
//! reaches the client, then the role's Close says how the target ended.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::time::Duration;

use podssh_relay::serve::egress::Egress;
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Limits, Mint};
use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use podssh_ws::ConnectError;
use role_harness::proxy::{self, StandIn};
use role_harness::{closed, next, next_text, Role, LIMIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

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
    // The stop waits for each peer's answer to its Close (T-255), which a
    // read of the Close gives.
    let stop = role.cfg.pairs.restart(Duration::from_secs(5));
    let (stopped, operator_saw, node_saw) = tokio::join!(stop, closed(&operator), closed(&node));
    assert!(stopped, "each Close went out, and each peer answered it");
    assert_eq!(operator_saw, (Some(1012), "relay restarting".into()));
    assert_eq!(node_saw, (Some(1012), "relay restarting".into()));
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

/// What a target of the test's says first, through the proxy or not.
const GREETING: &[u8] = b"SSH-2.0-through-the-proxy\r\n";

/// The role, its targets through a stand-in proxy that answers `status`
/// and carries each tunnel to a target of the test's; with private targets
/// when `private`, and the proxy's `userinfo` in its URL. The role, the
/// proxy, a token of the role's, and the target's port.
async fn through(status: &'static str, private: bool, userinfo: &str) -> (Role, StandIn, String, u16) {
    let target = proxy::greeting("SSH-2.0-through-the-proxy\r\n").await;
    let stand_in = StandIn::start(status, target).await;
    let url = stand_in.url(userinfo);
    let egress = Egress::from_vars(|name| (name == "HTTPS_PROXY").then(|| url.clone())).expect("the proxy's URL");
    let role = Role::configured(Mint::Anyone, Policy { private, ..Policy::default() }, egress).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    (role, stand_in, token, target)
}

/// The answer of a refused upgrade: its status and body.
fn refusal(r: Result<podssh_ws::session::RelaySession<tokio::net::TcpStream>, ConnectError>) -> (u16, String) {
    match r {
        Err(ConnectError::Refused { status, body }) => (status, body),
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the upgrade was taken"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_goes_through_the_hosts_proxy_by_its_checked_address_or_by_its_name_where_nothing_is_checked() {
    let (role, stand_in, token, target) = through("200 Connection Established", true, "").await;
    // Nothing is checked: the name goes as it came, for the proxy to resolve.
    let named = role.socket("/connect/target.invalid/22", &token).await;
    let named = named.expect("the name goes to the proxy, which reached the target");
    assert_eq!(next(&named).await, Some((OPCODE_BINARY, GREETING.to_vec())));
    let by_address = role.socket("/connect/10.255.255.1/22", &token).await.expect("an address through the proxy");
    assert_eq!(next(&by_address).await, Some((OPCODE_BINARY, GREETING.to_vec())));
    // `?dial=lazy`: the CONNECT once the client's first bytes came.
    let lazy = role.socket("/connect/2001:db8::7/22?dial=lazy", &token).await.expect("a lazy dial");
    lazy.send_binary(b"first").await.unwrap();
    assert_eq!(next(&lazy).await, Some((OPCODE_BINARY, GREETING.to_vec())));
    // `/trace` names the proxy's leg by its kind, never where the proxy is.
    let (status, body) = role.http("GET", "/trace?target=10.255.255.1:22", Some(token.as_str())).await;
    assert_eq!(status, 200, "{body}");
    let traced: serde_json::Value = serde_json::from_str(&body).unwrap();
    let leg = &traced["target"];
    assert_eq!((leg["road"].as_str(), leg["proxy"].as_str()), (Some("proxy"), Some("http")), "{body}");
    assert_eq!((leg["dialed"].as_str(), leg["address_family"].as_str()), (Some("10.255.255.1"), Some("4")), "{body}");
    assert_eq!(leg["banner"].as_str(), Some("SSH-2.0-through-the-proxy"), "{body}");
    assert!(!body.contains(&format!("127.0.0.1:{}", stand_in.port)), "{body}");
    let asked = [
        "CONNECT target.invalid:22 HTTP/1.1",
        "CONNECT 10.255.255.1:22 HTTP/1.1",
        "CONNECT [2001:db8::7]:22 HTTP/1.1",
        "CONNECT 10.255.255.1:22 HTTP/1.1",
    ];
    assert_eq!(stand_in.asked(), asked);
    // The loopback goes directly: no proxy reaches this host's.
    let local = role.socket(&format!("/connect/127.0.0.1/{target}"), &token).await.expect("the loopback");
    assert_eq!(next(&local).await, Some((OPCODE_BINARY, GREETING.to_vec())));
    assert_eq!(stand_in.asked().len(), asked.len(), "the loopback through the proxy");

    // The default policy: a public address, checked, is what the proxy is
    // asked for, never a name that the proxy could resolve otherwise.
    let (role, stand_in, token, _) = through("200 Connection Established", false, "").await;
    let public = role.socket("/connect/140.82.112.3/22", &token).await.expect("a public address through the proxy");
    assert_eq!(next(&public).await, Some((OPCODE_BINARY, GREETING.to_vec())));
    assert_eq!(stand_in.asked(), ["CONNECT 140.82.112.3:22 HTTP/1.1"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_proxys_refusal_is_the_roles_502_with_its_status_and_never_its_place_or_credentials() {
    let (role, stand_in, token, _) = through("403 Forbidden", true, "relayuser:s3cret-word@").await;
    let (status, body) = refusal(role.socket("/connect/target.invalid/22", &token).await);
    assert_eq!(status, 502, "{body}");
    assert!(body.contains("refused CONNECT target.invalid:22: 403 Forbidden"), "{body}");
    let at = format!("127.0.0.1:{}", stand_in.port);
    assert!(!body.contains(&at) && !body.contains("s3cret") && !body.contains("relayuser"), "{body}");
    // The owner's line names the proxy, never its credentials.
    role.until_said("proxy: the proxy").await;
    let events = role.events.lock().unwrap().join("\n");
    assert!(events.contains(&format!("the proxy {at} refused CONNECT target.invalid:22: 403")), "{events}");
    assert!(!events.contains("s3cret") && !events.contains("relayuser"), "{events}");
    // The proxy had them, as HTTP Basic.
    use base64::Engine as _;
    let basic = base64::engine::general_purpose::STANDARD.encode("relayuser:s3cret-word");
    let heads = stand_in.heads();
    assert!(heads[0].contains(&format!("Proxy-Authorization: Basic {basic}\r\n")), "{heads:?}");
    // `/trace` says the proxy's refusal as it is.
    let (status, body) = role.http("GET", "/trace?target=target.invalid:22", Some(token.as_str())).await;
    assert_eq!(status, 200, "{body}");
    let traced: serde_json::Value = serde_json::from_str(&body).unwrap();
    let error = traced["target"]["error"].as_str().unwrap_or_default();
    assert!(error.contains("403 Forbidden") && !error.contains(&at), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_that_the_policy_refuses_is_refused_before_any_connect() {
    let (role, stand_in, token, _) = through("200 Connection Established", false, "").await;
    for path in ["/connect/10.255.255.1/22", "/connect/127.0.0.1/22", "/connect/140.82.112.3/25"] {
        let (status, body) = refusal(role.socket(path, &token).await);
        assert_eq!(status, 403, "{path}: {body}");
        assert!(body.contains("not in the ALLOW list"), "{path}: {body}");
    }
    assert!(stand_in.asked().is_empty(), "the proxy was asked: {:?}", stand_in.asked());
}

// GitHub #126: a name that does not resolve and one that resolves into the
// role's own network get one answer, which names no address, so that a
// holder of a token cannot map the role's network by names; the operator's
// line keeps the cause.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_that_does_not_resolve_and_one_that_the_policy_refuses_answer_the_same() {
    let (role, stand_in, token, _) = through("200 Connection Established", false, "").await;
    let mut bodies = Vec::new();
    for (host, family) in [("localhost", ""), ("no-such-name.invalid", ""), ("140.82.112.3", "?family=6")] {
        let (status, body) = refusal(role.socket(&format!("/connect/{host}/22{family}"), &token).await);
        assert_eq!(status, 403, "{host}: {body}");
        assert!(
            !body.contains("127.0.0.1") && !body.contains("::1") && !body.contains("not a public address"),
            "{body}"
        );
        bodies.push(body.replace(host, "TARGET"));
        // `/trace` asks no family: the public literal would be dialed.
        if family.is_empty() {
            let (status, trace) = role.http("GET", &format!("/trace?target={host}:22"), Some(token.as_str())).await;
            assert!(
                status == 200 && !trace.contains("127.0.0.1") && !trace.contains("not a public address"),
                "{trace}"
            );
        }
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    assert!(bodies[0].contains("not in the ALLOW list"), "{bodies:?}");
    let events = role.events.lock().unwrap().clone();
    assert!(
        role.said("refused localhost:22: it resolves to") && role.said("refused no-such-name.invalid:22: no address"),
        "{events:?}"
    );
    assert!(stand_in.asked().is_empty(), "the proxy was asked: {:?}", stand_in.asked());
}

/// A target on the loopback that reads its one client's input to its end,
/// then answers `delay` later with the count of the bytes that it took; with
/// `closes` it then closes, else it holds the connection and says nothing.
async fn late_target(delay: Duration, closes: bool) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else { return };
        let mut input = Vec::new();
        let _ = tcp.read_to_end(&mut input).await;
        tokio::time::sleep(delay).await;
        let _ = tcp.write_all(format!("took {} bytes", input.len()).as_bytes()).await;
        if closes {
            let _ = tcp.shutdown().await;
        } else {
            tokio::time::sleep(LIMIT).await;
        }
    });
    port
}

/// The role, which dials the loopback and ends a half-closed session after
/// `half_closed` of its target's silence, and a forward session to `port`.
async fn forward_to(port: u16, half_closed: Duration) -> (Role, RelaySession<TcpStream>) {
    let limits = Limits { half_closed, ..Limits::default() };
    let role = Role::limited(Policy { private: true, ..Policy::default() }, limits).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let session = role.socket(&format!("/connect/127.0.0.1/{port}"), &token).await.expect("a forward session");
    (role, session)
}

/// What came after this side's Close: the payload, and the peer's Close.
async fn after_close(socket: &RelaySession<TcpStream>) -> (Vec<u8>, (Option<u16>, String)) {
    let mut payload = Vec::new();
    loop {
        match next(socket).await {
            Some((OPCODE_BINARY, bytes)) => payload.extend_from_slice(&bytes),
            Some((OPCODE_CLOSE, close)) => return (payload, close_code_and_reason(&close)),
            Some(_) => {}
            None => return (payload, (None, "no Close".into())),
        }
    }
}

/// T-671: a WebSocket Close is no TCP half-close, but the contract carries
/// the target's bytes after it (`docs/relay.md`, "The forward path"): a
/// target that reads to the end of its input answers 500 ms later, the
/// answer reaches the client after its Close, and the role's Close says
/// that the target closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_targets_answer_after_the_clients_close_reaches_the_client() {
    let port = late_target(Duration::from_millis(500), true).await;
    let (_role, client) = forward_to(port, Limits::default().half_closed).await;
    client.send_binary(b"the question").await.unwrap();
    client.send_close(1000, "").await.unwrap();
    let sent = Instant::now();
    let (answer, close) = after_close(&client).await;
    assert_eq!(String::from_utf8_lossy(&answer), "took 12 bytes", "the target's answer, after the Close");
    assert_eq!(close, (Some(1000), "target closed".to_string()));
    assert!(sent.elapsed() >= Duration::from_millis(400), "the answer came after the end of the input");
}

/// T-671: a target that answers, then says nothing and holds its connection,
/// ends the session once it was silent for the role's limit after its last
/// byte, not after the Close: `1000 client half-closed, target idle for
/// 15s` on the contract's 15 s, here 1 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_target_after_the_clients_close_ends_the_session_in_the_contracts_words() {
    let port = late_target(Duration::from_millis(600), false).await;
    let (_role, client) = forward_to(port, Duration::from_secs(1)).await;
    client.send_binary(b"ask").await.unwrap();
    client.send_close(1000, "").await.unwrap();
    let sent = Instant::now();
    let (answer, close) = after_close(&client).await;
    assert_eq!(String::from_utf8_lossy(&answer), "took 3 bytes", "the target's answer, after the Close");
    assert_eq!(close, (Some(1000), "client half-closed, target idle for 1s".to_string()));
    // 0.6 s to the answer, then 1 s of silence.
    assert!(sent.elapsed() >= Duration::from_millis(1500), "silent since its last byte: {:?}", sent.elapsed());
}
