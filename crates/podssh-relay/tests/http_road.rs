//! The HTTP road (T-319) against podssh's relay role on the loopback
//! (`role_harness`): a session carries 20 MiB each way to an echo, with equal
//! digests, in the split form and in the serial form, straight to the role
//! (kept connections, answers in chunks) and through a stand-in of a proxy
//! that ends TLS (`http_road_harness`): one request on each connection, each
//! body and each answer held to its end, and the upgrade refused. Through the
//! same stand-in, losing the answer of each third batch and cutting each third
//! answer down, a session still carries each byte once, in order: the
//! batches' numbers and the offsets down make each request one that may come
//! twice. With no form asked, the split form opens. OpenSSH's sshd, where
//! this host has one, says its version line through the road. A wrong key and
//! an unknown session get the same 404, the open takes the forward token and
//! the forward road's policy, and an ended session says why.
//!
//!     cargo test -p podssh-relay --features serve,plain-ws --test http_road
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod http_road_harness;
mod role_harness;

use http_road_harness::{each_way, echo_target, open, raw, road, sshd, Faults, Proxy, MIB};
use podssh_relay::http_road::client::End;
use podssh_relay::http_road::Form;
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Mint};
use role_harness::Role;
use tokio::io::AsyncReadExt;

/// The role, which dials the loopback, and a token of its own.
async fn role() -> (Role, String) {
    let role = Role::configured(Mint::Anyone, Policy { private: true, ..Policy::default() }, Default::default()).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    (role, token)
}

/// The end of a session whose target ended after the client's last byte.
fn target_closed() -> Option<End> {
    Some(End::Closed { code: 1000, reason: "target closed".into() })
}

/// The stand-in that holds each body and each answer to its end.
fn holding() -> Faults {
    Faults { hold_answers: true, ..Faults::default() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_split_form_carries_20_mib_each_way_straight_to_the_role() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let opened = open(&road(role.relay.port, "127.0.0.1"), target, &token, Some(Form::Split)).await;
    assert_eq!(opened.form, Form::Split);
    assert_eq!(each_way(opened, b"", 20 * MIB, 1).await, target_closed());
    assert!(role.said("http open") && role.said("http close 1000"), "{:?}", role.events.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_serial_form_carries_20_mib_each_way_straight_to_the_role() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let opened = open(&road(role.relay.port, "127.0.0.1"), target, &token, Some(Form::Serial)).await;
    assert_eq!(opened.form, Form::Serial);
    assert_eq!(each_way(opened, b"", 20 * MIB, 2).await, target_closed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_split_form_carries_20_mib_each_way_through_a_proxy_that_holds_bodies_and_answers() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let proxy = Proxy::start(role.relay.port, holding()).await;
    let opened = open(&road(proxy.port, "127.0.0.1"), target, &token, Some(Form::Split)).await;
    assert_eq!(each_way(opened, b"", 20 * MIB, 3).await, target_closed());
    assert!(proxy.count(|c| &c.requests) > 2, "each request on a connection of its own");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_serial_form_carries_20_mib_each_way_through_a_proxy_that_holds_bodies_and_answers() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let proxy = Proxy::start(role.relay.port, holding()).await;
    let opened = open(&road(proxy.port, "127.0.0.1"), target, &token, Some(Form::Serial)).await;
    assert_eq!(each_way(opened, b"", 20 * MIB, 4).await, target_closed());
}

/// The answers that the stand-in lost and cut came again: no byte twice,
/// none lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_byte_comes_once_where_a_proxy_loses_answers_of_batches_and_cuts_answers_down() {
    for (form, seed) in [(Form::Split, 5), (Form::Serial, 6)] {
        let (role, token) = role().await;
        let target = echo_target(b"").await;
        let faults = Faults { hold_answers: true, lose_batches: Some(3), cut_answers: Some(3) };
        let proxy = Proxy::start(role.relay.port, faults).await;
        let opened = open(&road(proxy.port, "127.0.0.1"), target, &token, Some(form)).await;
        assert_eq!(each_way(opened, b"", 4 * MIB, seed).await, target_closed(), "{form:?}");
        assert!(proxy.count(|c| &c.lost) > 0 && proxy.count(|c| &c.cut) > 0, "{form:?}: the faults came");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_no_form_asked_the_split_form_opens_through_the_proxy() {
    let (role, token) = role().await;
    let target = echo_target(b"").await;
    let proxy = Proxy::start(role.relay.port, holding()).await;
    let opened = open(&road(proxy.port, "127.0.0.1"), target, &token, None).await;
    assert_eq!(opened.form, Form::Split);
    assert_eq!(each_way(opened, b"", MIB, 7).await, target_closed());
}

/// sshd, software that podssh did not write, as the target: its version
/// line comes first through the road and the stand-in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_s_sshd_says_its_version_line_through_the_road() {
    let server = match sshd("version") {
        Ok(server) => server,
        Err(why) => return eprintln!("did not run: {why}"),
    };
    let (role, token) = role().await;
    let proxy = Proxy::start(role.relay.port, holding()).await;
    for form in [Form::Split, Form::Serial] {
        let mut opened = open(&road(proxy.port, "127.0.0.1"), server.port, &token, Some(form)).await;
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\n") && line.len() < 256 {
            let read = tokio::time::timeout(http_road_harness::LIMIT, opened.stream.read(&mut byte)).await;
            match read.expect("the version line in time").expect("the version line") {
                0 => break,
                _ => line.push(byte[0]),
            }
        }
        let line = String::from_utf8_lossy(&line).into_owned();
        assert!(line.starts_with("SSH-2.0-OpenSSH"), "{form:?}: {line:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_open_takes_the_token_and_the_policy_and_a_session_its_key() {
    let (role, token) = role().await;
    let port = role.relay.port;
    let target = echo_target(b"hello\n").await;
    let ask = |method: &str, path: &str, headers: &str| {
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Content-Length: 0\r\nConnection: close\r\n\r\n")
    };
    let open_path = format!("/v1/http/open/127.0.0.1/{target}");
    let (status, text) = raw(port, &ask("POST", &open_path, "")).await;
    assert_eq!(status, 403, "{text}");
    assert!(text.contains("http: missing or wrong token"), "{text}");
    let minted = format!("X-Relay-Token: {token}\r\n");
    let (status, text) = raw(port, &ask("POST", "/v1/http/open/127.0.0.1/25", &minted)).await;
    assert_eq!(status, 403, "{text}");
    assert!(text.contains("not in the ALLOW list"), "the forward road's policy: {text}");
    let (status, text) = raw(port, &ask("POST", &open_path, &minted)).await;
    assert_eq!(status, 200, "{text}");
    let doc: serde_json::Value = serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
    let (id, key) = (doc["session"].as_str().unwrap(), doc["key"].as_str().unwrap());
    assert_eq!(doc["batch_max"], 256 * 1024, "{doc}");
    let down = format!("/v1/http/s/{id}/down?at=0&wait=0");
    let wrong = "X-Session-Key: abcdefghijklmnopqrstuvwxyzABCDEFGHIJ-_01234\r\n";
    let (status, unknown) = raw(port, &ask("GET", &down, wrong)).await;
    assert_eq!(status, 404, "a wrong key: {unknown}");
    let (status, none) = raw(port, &ask("GET", &down, "")).await;
    assert_eq!(status, 404, "no key: {none}");
    let other = format!("/v1/http/s/{}/down?at=0", "0".repeat(32));
    let (status, other) = raw(port, &ask("GET", &other, &format!("X-Session-Key: {key}\r\n"))).await;
    assert_eq!(status, 404, "an unknown session: {other}");
    assert_eq!(unknown.split_once("\r\n\r\n").map(|(_, b)| b), other.split_once("\r\n\r\n").map(|(_, b)| b));
    let mine = format!("X-Session-Key: {key}\r\n");
    let (status, text) = raw(port, &ask("GET", &format!("/v1/http/s/{id}/down?at=0&wait=5000"), &mine)).await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("X-Offset: 0\r\n") && text.ends_with("hello\n"), "{text}");
    let (status, text) = raw(port, &ask("POST", &format!("/v1/http/s/{id}/close"), &mine)).await;
    assert_eq!(status, 204, "{text}");
    let (status, text) = raw(port, &ask("GET", &format!("/v1/http/s/{id}/down?at=6"), &mine)).await;
    assert_eq!(status, 410, "{text}");
    assert!(text.contains("X-Close: 1000 client closed\r\n"), "{text}");
}

/// The stand-in's refusal of an upgrade is a proxy's page, which the probe
/// of the Piping Server road tells from the relay's own word: the cue of
/// this road.
#[cfg(feature = "piping")]
#[tokio::test]
async fn the_proxy_s_refusal_of_the_upgrade_is_the_way_s() {
    let proxy = Proxy::start(1, holding()).await;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port)).await.expect("the stand-in");
    let key = podssh_ws::handshake::generate_key().expect("a key");
    let request = format!(
        "GET /connect/github.com/22 HTTP/1.1\r\nHost: relay.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let refused = podssh_ws::client::upgrade_with(tcp, request.as_bytes(), &key).await.expect_err("refused");
    assert!(
        matches!(
            &refused,
            podssh_ws::ConnectError::Refused { status: 403, body } if body.contains(http_road_harness::REFUSAL)
        ),
        "{refused}"
    );
    assert!(podssh_relay::piping::probe::upgrade_refused(&refused));
}
