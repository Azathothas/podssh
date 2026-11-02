//! The relay role behind a quick tunnel's node (T-428), through the stand-in
//! edge of T-300 and its front (`quick_relay_harness`): a client that takes
//! the tunnel's name for its relay host mints a token with its key, as
//! `--mint keys:FILE` asks (T-448), and reads a target's first line through
//! the role, the node and the edge; the role's documents answer there; the
//! node's own paths stay its own, and with no TARGET each path is the
//! role's; podssh's own node and operator of the reverse road meet through
//! it. The planted node that keeps its 404 for the relay's paths fails the
//! first test (`scripts/plants/t428-keeps-404.patch`).
#![cfg(all(feature = "quick", feature = "serve", feature = "plain-ws"))]

mod quick_harness;
mod quick_relay_harness;

use std::sync::Arc;

use podssh_relay::identity::Identity;
use podssh_relay::pair::{self, Pair};
use podssh_relay::quick::serve::Step;
use podssh_relay::relay::Relay;
use podssh_relay::reverse::{self, operator, Exit, Handler, NodeConfig, Opening, OperatorConfig, OperatorLimits};
use podssh_relay::reverse::{SessionId, Settings, Wire};
use podssh_relay::serve::Mint;
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::{ProxyChoice, Trust};
use quick_relay_harness::{banner_target, http, list_of, Tunnel, BANNER, LIMIT, NAME};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;

/// The token of a mint through the tunnel, by the key of `seed`: the
/// contract's `{}` first, then the key's proof of the role's challenge,
/// signed for the tunnel's name, which the request names as its Host.
async fn mint(tunnel: &Tunnel, seed: u8) -> Result<String, (u16, String)> {
    let (status, body) = http(tunnel.port, "POST", "/v1/mint", NAME, b"{}").await;
    if status != 401 {
        return Err((status, body));
    }
    let asked: serde_json::Value = serde_json::from_str(&body).expect("the challenge's JSON");
    let challenge = asked["challenge"].as_str().expect("a challenge");
    let proof = podssh_relay::keyed::proof(&Identity::from_seed(&[seed; 32]), NAME, "/v1/mint", challenge);
    let (status, body) = http(tunnel.port, "POST", "/v1/mint", NAME, &proof).await;
    if status != 200 {
        return Err((status, body));
    }
    let minted: serde_json::Value = serde_json::from_str(&body).expect("the token's JSON");
    Ok(minted["token"].as_str().expect("a token").to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_with_the_tunnel_s_name_reads_a_target_s_first_line_through_the_role() {
    // The list's guard lives to the test's end: the role reads it at each proof.
    let list = list_of(1, "banner");
    let tunnel = Tunnel::start(Mint::Keys(list.path.clone()), false).await;
    // A key that is not on the list gets the role's 403, which names it.
    let (status, body) = mint(&tunnel, 2).await.expect_err("a key off the list");
    assert_eq!(status, 403, "{body}");
    assert!(body.contains(&Identity::from_seed(&[2; 32]).public().fingerprint()), "{body}");
    let token = mint(&tunnel, 1).await.expect("a token for the listed key");
    let target = banner_target().await;
    let path = format!("/connect/127.0.0.1/{target}");
    let session = podssh_ws::plain::connect_loopback("127.0.0.1", tunnel.port, &path, &token, LIMIT, None)
        .await
        .expect("the role took the upgrade through the tunnel");
    let mut got = Vec::new();
    while got.len() < BANNER.len() {
        let frame = tokio::time::timeout(LIMIT, session.read_frame()).await.expect("a frame in time").unwrap();
        assert_eq!(frame.opcode, OPCODE_BINARY);
        got.extend_from_slice(&frame.payload);
    }
    assert_eq!(got, BANNER, "the target's first line, through the role, the node and the edge");
    // And back: the target echoes what goes up.
    session.send_binary(b"SSH-2.0-podssh_t428\r\n").await.unwrap();
    let mut echoed = Vec::new();
    while echoed.len() < 21 {
        let frame = tokio::time::timeout(LIMIT, session.read_frame()).await.expect("a frame in time").unwrap();
        echoed.extend_from_slice(&frame.payload);
    }
    assert_eq!(echoed, b"SSH-2.0-podssh_t428\r\n");
    assert!(tunnel.said("/v1/mint: the key") && tunnel.said("upgrade"), "{:?}", tunnel.events.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_role_s_documents_answer_and_the_node_s_paths_stay_its_own() {
    let mut tunnel = Tunnel::start(Mint::Anyone, false).await;
    let (status, body) = http(tunnel.port, "GET", "/health", NAME, b"").await;
    assert_eq!(status, 200, "{body}");
    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!((health["contract"].as_str(), health["mint"].as_str()), (Some("2026-10-03-r2"), Some("anyone")));
    let (status, body) = http(tunnel.port, "GET", "/relays.json?host=github.com&port=22", NAME, b"").await;
    assert_eq!(status, 200, "{body}");
    let relays: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(relays["pool"][0]["host"], NAME, "the tunnel's name is the relay host");
    assert_eq!(relays["connect"], format!("wss://{NAME}/connect/github.com/22"));
    // The node's own paths: a request that is no visitor's gets its 404,
    // and a visitor's WebSocket at / reaches TARGET as before.
    let (status, body) = http(tunnel.port, "GET", "/", NAME, b"").await;
    assert_eq!((status, body.as_str()), (404, ""), "the node's 404, with no body");
    let visitor = podssh_ws::plain::connect_loopback("127.0.0.1", tunnel.port, "/", "unused", LIMIT, None)
        .await
        .expect("a visitor's WebSocket");
    let step = tokio::time::timeout(LIMIT, tunnel.steps.recv()).await.expect("a step in time");
    assert_eq!(step, Some(Step::Visitor));
    visitor.send_binary(b"to the node's TARGET").await.unwrap();
    let echoed = tokio::time::timeout(LIMIT, visitor.read_frame()).await.expect("in time").unwrap();
    assert_eq!(echoed.payload, b"to the node's TARGET");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_target_each_path_is_the_role_s() {
    let tunnel = Tunnel::start(Mint::Nobody, true).await;
    let (status, body) = http(tunnel.port, "GET", "/", NAME, b"").await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("/: not found"), "the role's 404, not the node's: {body}");
    let refused = podssh_ws::plain::connect_loopback("127.0.0.1", tunnel.port, "/", "unused", LIMIT, None).await;
    assert!(matches!(refused, Err(podssh_ws::ConnectError::Refused { status: 404, .. })), "{:?}", refused.err());
    let (status, body) = http(tunnel.port, "POST", "/v1/mint", NAME, b"{}").await;
    assert_eq!(status, 503, "--mint nobody: {body}");
}

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

/// Each session of the node echoes what it takes.
struct Echo;

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(256 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(ours)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_and_an_operator_of_podssh_meet_through_the_role_behind_the_tunnel() {
    let tunnel = Tunnel::start(Mint::Anyone, true).await;
    let relay = Relay { host: "127.0.0.1".into(), port: tunnel.port };
    let now = podssh_relay::serve::tokens::now_ms();
    let made = tunnel.cfg.pairs.make(now).expect("a pair");
    let body = serde_json::json!({
        "name": made.name, "node_token": made.node, "connect_token": made.connect,
        "stop_token": made.stop, "expires": made.expires_ms,
    });
    let pair: Pair = pair::parse(&relay, body.to_string().as_bytes(), now as i64).expect("the role's pair");
    let (name, token) = (pair.name.clone(), pair.connect_token().to_string());
    let (stop, stopped) = oneshot::channel::<()>();
    let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
    let node = async {
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
        reverse::run(&mut config, Arc::new(Echo), async {
            let _ = stopped.await;
        })
        .await
    };
    let operate = async {
        let deadline = std::time::Instant::now() + LIMIT;
        while !tunnel.said("reverse node") {
            assert!(std::time::Instant::now() < deadline, "{:?}", tunnel.events.lock().unwrap());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let config = OperatorConfig {
            relay: &relay,
            name: &name,
            connect_token: &token,
            trust: &trust,
            proxy: &proxy,
            timeout: LIMIT,
            limits: OperatorLimits::default(),
            wire: Wire::PlainLoopback,
        };
        let sent = pattern(1 << 20, 4);
        let (app, leg) = tokio::io::duplex(64 * 1024);
        let (mut r, mut w) = tokio::io::split(app);
        let carry = async {
            let writing = async {
                w.write_all(&sent).await.unwrap();
                w
            };
            let mut got = Vec::new();
            let reading = async {
                let mut buf = vec![0u8; 16 * 1024];
                while got.len() < sent.len() {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
            };
            let (mut w, ()) = tokio::join!(writing, reading);
            let _ = w.shutdown().await;
            got
        };
        let (outcome, got) = tokio::join!(operator::run(&config, leg), carry);
        let _ = stop.send(());
        (outcome, got, sent)
    };
    let ((outcome, got, sent), exit) =
        tokio::time::timeout(4 * LIMIT, async { tokio::join!(operate, node) }).await.expect("in time");
    assert_eq!(Sha256::digest(&got), Sha256::digest(&sent), "1 MiB each way through the tunnel: {outcome:?}");
    assert!(outcome.expect("the operator's socket").is_success());
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
}
