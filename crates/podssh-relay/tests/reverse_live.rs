//! The node runner against the live relay (T-079), on request only:
//! `cargo test -p podssh-relay --features pair --test reverse_live -- --ignored`.
//! It makes a pair, runs an echo node, opens two operator sessions at once,
//! sends 1 MiB on each and compares what comes back, then stops the node and
//! the pair. It prints no token. The operator here is a few lines over
//! `podssh_ws::connect`; the operator runner is T-080.
#![cfg(feature = "pair")]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::pair::{self, Pair, PairContext};
use podssh_relay::relay::{Relay, DEFAULT_RELAY_HOST};
use podssh_relay::reverse::{run, Exit, Handler, NodeConfig, Opening, Settings};
use podssh_transport::{LegTarget, SessionId};
use podssh_ws::client::{connect, Endpoint, WsClientConfig};
use podssh_ws::{frame, ProxyChoice, Trust};
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

/// An operator's session: wait for `ready`, send `payload` in frames of
/// 64 KiB, and read until as many bytes came back.
async fn operator(pair: &Pair, payload: Vec<u8>) -> Vec<u8> {
    let path = (LegTarget::ReverseOperator { name: pair.name.clone() }).path().unwrap();
    let ws = WsClientConfig {
        endpoint: Endpoint { host: pair.relay.host.clone(), port: pair.relay.port, path },
        trust: Trust::Default,
        server_name: pair.relay.host.clone(),
        timeout: LIMIT,
        idle_timeout: Some(LIMIT),
        proxy: ProxyChoice::FromEnvironment,
    };
    let session = Arc::new(connect(&ws, pair.connect_token()).await.expect("the operator's socket"));
    let ready = session.read_frame().await.expect("ready");
    assert_eq!(ready.opcode, frame::OPCODE_TEXT);
    assert!(String::from_utf8_lossy(&ready.payload).contains(r#""type":"ready""#));
    let sender = {
        let session = session.clone();
        let total = payload.len();
        tokio::spawn(async move {
            for chunk in payload.chunks(64 * 1024) {
                session.send_binary(chunk).await.expect("a send");
            }
            total
        })
    };
    let mut got = Vec::new();
    while got.len() < MIB {
        let f = tokio::time::timeout(LIMIT, session.read_frame()).await.expect("data in time").expect("a frame");
        assert_eq!(f.opcode, frame::OPCODE_BINARY, "{f:?}");
        got.extend_from_slice(&f.payload);
    }
    assert_eq!(sender.await.unwrap(), MIB);
    let _ = session.send_close(1000, "").await;
    got
}

fn pattern(seed: u8) -> Vec<u8> {
    (0..MIB).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "the live relay: run with --ignored"]
async fn node_serves_two_sessions_at_once() {
    let relay = Relay { host: DEFAULT_RELAY_HOST.into(), port: 443 };
    let ctx = PairContext { relay: &relay, trust: &Trust::Default, proxy: &ProxyChoice::FromEnvironment, timeout: LIMIT };
    let made = pair::create(&ctx).await.expect("a pair");
    let operator_pair = pair::parse(&relay, &body_of(&made), now_ms()).expect("the same pair");

    let stop = Arc::new(Notify::new());
    let stopper = stop.clone();
    let node = tokio::spawn(async move {
        let config = NodeConfig {
            pair: made,
            label: None,
            trust: &Trust::Default,
            proxy: &ProxyChoice::FromEnvironment,
            timeout: LIMIT,
            settings: Settings::default(),
            repair: None,
        };
        run(config, Arc::new(Echo), async move { stopper.notified().await }).await
    });
    tokio::time::sleep(Duration::from_secs(2)).await;

    let (one, two) = tokio::join!(operator(&operator_pair, pattern(1)), operator(&operator_pair, pattern(2)));
    assert!(one == pattern(1), "the first session's bytes came back changed");
    assert!(two == pattern(2), "the second session's bytes came back changed");
    eprintln!("two sessions, 1 MiB each way, came back whole");

    stop.notify_one();
    let exit = tokio::time::timeout(LIMIT, node).await.expect("the node stops").unwrap();
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
    let stopped = pair::stop(&ctx, &operator_pair).await.expect("the pair stops");
    eprintln!("node: {exit:?}; pair: {stopped:?}");
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
