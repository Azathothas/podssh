//! A grant used once through the live relay (T-226), on request only:
//! `cargo test -p podssh-relay --features pair,grant --test grant_live --
//! --ignored`. A node of a pair of the live relay, whose allowlist names
//! nobody, lets in one session of a grant that its own key signed for the
//! operator's key, then refuses that grant; the relay carries the channel,
//! and sees neither the grant nor a byte. No test prints a token.
#![cfg(all(feature = "pair", feature = "grant"))]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends::{self, GRANT_REFUSED};
use podssh_relay::e2e::{self, Ask, Refusal};
use podssh_relay::grant::{self, Door, Mint, Spent};
use podssh_relay::identity::{Identity, PublicKey};
use podssh_relay::pair::{self, Pair, PairContext};
use podssh_relay::relay::{default_relay_host, Relay};
use podssh_relay::reverse::{operator, run, E2e, Handler, NodeConfig, Opening, OperatorConfig, OperatorLimits};
use podssh_relay::reverse::{Outcome, SessionId, Settings, Wire};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

const LIMIT: Duration = Duration::from_secs(30);

/// Each session echoes its bytes.
struct Echo;

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async {
            let (node_end, mut echo_end) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = echo_end.read(&mut buf).await {
                    if n == 0 || echo_end.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = echo_end.shutdown().await;
            });
            Ok(node_end)
        })
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// The pair as a body of `/v1/pair`, to give the operator its own copy.
fn body_of(pair: &Pair) -> Vec<u8> {
    serde_json::json!({
        "name": pair.name, "node_token": pair.node_token(), "connect_token": pair.connect_token(),
        "stop_token": pair.stop_token(), "expires": pair.expires_ms,
    })
    .to_string()
    .into_bytes()
}

/// What came back, the leg's outcome and the channel's.
type Echoed = (Vec<u8>, Outcome, Result<PublicKey, e2e::Error>);

/// One operator session with `grant`.
async fn granted_echo(pair: &Pair, operator_key: Arc<Identity>, grant: Vec<u8>) -> Echoed {
    let (io, mut user) = tokio::io::duplex(64 * 1024);
    let (cipher, channel) = ends::operator_granted(io, operator_key, |_: &PublicKey| Ok(()), None, Some(grant));
    let channel = tokio::spawn(channel);
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
        operator::run(&config, cipher).await.expect("the operator's socket")
    });
    let said = b"one session of a grant".to_vec();
    let (mut from_user, mut to_user) = tokio::io::split(&mut user);
    let sent = said.len();
    let (_, back) = tokio::join!(async move { to_user.write_all(&said).await }, async move {
        let mut back = Vec::with_capacity(sent);
        let _ = tokio::time::timeout(LIMIT, (&mut from_user).take(sent as u64).read_to_end(&mut back)).await;
        back
    });
    let _ = user.shutdown().await;
    let outcome = tokio::time::timeout(LIMIT, session).await.expect("an outcome").unwrap();
    let channel = tokio::time::timeout(LIMIT, channel).await.expect("the channel's end").unwrap();
    (back, outcome, channel)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "the live relay: run with --ignored"]
async fn a_grant_is_used_once_through_the_live_relay() {
    let relay = Relay { host: default_relay_host().into(), port: 443 };
    let ctx =
        PairContext { relay: &relay, trust: &Trust::Default, proxy: &ProxyChoice::FromEnvironment, timeout: LIMIT };
    let made = pair::create(&ctx).await.expect("a pair");
    let copy = pair::parse(&relay, &body_of(&made), now_secs() as i64 * 1000).expect("the same pair");

    // The node's door: its allowlist names nobody, its own key issues.
    let node_key = Arc::new(Identity::from_seed(&[0x5a; 32]));
    let spent = std::env::temp_dir().join(format!("podssh-grant-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&spent);
    let issuers: Arc<grant::Issuers> = Arc::new(|_: &PublicKey, _: &Ask| -> Result<(), String> { Err("none".into()) });
    let door = Door { node: node_key.public(), issuers, spent: Spent::at(spent.clone()), revoked: None };
    let say = Arc::new(|line: String| eprintln!("node: {line}"));
    let mut node_end = ends::Node::open_to_all(node_key.clone(), say);
    node_end.admit = Arc::new(|_: &PublicKey, _: &Ask| -> Result<(), String> { Err("no allowlist".into()) });
    node_end.redeem = Some(Arc::new(move |peer: &PublicKey, ask: &Ask, blob: &[u8]| {
        door.redeem(peer, ask, blob, now_secs()).map(|redeemed| redeemed.to_string())
    }));
    let stop = Arc::new(Notify::new());
    let stopper = stop.clone();
    let node = tokio::spawn(async move {
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
        run(&mut config, Arc::new(E2e::new(Echo, node_end)), async move { stopper.notified().await }).await
    });
    tokio::time::sleep(Duration::from_secs(2)).await;

    // A grant of the node's key for the operator's, as --grant-to makes one.
    let operator_key = Arc::new(Identity::from_seed(&[0x6e; 32]));
    let principals = vec![grant::principal(&node_key.public(), None)];
    let now = now_secs();
    let blob = Mint {
        nonce: [0x2a; 32],
        key: operator_key.public(),
        serial: now,
        key_id: "the live test",
        principals: &principals,
        valid_after: now - 60,
        valid_before: now + 600,
        critical: &[(grant::ONCE, &b""[..])],
    }
    .sign(&node_key)
    .blob();

    let (back, first, channel) = granted_echo(&copy, operator_key.clone(), blob.clone()).await;
    assert_eq!(back, b"one session of a grant", "{first:?} {channel:?}");
    assert_eq!(channel.ok(), Some(node_key.public()));
    let (_, second, channel) = granted_echo(&copy, operator_key, blob).await;
    let refused = matches!(&channel, Err(e2e::Error::Refused(Refusal::Other(why))) if why == GRANT_REFUSED);
    assert!(refused, "the second use: {second:?} {channel:?}");

    stop.notify_one();
    let _ = tokio::time::timeout(LIMIT, node).await;
    let stopped = pair::stop(&ctx, &copy).await.expect("the pair stops");
    eprintln!("pair: {stopped:?}");
    let _ = std::fs::remove_dir_all(&spent);
}
