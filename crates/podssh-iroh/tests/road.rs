//! The iroh road (T-162), offline. A relay server on the loopback has a name
//! that only a stand-in CONNECT proxy resolves, and two endpoints have no
//! UDP: each byte goes through the proxy and the relay, as in a sandbox. A
//! session of the resumable layer carries 20 MiB each way with equal SHA-256
//! digests. And podssh's own trust store refuses the relay's certificate,
//! which the other tests skip.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use iroh::EndpointAddr;
use podssh_iroh::{Options, ALPN};
use podssh_relay::session::client::{self, Found, Outcome};
use podssh_relay::session::{Ask, End, OsEntropy, Settings};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use common::{options, proxy, relay, LIMIT};

const PIPE: usize = 256 * 1024;
const MIB: usize = 1 << 20;

fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Write `out` and read as many bytes at once, then end the bytes.
async fn exchange(stream: DuplexStream, out: Vec<u8>) -> Vec<u8> {
    let (mut r, mut w) = tokio::io::split(stream);
    let len = out.len();
    let writer = tokio::spawn(async move {
        w.write_all(&out).await.unwrap();
        w
    });
    let mut got = vec![0u8; len];
    r.read_exact(&mut got).await.unwrap();
    let mut w = writer.await.unwrap();
    w.shutdown().await.unwrap();
    got
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_through_a_proxy_and_a_relay_carries_20_mib_each_way() {
    let (relay_url, _relay) = relay().await;
    let (proxy, tunnels) = proxy(relay_url.port().unwrap()).await;

    let far = podssh_iroh::bind(&options(&relay_url, proxy, true)).await.expect("the far end");
    tokio::time::timeout(LIMIT, far.online()).await.expect("the far end has its home relay");
    // Each new session's target: one end of a pipe, the other to the test.
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let open = move || {
        let targets = targets_tx.clone();
        async move {
            let (target, test_end) = tokio::io::duplex(PIPE);
            targets.send(test_end).map_err(|e| e.to_string())?;
            Ok::<_, String>(target)
        }
    };
    let near = podssh_iroh::bind(&options(&relay_url, proxy, false)).await.expect("the client");
    // The client's key, and no other, is in the far end's allowlist.
    let client_key = near.id();
    let admit = move |key: &iroh::PublicKey| *key == client_key;
    tokio::spawn(podssh_iroh::far::serve(far.clone(), Settings::default(), 64 * MIB, open, admit));

    let addr = EndpointAddr::new(far.id()).with_relay_url(relay_url.clone());
    let connection = tokio::time::timeout(LIMIT, near.connect(addr, ALPN)).await.unwrap().expect("a connection");
    let stream = podssh_iroh::open_session(&connection).await.expect("a session's stream");
    let session = tokio::time::timeout(LIMIT, client::start(stream, Ask::New, Settings::default(), &mut OsEntropy))
        .await
        .unwrap()
        .expect("the layer's handshake");
    assert!(matches!(session.found(), Found::Layer { .. }), "{:?}", session.found());

    let (app, app_end) = tokio::io::duplex(PIPE);
    let run = tokio::spawn(session.run(app_end));
    let target = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().expect("the session's target");
    let up = pseudo_random(20 * MIB, 0x1205);
    let down = pseudo_random(20 * MIB, 0x5021);
    let (at_target, at_client) =
        tokio::time::timeout(LIMIT, async { tokio::join!(exchange(target, down.clone()), exchange(app, up.clone())) })
            .await
            .expect("20 MiB each way within the limit");
    assert_eq!(Sha256::digest(&at_target), Sha256::digest(&up), "the client's bytes reached the target whole");
    assert_eq!(Sha256::digest(&at_client), Sha256::digest(&down), "the target's bytes reached the client whole");
    let outcome = tokio::time::timeout(LIMIT, run).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd | End::Closed(_))),
        "{outcome:?}"
    );
    // The relay has a name that only the proxy knows: each end reached it
    // through the proxy.
    assert!(tunnels.load(Ordering::SeqCst) >= 2, "{} tunnels through the proxy", tunnels.load(Ordering::SeqCst));
    near.close().await;
    far.close().await;
}

/// With podssh's trust store, and no skip, the relay's self-signed
/// certificate is refused: the endpoint never gets a home relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn podssh_s_trust_store_refuses_a_relay_that_it_does_not_trust() {
    let (relay_url, _relay) = relay().await;
    let (proxy, _tunnels) = proxy(relay_url.port().unwrap()).await;
    let trusting = Options { relay_tls: None, ..options(&relay_url, proxy, true) };
    let endpoint = podssh_iroh::bind(&trusting).await.expect("an endpoint");
    let online = tokio::time::timeout(Duration::from_secs(8), endpoint.online()).await;
    assert!(online.is_err(), "a relay with a self-signed certificate was trusted");
    endpoint.close().await;
}
