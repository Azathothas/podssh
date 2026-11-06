//! The probe of a tunnel that has just opened (T-560), against the stand-in
//! edge (rustls's server, h2's server, smoltcp at its far end): a front door
//! that takes TLS and the CONNECT and then relays nothing is named as such,
//! within the probe's ceiling, and not remembered for the run; one that
//! carries gives a road whose probe was answered, a SYN-ACK or a reset; and
//! a run that skips the probe takes the tunnel as it opens. Feature
//! `stand-in`, as the stand-in listens on the loopback.
#![cfg(feature = "stand-in")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use podssh_warp::key::DeviceKey;
use podssh_warp::probe;
use podssh_warp::stand_in::{Route, StandIn};
use podssh_warp::{Fault, Warp};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// The bound on each wait of a test.
const LIMIT: Duration = Duration::from_secs(20);
const TARGET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 22);

/// The longest the probe may take before its verdict: each try, the pause,
/// and a margin for a loaded runner.
fn ceiling() -> Duration {
    probe::TRY * probe::TRIES as u32 + probe::GAP + Duration::from_secs(3)
}

/// An echo service on the loopback: each connection's bytes back.
async fn echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

/// The stand-in's count of answered probes once it reaches `want`, within
/// [`LIMIT`]: its far end counts in a task of its own, a moment after the
/// client's connection opened.
async fn probes_reach(edge: &StandIn, want: usize) -> usize {
    let deadline = Instant::now() + LIMIT;
    while edge.probes() < want && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    edge.probes()
}

/// A stand-in that enrolled `key`, with one route to an echo service.
async fn edge_for(key: &DeviceKey) -> StandIn {
    let route = Route { inside: TARGET, outside: echo().await };
    StandIn::start(vec![key.point()], vec![route]).await.unwrap()
}

/// A front door that takes TLS and the CONNECT, then relays nothing: the
/// opening ends with one line of the road, the probe's two tries within
/// its ceiling, and no stream to time out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_front_door_is_named_within_the_ceiling() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    edge.silence(true);
    let device = edge.device(key);
    assert_eq!(device.probe, Some(probe::target_v4()));
    let start = Instant::now();
    let fault = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    let took = start.elapsed();
    let Fault::Silent(line) = &fault else { panic!("{fault:?}") };
    assert!(line.contains("the tunnel opened and carried nothing"), "{line}");
    assert!(line.contains(&format!("WARP's endpoint {}", edge.addr)), "{line}");
    assert!(line.contains("from 1.1.1.1:443 in 2 tries"), "{line}");
    assert!(took >= probe::GAP, "a verdict after one try: {took:?}");
    assert!(took < ceiling(), "the probe took {took:?}");
    assert_eq!((edge.tunnels(), edge.probes(), edge.carried()), (1, 0, 0));
}

/// A front door that carries gives the road, whose probe the far end
/// answered; the probe is no stream of the user's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_front_door_that_carries_gives_a_road_whose_probe_was_answered() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let warp = Warp::open(&edge.device(key), &ProxyChoice::Direct, LIMIT).await.expect("the tunnel opens");
    assert_eq!(warp.probed, Some(probe::target_v4()));
    assert_eq!(probes_reach(&edge, 1).await, 1);
    let mut stream = warp.connect("192.0.2.10", 22, LIMIT).await.expect("a stream inside");
    stream.write_all(b"proven").await.unwrap();
    let mut back = [0u8; 6];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"proven");
    assert_eq!((edge.tunnels(), edge.carried()), (1, 1));
}

/// A reset from inside the tunnel is an answer too: a packet went out and
/// one came back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reset_inside_the_tunnel_is_an_answer() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let closed = SocketAddr::new(TARGET.ip(), 23);
    let device = edge.device(key).probing(Some(closed));
    let warp = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.expect("a reset is an answer");
    assert_eq!(warp.probed, Some(closed));
    assert_eq!(edge.probes(), 0);
}

/// A run that skips the probe takes the silent tunnel as it opens, and
/// says that nothing was proven; its first stream then meets the silence
/// that the probe would have named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_that_skips_the_probe_proves_nothing() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    edge.silence(true);
    let device = edge.device(key).probing(None);
    let warp = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.expect("no probe, no verdict");
    assert_eq!(warp.probed, None);
    let quiet = warp.connect("192.0.2.10", 22, Duration::from_secs(2)).await.unwrap_err();
    assert!(quiet.contains("no answer"), "{quiet}");
}

/// A silent front door is not remembered as a proxy that re-terminates TLS
/// is: once it carries again, the same endpoint opens in the same run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_front_door_is_tried_again() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let device = edge.device(key);
    edge.silence(true);
    let first = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    assert!(matches!(first, Fault::Silent(_)), "{first:?}");
    edge.silence(false);
    let warp = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.expect("the endpoint is tried again");
    assert_eq!(warp.probed, Some(probe::target_v4()));
    assert_eq!((edge.tunnels(), probes_reach(&edge, 1).await), (2, 1));
}
