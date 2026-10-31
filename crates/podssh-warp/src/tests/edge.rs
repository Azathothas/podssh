//! The client against the stand-in edge: a session both ways, a name asked
//! inside the tunnel, a device that the edge does not know, an endpoint of
//! another key, a closed port, an address with no route, and the tunnel's
//! end.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::PoisonError;
use std::time::Duration;

use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{echo, resolver, LIMIT};
use crate::key::DeviceKey;
use crate::road::{Fault, Warp};
use crate::stand_in::{Route, StandIn};
use crate::tunnel::{self, Opening};

const TARGET: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 22);

/// A stand-in that enrolled `key`, with one route to an echo service.
async fn edge_for(key: &DeviceKey) -> StandIn {
    let route = Route { inside: TARGET, outside: echo().await };
    StandIn::start(vec![key.point()], vec![route]).await.unwrap()
}

async fn open(edge: &StandIn, key: DeviceKey) -> Warp {
    let device = edge.device(key);
    Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.expect("the tunnel opens")
}

/// 1 MiB to the echo service and back, inside the tunnel, the same bytes;
/// the CONNECT as the edge reads connect-ip's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_passes_both_ways_inside_the_tunnel() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let warp = open(&edge, key).await;
    let stream = warp.connect("192.0.2.10", 22, LIMIT).await.expect("a stream inside");
    assert_eq!(stream.peer(), Some(TARGET));
    let sent: Vec<u8> = (0..1u32 << 20).map(|i| (i.wrapping_mul(7) % 251) as u8).collect();
    let (mut r, mut w) = tokio::io::split(stream);
    let out = sent.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&out).await.unwrap();
        w.shutdown().await.unwrap();
        w
    });
    let mut got = Vec::new();
    tokio::time::timeout(LIMIT * 3, r.read_to_end(&mut got)).await.expect("the echo in time").unwrap();
    assert_eq!(got.len(), sent.len());
    assert!(got == sent, "the bytes came back changed");
    drop(writer.await.unwrap());
    assert_eq!((edge.tunnels(), edge.carried()), (1, 1));
    let authority = edge.seen.authority.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(authority.as_deref(), Some("cloudflareaccess.com:443"));
    let headers = edge.seen.headers.lock().unwrap_or_else(PoisonError::into_inner).clone();
    let header = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
    assert_eq!(header("cf-connect-proto").as_deref(), Some("cf-connect-ip"));
    assert_eq!(header("pq-enabled").as_deref(), Some("false"));
    assert_eq!(header("user-agent"), None, "usque sends no User-Agent");
}

/// A name is asked of the resolver inside the tunnel, at 1.1.1.1:53, and
/// the stream goes to its address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_is_asked_inside_the_tunnel() {
    let key = DeviceKey::generate().unwrap();
    let dns = SocketAddr::new(crate::dns::RESOLVERS[0], crate::dns::PORT);
    let routes = vec![
        Route { inside: dns, outside: resolver(Ipv4Addr::new(192, 0, 2, 10)).await },
        Route { inside: TARGET, outside: echo().await },
    ];
    let edge = StandIn::start(vec![key.point()], routes).await.unwrap();
    let warp = open(&edge, key).await;
    assert_eq!(warp.resolve("target.example", LIMIT).await.unwrap(), vec![TARGET.ip()]);
    let mut stream = warp.connect("target.example", 22, LIMIT).await.expect("a stream to the name");
    stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"ping");
}

/// A device whose key the edge did not enrol is refused, as the device's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_that_the_edge_does_not_know_is_refused() {
    let edge = StandIn::start(vec![DeviceKey::generate().unwrap().point()], vec![]).await.unwrap();
    let device = edge.device(DeviceKey::generate().unwrap());
    let fault = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    assert!(matches!(fault, Fault::Device(_)), "{fault:?}");
    assert_eq!(edge.tunnels(), 0);
}

/// An endpoint whose key is not the pinned one is named as an interception,
/// and the road is not tried again with it in the run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_endpoint_of_another_key_is_not_trusted() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let other = crate::der::pem(&DeviceKey::generate().unwrap().spki(), "PUBLIC KEY");
    let device = edge.device(key);
    let device = crate::Device::new(
        device.id.clone(),
        device.token().to_string(),
        device.key.clone(),
        &other,
        edge.addr,
        device.address_v4,
        None,
        device.registered.clone(),
        false,
    )
    .unwrap();
    let opened = tunnel::open(&device, &ProxyChoice::Direct, LIMIT).await;
    assert!(matches!(opened, Err(Opening::Intercepted { .. })), "{:?}", opened.err());
    let first = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    assert!(matches!(&first, Fault::Intercepted(line) if line.contains("re-terminates TLS")), "{first:?}");
    let again = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    assert!(matches!(&again, Fault::Intercepted(line) if line.contains("not tried again")), "{again:?}");
    assert_eq!(edge.tunnels(), 0);
}

/// A closed port of a routed address is refused at once; an address with
/// no route gets no answer within the limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_port_is_refused_and_no_route_is_silent() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let warp = open(&edge, key).await;
    let refused = warp.connect("192.0.2.10", 23, LIMIT).await.unwrap_err();
    assert!(refused.contains("refused"), "{refused}");
    let silent = warp.connect("198.51.100.1", 22, Duration::from_secs(2)).await.unwrap_err();
    assert!(silent.contains("no answer"), "{silent}");
    let family = warp.connect("2001:db8::1", 22, LIMIT).await.unwrap_err();
    assert!(family.contains("no address of a family"), "{family}");
}

/// The edge that goes away ends each stream with the tunnel's end, and the
/// stack says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_end_of_the_tunnel_ends_its_streams() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let warp = open(&edge, key).await;
    let mut stream = warp.connect("192.0.2.10", 22, LIMIT).await.unwrap();
    edge.cut();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(LIMIT, stream.read(&mut buf)).await.expect("the end in time");
    let e = read.expect_err("an error, not an end of the stream");
    assert!(e.to_string().contains("WARP's tunnel ended"), "{e}");
    assert!(warp.ended().is_some());
    let after = warp.connect("192.0.2.10", 22, LIMIT).await.unwrap_err();
    assert!(after.contains("the tunnel has ended"), "{after}");
}
