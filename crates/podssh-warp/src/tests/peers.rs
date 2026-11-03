//! The endpoints of a device in turn (T-561), against the stand-in edge and
//! ports of the loopback that refuse: a record whose first endpoint refuses
//! reaches the next and keeps it, tried first the next time; the failure of
//! each names each, and forgets the one that was kept; the run's one
//! endpoint is tried alone; and a device that the edge refuses is not taken
//! to the next endpoint.

use std::net::{Ipv4Addr, SocketAddr};

use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::api::api;
use super::{echo, LIMIT};
use crate::device::Device;
use crate::key::DeviceKey;
use crate::road::{Fault, Warp};
use crate::stand_in::{Route, StandIn};

/// A stand-in that enrolled `key`, with one route to an echo service.
async fn edge_for(key: &DeviceKey) -> StandIn {
    let route = Route { inside: "192.0.2.10:22".parse().unwrap(), outside: echo().await };
    StandIn::start(vec![key.point()], vec![route]).await.unwrap()
}

/// A port of the loopback that refuses each connection at once.
async fn refusing() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// A stream inside the tunnel carries bytes both ways.
async fn echoes(warp: &Warp) {
    let mut stream = warp.connect("192.0.2.10", 22, LIMIT).await.expect("a stream inside");
    stream.write_all(b"peer").await.unwrap();
    let mut back = [0u8; 4];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"peer");
}

/// The record's endpoint refuses, and the API's peer after it opens: the
/// device keeps the peer, which its record holds and the next run tries
/// first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_of_two_peers_whose_first_refuses_reaches_the_second_and_keeps_it() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let refused = refusing().await;
    let mut device = edge.device(key).with_peers(vec![edge.addr]);
    device.endpoint = refused;
    assert_eq!(device.endpoints(), vec![refused, edge.addr]);
    let warp = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.expect("the peer opens");
    assert_eq!(warp.endpoint, edge.addr);
    assert_eq!(device.reached, None, "Warp::open changes no device");
    drop(warp);
    // An API that is never asked: no certificate of another key comes.
    let stand_in = api(&DeviceKey::generate().unwrap(), None).await;
    let warp = Warp::open_reading(&mut device, &stand_in.api, &ProxyChoice::Direct, LIMIT).await;
    let warp = warp.expect("the peer opens again");
    assert_eq!((warp.endpoint, device.reached), (edge.addr, Some(edge.addr)));
    let kept = Device::from_json(&device.to_json()).unwrap();
    assert_eq!(kept.endpoints(), vec![edge.addr, refused], "the one that opened goes first");
    echoes(&warp).await;
    assert_eq!((edge.tunnels(), stand_in.asked("GET")), (2, 0));
}

/// Each endpoint fails, each its own way: the line names each, in turn,
/// and the device forgets the endpoint that it had kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_failure_of_each_endpoint_names_each_and_forgets_the_kept_one() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    edge.silence(true);
    let (first, second) = (refusing().await, refusing().await);
    let mut device = edge.device(key).with_peers(vec![edge.addr]);
    device.endpoint = second;
    device.reached = Some(first);
    let stand_in = api(&DeviceKey::generate().unwrap(), None).await;
    let fault = Warp::open_reading(&mut device, &stand_in.api, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    let Fault::Unreachable(line) = &fault else { panic!("the first one's kind: {fault:?}") };
    assert!(line.starts_with("each of WARP's 3 endpoints failed, in turn"), "{line}");
    for at in [first, second, edge.addr] {
        assert!(line.contains(&format!("WARP's endpoint {at}")), "{at}: {line}");
    }
    assert!(line.contains("carried nothing"), "{line}");
    assert_eq!(device.reached, None, "a run that opens none forgets the kept endpoint");
}

/// The run's one endpoint (`PODSSH_WARP_ENDPOINT`) is tried alone: its
/// failure is its own line, the peers are not dialled, and the kept
/// endpoint stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_endpoint_that_the_run_names_is_the_only_one_tried() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let refused = refusing().await;
    let mut device = edge.device(key).with_peers(vec![edge.addr]);
    device.reached = Some(edge.addr);
    let mut device = device.at(refused);
    assert_eq!(device.endpoints(), vec![refused]);
    let stand_in = api(&DeviceKey::generate().unwrap(), None).await;
    let fault = Warp::open_reading(&mut device, &stand_in.api, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    let Fault::Unreachable(line) = &fault else { panic!("{fault:?}") };
    assert!(line.contains(&refused.to_string()) && !line.contains("each of"), "{line}");
    assert_eq!((edge.connections(), device.reached), (0, Some(edge.addr)));
}

/// An edge that refuses the device would refuse it at each endpoint: the
/// road ends there, and the next endpoint is not dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_that_the_edge_refuses_is_not_taken_to_the_next_endpoint() {
    let key = DeviceKey::generate().unwrap();
    let stranger = StandIn::start(vec![DeviceKey::generate().unwrap().point()], vec![]).await.unwrap();
    let edge = edge_for(&key).await;
    let mut device = edge.device(key).with_peers(vec![edge.addr]);
    device.endpoint = stranger.addr;
    let fault = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    assert!(matches!(fault, Fault::Device(_)), "{fault:?}");
    assert_eq!(edge.connections(), 0);
}
