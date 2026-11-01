//! A front door that shows another key than the device's record (T-399),
//! as WARP's showed a new device until its record was read again (cfrs
//! #32): the stand-in edge changes the key that it shows, and the stand-in
//! API the record that it serves. The road reads the record again, keeps
//! the API's new key and tries it, once more a second later; the record's
//! key, which the API gives again, once more a second later too; a key that
//! the API never gave is never taken; a proxy's CA, for which the API gives
//! the same key, stays an interception; and an API that is not reached
//! leaves the refusal as it was.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant, SystemTime};

use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::api::{api, ApiStandIn};
use super::proxies::{proxy, tls_server, Mode};
use super::{echo, LIMIT};
use crate::device::Device;
use crate::key::DeviceKey;
use crate::register;
use crate::road::{Fault, Warp, RETRY_AFTER};
use crate::stand_in::{Route, StandIn};

/// A device that the stand-in API registered with the endpoint's key
/// `first`, at a stand-in edge that shows `first` and carries a stream to
/// an echo service.
async fn registered(first: &DeviceKey) -> (ApiStandIn, StandIn, Device) {
    let stand_in = api(first, None).await;
    let device = register::register(&stand_in.api, None, SystemTime::now()).await.expect("a device");
    let route = Route { inside: "192.0.2.10:22".parse().unwrap(), outside: echo().await };
    let edge = StandIn::start_with(first.clone(), vec![device.key.point()], vec![route]).await.unwrap();
    let device = device.at(edge.addr);
    (stand_in, edge, device)
}

/// A stream inside the tunnel carries bytes both ways.
async fn echoes(warp: &Warp) {
    let mut stream = warp.connect("192.0.2.10", 22, LIMIT).await.expect("a stream inside");
    stream.write_all(b"rekeyed").await.unwrap();
    let mut back = [0u8; 7];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"rekeyed");
}

fn keys<const N: usize>() -> [DeviceKey; N] {
    std::array::from_fn(|_| DeviceKey::generate().unwrap())
}

/// The front door changes its key, and the record that the API serves: the
/// road reads the record again, keeps the new key, and opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_key_of_the_front_door_is_read_from_the_record_and_kept() {
    let [first, next] = keys();
    let (stand_in, edge, mut device) = registered(&first).await;
    edge.show(vec![next.clone()]);
    stand_in.serve_key(&next);
    let warp = Warp::open_reading(&mut device, &stand_in.api, &ProxyChoice::Direct, LIMIT).await;
    let warp = warp.expect("the tunnel opens with the record's new key");
    assert_eq!(device.endpoint_point, next.point(), "the API's new key is pinned");
    let kept = Device::from_json(&device.to_json()).unwrap();
    assert_eq!(kept.endpoint_point, next.point(), "and the device's record holds it");
    assert_eq!((stand_in.asked("GET"), edge.hellos(), edge.tunnels()), (1, 2, 1));
    echoes(&warp).await;
}

/// The front door's next connection shows a key that the API never gave,
/// as another of its servers might: the road tries the API's key once more
/// a second later, and opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_api_s_key_is_tried_once_more_a_second_later() {
    let [first, next, stray] = keys();
    let (stand_in, edge, mut device) = registered(&first).await;
    edge.show(vec![stray.clone(), stray, next.clone()]);
    stand_in.serve_key(&next);
    let start = Instant::now();
    let warp = Warp::open_reading(&mut device, &stand_in.api, &ProxyChoice::Direct, LIMIT).await;
    let warp = warp.expect("the tunnel opens at the third handshake");
    assert!(start.elapsed() >= RETRY_AFTER, "{:?}", start.elapsed());
    assert_eq!((stand_in.asked("GET"), edge.hellos()), (1, 3));
    assert_eq!(device.endpoint_point, next.point());
    echoes(&warp).await;
}

/// The front door shows another server's certificate once, as WARP's
/// showed one of a public CA to a runner, and the API gives the same key:
/// the record's key is tried once more a second later, and opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_record_s_key_is_tried_once_more_when_the_api_gives_it_again() {
    let [first, stray] = keys();
    let (stand_in, edge, mut device) = registered(&first).await;
    edge.show(vec![stray, first.clone()]);
    let start = Instant::now();
    let warp = Warp::open_reading(&mut device, &stand_in.api, &ProxyChoice::Direct, LIMIT).await;
    let warp = warp.expect("the tunnel opens at the second handshake");
    assert!(start.elapsed() >= RETRY_AFTER, "{:?}", start.elapsed());
    assert_eq!((stand_in.asked("GET"), edge.hellos(), edge.tunnels()), (1, 2, 1));
    assert_eq!(device.endpoint_point, first.point(), "the record's key stays");
    echoes(&warp).await;
}

/// A front door that shows a key that the API never gave is refused, while
/// the API gives another new one: the device takes the API's key alone,
/// and the road is not tried again in the run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_that_the_api_never_gave_is_never_taken() {
    let [first, next, stray] = keys();
    let (stand_in, edge, mut device) = registered(&first).await;
    edge.show(vec![stray.clone()]);
    stand_in.serve_key(&next);
    let fault = Warp::open_reading(&mut device, &stand_in.api, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    let Fault::Intercepted(line) = &fault else { panic!("{fault:?}") };
    assert!(line.contains("the key that WARP's API gives now"), "{line}");
    assert_eq!(device.endpoint_point, next.point(), "the API's key, never the front door's");
    assert_ne!(device.endpoint_point, stray.point());
    assert_eq!((edge.hellos(), edge.tunnels()), (3, 0));
    let again = Warp::open_reading(&mut device, &stand_in.api, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    assert!(again.to_string().contains("not tried again"), "{again}");
    assert_eq!((stand_in.asked("GET"), edge.hellos()), (1, 3));
}

/// Through a proxy that re-terminates TLS, the API, read again, gives the
/// same key: the certificate is the proxy's, named by its CA, and the road
/// is not tried again through it; directly, the record's key opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_s_ca_stays_an_interception() {
    let [first] = keys();
    let (stand_in, edge, mut device) = registered(&first).await;
    let (acceptor, _) = tls_server("Corp Proxy CA", &[crate::SERVER_NAME]);
    let via = proxy(Mode::Reterminate(acceptor)).await;
    let fault = Warp::open_reading(&mut device, &stand_in.api, &via, LIMIT).await.unwrap_err();
    let Fault::Intercepted(line) = &fault else { panic!("{fault:?}") };
    assert!(line.contains("CN=Corp Proxy CA") && line.contains("gives the same key"), "{line}");
    assert_eq!(device.endpoint_point, first.point());
    let again = Warp::open_reading(&mut device, &stand_in.api, &via, LIMIT).await.unwrap_err();
    assert!(again.to_string().contains("not tried again"), "{again}");
    assert_eq!((stand_in.asked("GET"), edge.tunnels()), (1, 0));
    let warp = Warp::open_reading(&mut device, &stand_in.api, &ProxyChoice::Direct, LIMIT).await;
    echoes(&warp.expect("directly, the record's key opens")).await;
    assert_eq!(stand_in.asked("GET"), 1);
}

/// An API that is not reached leaves the refusal as it was, and says why;
/// the pinned key stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_api_that_is_not_reached_leaves_the_refusal() {
    let [first, next] = keys();
    let (stand_in, edge, mut device) = registered(&first).await;
    edge.show(vec![next]);
    let closed = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut gone = stand_in.api.clone();
    gone.port = closed.local_addr().unwrap().port();
    gone.limit = Duration::from_secs(5);
    drop(closed);
    let fault = Warp::open_reading(&mut device, &gone, &ProxyChoice::Direct, LIMIT).await.unwrap_err();
    let Fault::Intercepted(line) = &fault else { panic!("{fault:?}") };
    assert!(line.contains("was not read again"), "{line}");
    assert_eq!(device.endpoint_point, first.point());
    assert_eq!(edge.tunnels(), 0);
}
