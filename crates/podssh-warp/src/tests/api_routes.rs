//! The routes to WARP's API in turn (T-562), against the stand-in API and
//! ports of the loopback that refuse: a first route that is not reached
//! hands the registration to the second, whose route the device keeps; the
//! failure of each route names each; a refusal by the first is the API's
//! answer, and goes to no other route; and a read of the record again goes
//! by the routes in turn too.

use std::time::{Duration, SystemTime};

use super::api::api;
use super::refusing;
use crate::device::Device;
use crate::key::DeviceKey;
use crate::register::{self, Api, Fault};
use crate::routes::Route;

/// The routes of the loopback's `ports`, in turn, with the trust of `api`.
fn by(api: &Api, ports: &[u16]) -> Api {
    let mut api = api.clone();
    api.routes = ports.iter().map(|port| Route { host: "127.0.0.1".into(), port: *port }).collect();
    api.limit = Duration::from_secs(5);
    api
}

/// The first route refuses at once; the second, the stand-in API, takes
/// the registration and the enrolment, and the device keeps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_route_that_is_not_reached_hands_the_registration_to_the_second() {
    let stand_in = api(&DeviceKey::generate().unwrap(), None).await;
    let (refused, port) = (refusing().await.port(), stand_in.api.routes[0].port);
    let routes = by(&stand_in.api, &[refused, port]);
    let device = register::register(&routes, None, SystemTime::now()).await.expect("the second route registers");
    assert_eq!(device.api, Some(Route { host: "127.0.0.1".into(), port }));
    assert_eq!((stand_in.asked("POST"), stand_in.asked("PATCH")), (1, 1));
    let kept = Device::from_json(&device.to_json()).unwrap();
    assert_eq!(kept.api, device.api, "the record keeps the route that answered");
    let (answer, route) = register::read_record(&routes, &kept).await.expect("the record read again");
    assert_eq!((answer.id, route.port), (kept.id.clone(), port));
    assert_eq!(stand_in.asked("GET"), 1);
}

/// Each route is refused: the line names each, in turn, and says that no
/// route reached the API.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_route_that_is_not_reached_is_named() {
    let stand_in = api(&DeviceKey::generate().unwrap(), None).await;
    let (first, second) = (refusing().await.port(), refusing().await.port());
    let fault = register::register(&by(&stand_in.api, &[first, second]), None, SystemTime::now()).await.unwrap_err();
    assert!(matches!(fault, Fault::Unreachable(_)), "{fault:?}");
    let line = fault.to_string();
    assert!(line.starts_with("WARP's API was not reached by any of its routes: 127.0.0.1:"), "{line}");
    assert!(line.contains(&format!("127.0.0.1:{first}: ")), "{line}");
    assert!(line.contains(&format!("; then 127.0.0.1:{second}: ")), "{line}");
    assert_eq!(stand_in.asked("POST"), 0);
}

/// A refusal by the first route is the API's own answer: it is said, and
/// the second route is not asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_by_the_first_route_goes_to_no_other() {
    let limited = api(&DeviceKey::generate().unwrap(), Some(429)).await;
    let other = api(&DeviceKey::generate().unwrap(), None).await;
    let routes = by(&limited.api, &[limited.api.routes[0].port, other.api.routes[0].port]);
    let fault = register::register(&routes, None, SystemTime::now()).await.unwrap_err();
    assert!(matches!(fault, Fault::Refused { status: 429, .. }), "{fault:?}");
    assert_eq!((limited.asked("POST"), other.asked("POST")), (1, 0));
}

/// A route put first goes first, once; Cloudflare's API has its two names,
/// in order.
#[test]
fn a_route_put_first_goes_first_once() {
    let api = Api::cloudflare(podssh_ws::Trust::Default, podssh_ws::ProxyChoice::Direct, Duration::ZERO);
    let names: Vec<String> = api.routes.iter().map(Route::to_string).collect();
    assert_eq!(names, vec![register::API_HOST.to_string(), register::API_SECOND.to_string()]);
    let second = Route::https(register::API_SECOND);
    let routes = api.first(second.clone()).routes;
    assert_eq!(routes, vec![second, Route::https(register::API_HOST)]);
}
