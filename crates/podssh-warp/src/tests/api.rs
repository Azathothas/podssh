//! The registration against a stand-in of the API on the loopback, over
//! podssh-ws's HTTPS with a CA of the test: the two requests as usque sends
//! them, the device that the answers give, a team's token, a refusal; and
//! the device then through the stand-in edge, which takes the key that the
//! API enrolled.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::proxies::tls_server;
use super::{echo, LIMIT};
use crate::key::DeviceKey;
use crate::register::{self, Api, Fault};
use crate::road::Warp;
use crate::stand_in::{Route, StandIn};

const ID: &str = "0d2a1b3c-4d5e-6f70-8192-a3b4c5d6e7f8";
const TOKEN: &str = "stand-in-token-0123";

/// A request that the stand-in took: its head and its body.
type Asked = (podssh_ws::http::Request, Vec<u8>);

/// The stand-in API: its address, the trust of its CA, and what it took.
struct ApiStandIn {
    api: Api,
    asked: Arc<Mutex<Vec<Asked>>>,
}

/// A stand-in that answers as the API: the device at `POST /reg`, its key
/// of MASQUE at `PATCH /reg/ID` with the device's token, with `endpoint`'s
/// key; `status` in place of the answer of `POST`, when one is given.
async fn api(endpoint: &DeviceKey, status: Option<u16>) -> ApiStandIn {
    let (acceptor, roots) = tls_server("podssh-test-api-ca", &["127.0.0.1"]);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let asked: Arc<Mutex<Vec<Asked>>> = Arc::default();
    let pem = crate::der::pem(&endpoint.spki(), "PUBLIC KEY");
    let took = asked.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let Ok(mut tls) = acceptor.accept(tcp).await else { continue };
            let Ok((request, mut body)) = podssh_ws::http::read_request(&mut tls, Vec::new()).await else { continue };
            let len: usize = request.header("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
            while body.len() < len {
                let mut chunk = [0u8; 4096];
                match tls.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                }
            }
            let (code, answer) = answer(&request, &pem, status);
            took.lock().unwrap_or_else(PoisonError::into_inner).push((request, body));
            let head = format!(
                "HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                answer.len()
            );
            let _ = tls.write_all(&[head.into_bytes(), answer.into_bytes()].concat()).await;
            let _ = tls.shutdown().await;
        }
    });
    let config =
        podssh_ws::tls::client_config(&podssh_ws::tls::TlsRoots { roots, source: "the test's CA".into(), count: 1 })
            .unwrap();
    let trust = Trust::caller(config).unwrap();
    let api = Api { host: "127.0.0.1".into(), port: addr.port(), trust, proxy: ProxyChoice::Direct, limit: LIMIT };
    ApiStandIn { api, asked }
}

/// The API's answer to `request`, in the form of usque's `AccountData`.
fn answer(request: &podssh_ws::http::Request, pem: &str, status: Option<u16>) -> (u16, String) {
    let reg = format!("/{}/reg", register::API_VERSION);
    let device = format!("{reg}/{ID}");
    let bearer = format!("Bearer {TOKEN}");
    let bearer = Some(bearer.as_str());
    match (request.method.as_str(), request.target.as_str()) {
        ("POST", target) if target == reg => match status {
            Some(code) => (code, r#"{"success":false,"errors":[{"code":1015,"message":"rate limited"}]}"#.into()),
            None => (
                200,
                serde_json::json!({
                    "id": ID, "type": "a", "token": TOKEN, "key_type": "curve25519", "tunnel_type": "wireguard",
                    "config": {"peers": [{"public_key": "bmV2ZXIgdXNlZA==", "endpoint": {"v4": "162.159.192.1:0"}}],
                        "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a36::2"}}}
                })
                .to_string(),
            ),
        },
        ("PATCH", target) if target == device && request.header("authorization") == bearer => (
            200,
            serde_json::json!({
                "id": ID, "key_type": "secp256r1", "tunnel_type": "masque",
                "config": {"peers": [{"public_key": pem,
                    "endpoint": {"v4": "162.159.198.1:0", "v6": "[2606:4700:103::]:0"}}],
                    "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a36::2"}}}
            })
            .to_string(),
        ),
        _ => (403, r#"{"success":false}"#.into()),
    }
}

/// The two requests as usque sends them, and the device of their answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registration_gives_a_device_with_the_endpoint_s_key() {
    let endpoint = DeviceKey::generate().unwrap();
    let stand_in = api(&endpoint, None).await;
    let device = register::register(&stand_in.api, None, SystemTime::now()).await.expect("a device");
    assert_eq!(device.id, ID);
    assert_eq!(device.token(), TOKEN);
    assert_eq!(device.endpoint_point, endpoint.point());
    assert_eq!(device.endpoint, crate::ENDPOINT_H2.parse::<std::net::SocketAddr>().unwrap());
    assert_eq!(device.address_v4, Some(Ipv4Addr::new(172, 16, 0, 2)));
    assert!(!device.team);
    let asked = stand_in.asked.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(asked.len(), 2);
    let (post, body) = &asked[0];
    assert_eq!((post.method.as_str(), post.target.as_str()), ("POST", "/v0a4471/reg"));
    assert_eq!(post.header("user-agent"), Some("WARP for Android"));
    assert_eq!(post.header("cf-client-version"), Some("a-6.35-4471"));
    assert_eq!(post.header("authorization"), None);
    assert_eq!(post.header("cf-access-jwt-assertion"), None);
    let body: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!((body["key_type"].as_str(), body["tunnel_type"].as_str()), (Some("curve25519"), Some("wireguard")));
    assert_eq!(body["serial_number"].as_str().map(str::len), Some(16));
    assert_eq!(body["model"], "PC");
    let (patch, body) = &asked[1];
    assert_eq!(patch.target, format!("/v0a4471/reg/{ID}"));
    let body: serde_json::Value = serde_json::from_slice(body).unwrap();
    let key = base64::engine::general_purpose::STANDARD.decode(body["key"].as_str().unwrap()).unwrap();
    assert_eq!(key, device.key.spki(), "the key enrolled is the device's");
    assert_eq!((body["key_type"].as_str(), body["tunnel_type"].as_str()), (Some("secp256r1"), Some("masque")));
    // The record keeps it all, for the next run.
    let again = crate::Device::from_json(&device.to_json()).unwrap();
    assert_eq!(again.endpoint_point, device.endpoint_point);
}

/// A team's token goes in its header, on the registration alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_team_s_token_goes_in_its_header() {
    let stand_in = api(&DeviceKey::generate().unwrap(), None).await;
    let device = register::register(&stand_in.api, Some("team.jwt.value"), SystemTime::now()).await.unwrap();
    assert!(device.team);
    let asked = stand_in.asked.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(asked[0].0.header("cf-access-jwt-assertion"), Some("team.jwt.value"));
    assert_eq!(asked[1].0.header("cf-access-jwt-assertion"), None);
}

/// A refusal says its status and the API's words, and never the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_says_its_status() {
    let stand_in = api(&DeviceKey::generate().unwrap(), Some(429)).await;
    let fault = register::register(&stand_in.api, None, SystemTime::now()).await.unwrap_err();
    let Fault::Refused { status, said } = &fault else { panic!("{fault:?}") };
    assert_eq!(*status, 429);
    assert!(said.contains("rate limited"), "{said}");
}

/// The device that the API registered opens a tunnel at an edge that took
/// its key, whose own key the API gave.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registered_device_opens_its_tunnel() {
    let endpoint = DeviceKey::generate().unwrap();
    let stand_in = api(&endpoint, None).await;
    let device = register::register(&stand_in.api, None, SystemTime::now()).await.unwrap();
    let route = Route { inside: "192.0.2.10:22".parse().unwrap(), outside: echo().await };
    let edge = StandIn::start_with(endpoint, vec![device.key.point()], vec![route]).await.unwrap();
    let device = device.at(edge.addr);
    let warp = Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.expect("the tunnel opens");
    let mut stream = warp.connect("192.0.2.10", 22, Duration::from_secs(10)).await.unwrap();
    stream.write_all(b"enrolled").await.unwrap();
    let mut back = [0u8; 8];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"enrolled");
}
