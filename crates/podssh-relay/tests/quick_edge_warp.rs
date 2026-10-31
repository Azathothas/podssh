//! The quick tunnel's edge inside WARP's tunnel (T-374), on the loopback: a
//! stand-in of WARP's edge (podssh-warp's, T-352: rustls's server, h2's
//! server, smoltcp at its far end) carries the node's TCP stream to the
//! edge's port 7844 at an address that only its tunnel reaches; there a
//! stand-in of the quick tunnel's edge, whose TLS names `h2.cftunnel.com`
//! under a CA of the test, is the client of HTTP/2, as cloudflared's edge
//! is (`quick_harness`). The node registers, and a visitor's WebSocket
//! passes both ways. Planted: a stream sent past the tunnel finds no edge
//! at that address, and the edge's stand-in sees no connection.
#![cfg(feature = "warp-stand-in")]

mod quick_harness;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use podssh_relay::quick::edge::{self, Edge};
use podssh_relay::quick::edge_warp;
use podssh_relay::quick::serve::Step;
use podssh_warp::key::DeviceKey;
use podssh_warp::stand_in::{Route, StandIn};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::{ProxyChoice, Trust};
use quick_harness::{echo, node_with, read_frame, register, visitor, LIMIT};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// The edge's address inside the stand-in's tunnel: TEST-NET-2, which no
/// network of this host routes.
const INSIDE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), edge::PORT);

/// A P-256 key of podssh-warp's, for rcgen's certificates.
struct Signer(DeviceKey, Vec<u8>);

impl Signer {
    fn new() -> Signer {
        let key = DeviceKey::generate().unwrap();
        let point = key.point();
        Signer(key, point)
    }
}

impl rcgen::PublicKeyData for Signer {
    fn der_bytes(&self) -> &[u8] {
        &self.1
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.0.sign(message))
    }
}

/// The stand-in of the quick tunnel's edge: TLS for `h2.cftunnel.com` on
/// the loopback, each connection handed to the test, which is its client
/// of HTTP/2; and the trust of the test's CA, for the node.
type Accepted = mpsc::UnboundedReceiver<tokio_rustls::server::TlsStream<TcpStream>>;

async fn quick_edge() -> (SocketAddr, Accepted, Trust) {
    let (ca_key, leaf_key) = (Signer::new(), Signer::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-edge-ca");
    // With no crypto feature, rcgen draws no serial number of its own.
    ca.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, &ca_key);
    let mut leaf = rcgen::CertificateParams::new(vec![edge::SERVER_NAME.to_string()]).unwrap();
    leaf.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    let certified = rustls::sign::CertifiedKey::new(vec![leaf.der().clone()], leaf_key.0.signer());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(podssh_ws::crypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, conns) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            if let Ok(tls) = acceptor.accept(tcp).await {
                let _ = accepted.send(tls);
            }
        }
    });
    let mut store = rustls::RootCertStore::empty();
    store.add(ca_cert.der().clone()).unwrap();
    let roots = podssh_ws::tls::TlsRoots { roots: store, source: "the test's CA".into(), count: 1 };
    let trust = Trust::caller(podssh_ws::tls::client_config(&roots).unwrap()).unwrap();
    (addr, conns, trust)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_registers_through_warp_s_tunnel_and_a_visitor_passes() {
    let (edge_addr, mut conns, trust) = quick_edge().await;
    let key = DeviceKey::generate().unwrap();
    let route = Route { inside: INSIDE, outside: edge_addr };
    let warp_edge = StandIn::start(vec![key.point()], vec![route]).await.unwrap();
    let warp = podssh_warp::Warp::open(&warp_edge.device(key), &ProxyChoice::Direct, LIMIT)
        .await
        .expect("WARP's tunnel to the stand-in opens");
    // The edge by its address inside the tunnel, as its SRV record names
    // regions that the tunnel reaches.
    let found = Edge { regions: vec![INSIDE.ip().to_string()], port: edge::PORT, fixed: None };
    let tls = tokio::time::timeout(LIMIT, edge_warp::connect(&warp, &found, &trust))
        .await
        .expect("in time")
        .expect("the edge's TLS inside WARP's tunnel");
    assert_eq!(warp_edge.carried(), 1, "the stream to the edge went through WARP's stand-in");
    let (mut steps, stop, served) = node_with(tls, echo);

    // The edge's end: the client of HTTP/2, on the connection that came
    // through the tunnel.
    let edge_io = tokio::time::timeout(LIMIT, conns.recv()).await.expect("a connection in time").unwrap();
    let (mut client, connection) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(connection);
    let (_to_node, _from_node) = register(&mut client, &mut steps).await;
    let (mut visitor_out, mut visitor_in) = visitor(&mut client).await;
    assert_eq!(steps.recv().await, Some(Step::Visitor));
    let message = Frame { fin: true, opcode: 0x2, payload: b"through warp".to_vec() };
    visitor_out.send_data(Bytes::from(frame::encode(&message, Role::Client, [3, 1, 4, 1])), false).unwrap();
    let echoed = read_frame(&mut visitor_in).await;
    assert_eq!((echoed.opcode, echoed.payload.as_slice()), (0x2, &b"through warp"[..]));
    assert!(conns.try_recv().is_err(), "the edge's stand-in saw one connection alone");

    stop.send(()).unwrap();
    drop((visitor_out, visitor_in));
    let _ = tokio::time::timeout(LIMIT, served).await;
}

/// The edge at an address that the tunnel does not reach gives the node a
/// line that names the road and the region, within the dial's limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edge_that_the_tunnel_does_not_reach_is_named() {
    let (_, _conns, trust) = quick_edge().await;
    let key = DeviceKey::generate().unwrap();
    let warp_edge = StandIn::start(vec![key.point()], vec![]).await.unwrap();
    let warp = podssh_warp::Warp::open(&warp_edge.device(key), &ProxyChoice::Direct, LIMIT).await.unwrap();
    let found = Edge { regions: vec![INSIDE.ip().to_string()], port: edge::PORT, fixed: None };
    let why = match edge_warp::connect(&warp, &found, &trust).await {
        Ok(_) => panic!("an edge where the tunnel reaches none"),
        Err(why) => why,
    };
    assert!(why.contains("inside WARP's tunnel") && why.contains("198.51.100.7:7844"), "{why}");
    assert_eq!(warp_edge.carried(), 0);
}
