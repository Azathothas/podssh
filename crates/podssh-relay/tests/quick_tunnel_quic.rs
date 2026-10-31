//! The quick tunnel over QUIC (T-301), against a stand-in edge on the
//! loopback: QUIC at both ends through noq, both TLS handshakes on podssh's
//! own provider; the stand-in's certificate for `quic.cftunnel.com` made by
//! rcgen and signed with P-256 under a CA of the test, which the node trusts;
//! the registration's messages and the streams' requests and answers as the
//! reference encoder wrote them (`tests/fixtures/quick/`).
#![cfg(feature = "quick")]

mod quick_harness;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use noq::crypto::rustls::QuicServerConfig;
use noq::crypto::{CryptoError, HandshakeTokenKey};
use noq::{Connection, Endpoint, ServerConfig, TokioRuntime};
use podssh_relay::quick::serve::{Ended, Step};
use podssh_relay::quick::{connect, quic, quic_serve};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::tls::TlsRoots;
use quick_harness::{echo, empty_return, registration, BOOTSTRAP, CALL_REGISTER, CALL_UNREGISTER, FINISH, LIMIT};
use quick_harness::{RETURN_DETAILS, RETURN_REFUSED};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

const REQUEST: &[u8] = include_bytes!("fixtures/quick/quic-connect-request.bin");
const RESPONSE: &[u8] = include_bytes!("fixtures/quick/quic-connect-response.bin");
const HTTP: &[u8] = include_bytes!("fixtures/quick/quic-connect-http.bin");
const REFUSAL: &[u8] = include_bytes!("fixtures/quick/quic-connect-refusal.bin");

/// A P-256 key, for rcgen's certificates and for rustls's handshake.
struct Key {
    signing: Arc<p256::ecdsa::SigningKey>,
    public: Vec<u8>,
}

impl Key {
    fn new() -> Key {
        use p256::elliptic_curve::Generate;
        let signing = p256::ecdsa::SigningKey::generate();
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key { signing: Arc::new(signing), public }
    }
}

/// An ECDSA signature in DER, as X.509 and TLS carry it.
fn sign(key: &p256::ecdsa::SigningKey, message: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::Signature = key.sign(message);
    signature.to_der().as_bytes().to_vec()
}

impl rcgen::PublicKeyData for Key {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(sign(&self.signing, message))
    }
}

/// The stand-in's TLS key, for rustls.
struct TlsKey(Arc<p256::ecdsa::SigningKey>);

impl std::fmt::Debug for TlsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsKey(P-256)")
    }
}

impl rustls::sign::SigningKey for TlsKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        let scheme = rustls::SignatureScheme::ECDSA_NISTP256_SHA256;
        offered.contains(&scheme).then(|| Box::new(TlsKey(self.0.clone())) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

impl rustls::sign::Signer for TlsKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(sign(&self.0, message))
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[derive(Debug)]
struct OneCertificate(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for OneCertificate {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The stand-in's tokens: a tag of zeros, as none of them guards anything.
struct TestTokens;

impl HandshakeTokenKey for TestTokens {
    fn seal(&self, _nonce: u128, data: &mut Vec<u8>) -> Result<(), CryptoError> {
        data.extend_from_slice(&[0; 16]);
        Ok(())
    }

    fn open<'a>(&self, _nonce: u128, data: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        let len = data.len().checked_sub(16).ok_or(CryptoError)?;
        if data[len..].iter().any(|&b| b != 0) {
            return Err(CryptoError);
        }
        Ok(&data[..len])
    }
}

/// The stand-in edge: an endpoint on the loopback that takes QUIC with the
/// ALPN `argotunnel` and a certificate for the edge's name; and the roots
/// that trust it.
fn edge() -> (Endpoint, SocketAddr, TlsRoots) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-edge-ca");
    // With no crypto feature, rcgen draws no serial number of its own.
    ca.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, &ca_key);
    let mut leaf = rcgen::CertificateParams::new(vec![quic::SERVER_NAME.to_string()]).unwrap();
    leaf.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    let ca_der: CertificateDer<'static> = ca_cert.der().clone();
    let chain = vec![leaf.der().clone(), ca_der.clone()];
    let certified = rustls::sign::CertifiedKey::new(chain, Arc::new(TlsKey(leaf_key.signing.clone())));
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(podssh_ws::crypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OneCertificate(Arc::new(certified))));
    tls.alpn_protocols = vec![quic::ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls).expect("QUIC's TLS of the stand-in");
    let server = ServerConfig::new(Arc::new(crypto), Arc::new(TestTokens));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = socket.local_addr().unwrap();
    let endpoint = Endpoint::new(quic::endpoint_config().unwrap(), Some(server), socket, Arc::new(TokioRuntime));
    let mut roots = TlsRoots { roots: rustls::RootCertStore::empty(), source: "the test's CA".into(), count: 1 };
    roots.roots.add(ca_der).unwrap();
    (endpoint.unwrap(), addr, roots)
}

/// A forwarder of datagrams between the node and `edge`, on the loopback,
/// and the switch that cuts both ways, as a path that falls silent: no
/// close, no error, nothing.
async fn forwarder(edge: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
    let near = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let far = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    far.connect(edge).await.unwrap();
    let (addr, cut) = (near.local_addr().unwrap(), Arc::new(AtomicBool::new(false)));
    let cutting = cut.clone();
    tokio::spawn(async move {
        let (mut node, mut a, mut b) = (None, vec![0u8; 65536], vec![0u8; 65536]);
        loop {
            tokio::select! {
                Ok((n, from)) = near.recv_from(&mut a) => {
                    node = Some(from);
                    if !cutting.load(Ordering::SeqCst) {
                        let _ = far.send(&a[..n]).await;
                    }
                }
                Ok(n) = far.recv(&mut b) => {
                    if let (Some(node), false) = (node, cutting.load(Ordering::SeqCst)) {
                        let _ = near.send_to(&b[..n], node).await;
                    }
                }
            }
        }
    });
    (addr, cut)
}

type Served = tokio::task::JoinHandle<Result<(), Ended>>;

/// The node: QUIC to the stand-in at `addr`, served with the test's
/// registration, each visitor echoed; and the edge's end of the connection.
async fn node(edge: &Endpoint, addr: SocketAddr, roots: &TlsRoots) -> (Connection, Served, Steps) {
    let endpoint = quic::endpoint(false).unwrap();
    let tls = quic::tls(roots).unwrap();
    let dialed = tokio::spawn(async move {
        let connection = quic::connect(&endpoint, addr, quic::SERVER_NAME, tls).await;
        (endpoint, connection)
    });
    let incoming = timeout(LIMIT, edge.accept()).await.unwrap().expect("a connection");
    let at_edge = timeout(LIMIT, incoming).await.unwrap().expect("the handshake");
    let (endpoint, connection) = dialed.await.unwrap();
    let connection = connection.expect("the node's connection");
    let (steps, heard) = mpsc::unbounded_channel();
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        // The endpoint lives as long as its connection.
        let _endpoint = endpoint;
        let stop = async move {
            let _ = stopped.await;
        };
        quic_serve::serve(connection, &registration(), echo, steps, stop).await
    });
    (at_edge, served, Steps { heard, stop: Some(stop) })
}

struct Steps {
    heard: mpsc::UnboundedReceiver<Step>,
    stop: Option<oneshot::Sender<()>>,
}

impl Steps {
    async fn next(&mut self) -> Option<Step> {
        timeout(LIMIT, self.heard.recv()).await.expect("a step in time")
    }
}

/// The control stream, the first that the node opens, registered: the edge's
/// ends of it, the node's `Finish` read.
async fn register(edge: &Connection, answer: &[u8]) -> (noq::SendStream, noq::RecvStream) {
    let (mut to_node, mut from_node) = timeout(LIMIT, edge.accept_bi()).await.unwrap().expect("the control stream");
    let mut first = vec![0u8; BOOTSTRAP.len() + CALL_REGISTER.len()];
    timeout(LIMIT, from_node.read_exact(&mut first)).await.unwrap().unwrap();
    assert_eq!(first, [BOOTSTRAP, CALL_REGISTER].concat(), "the registration, as over HTTP/2");
    to_node.write_all(&[empty_return(0), answer.to_vec()].concat()).await.unwrap();
    (to_node, from_node)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_visitor_s_websocket_crosses_quic_whole_and_the_end_unregisters() {
    let (edge, addr, roots) = edge();
    let (at_edge, served, mut steps) = node(&edge, addr, &roots).await;
    let alpn = at_edge.handshake_data().and_then(|d| d.downcast::<noq::crypto::rustls::HandshakeData>().ok());
    assert_eq!(alpn.and_then(|d| d.protocol).as_deref(), Some(quic::ALPN));
    let (mut to_node, mut from_node) = register(&at_edge, RETURN_DETAILS).await;
    assert_eq!(steps.next().await, Some(Step::Registered { location: "msp01".into() }));
    let mut finish = vec![0u8; FINISH.len()];
    timeout(LIMIT, from_node.read_exact(&mut finish)).await.unwrap().unwrap();
    assert_eq!(finish, FINISH);

    // A visitor: its request, and the start of its first frame in the same
    // write, as the edge may send them.
    let (mut send, mut recv) = at_edge.open_bi().await.unwrap();
    let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i.wrapping_mul(7) % 251) as u8).collect();
    let frames: Vec<u8> = payload
        .chunks(64 * 1024)
        .flat_map(|c| frame::encode(&Frame { fin: true, opcode: 0x2, payload: c.to_vec() }, Role::Client, [1, 2, 3, 4]))
        .collect();
    send.write_all(&[&connect::preamble()[..], REQUEST, &frames[..1000]].concat()).await.unwrap();
    let mut answer = vec![0u8; connect::PREAMBLE + RESPONSE.len()];
    timeout(LIMIT, recv.read_exact(&mut answer)).await.unwrap().unwrap();
    assert_eq!(answer, [&connect::preamble()[..], RESPONSE].concat(), "101, as the reference wrote it");
    assert_eq!(steps.next().await, Some(Step::Visitor));
    let rest = frames[1000..].to_vec();
    let writer = tokio::spawn(async move {
        send.write_all(&rest).await.unwrap();
        send
    });
    let (mut back, mut inbox, mut chunk) = (Vec::new(), Vec::new(), vec![0u8; 64 * 1024]);
    while back.len() < payload.len() {
        let n = timeout(LIMIT, recv.read(&mut chunk)).await.unwrap().unwrap().expect("the echo");
        inbox.extend_from_slice(&chunk[..n]);
        while let Ok(Some((frame, used))) = frame::decode(&inbox, Role::Server) {
            inbox.drain(..used);
            back.extend_from_slice(&frame.payload);
        }
    }
    assert_eq!(Sha256::digest(&back), Sha256::digest(&payload), "each byte back, in order");
    let _send = writer.await.unwrap();

    // Another request: 404, as the reference wrote it, and the stream's end.
    let (mut send, mut recv) = at_edge.open_bi().await.unwrap();
    send.write_all(&[&connect::preamble()[..], HTTP].concat()).await.unwrap();
    let refused = timeout(LIMIT, recv.read_to_end(4096)).await.unwrap().unwrap();
    assert_eq!(refused, [&connect::preamble()[..], REFUSAL].concat());

    // An RPC stream of the edge: refused, with nothing written.
    let (mut send, mut recv) = at_edge.open_bi().await.unwrap();
    send.write_all(&[&connect::RPC_STREAM[..], &connect::VERSION[..]].concat()).await.unwrap();
    let read = timeout(LIMIT, recv.read(&mut chunk)).await.unwrap();
    assert!(read.is_err(), "the node resets an RPC stream: {read:?}");

    // The end: the unregistration on the control stream, then Ok.
    steps.stop.take().unwrap().send(()).unwrap();
    let mut unregister = vec![0u8; CALL_UNREGISTER.len()];
    timeout(LIMIT, from_node.read_exact(&mut unregister)).await.unwrap().unwrap();
    assert_eq!(unregister, CALL_UNREGISTER);
    to_node.write_all(&empty_return(2)).await.unwrap();
    assert_eq!(steps.next().await, Some(Step::Unregistered));
    let served = timeout(LIMIT, served).await.unwrap().unwrap();
    assert!(served.is_ok(), "{served:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_registration_ends_the_connection_with_the_edge_s_cause() {
    let (edge, addr, roots) = edge();
    let (at_edge, served, _steps) = node(&edge, addr, &roots).await;
    let _control = register(&at_edge, RETURN_REFUSED).await;
    let served = timeout(LIMIT, served).await.unwrap().unwrap();
    assert!(matches!(served, Err(Ended::Refused { .. })), "{served:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edge_that_closes_and_one_that_falls_silent_end_the_connection() {
    let (edge, addr, roots) = edge();
    let (at_edge, served, mut steps) = node(&edge, addr, &roots).await;
    let _control = register(&at_edge, RETURN_DETAILS).await;
    assert_eq!(steps.next().await, Some(Step::Registered { location: "msp01".into() }));
    at_edge.close(noq::VarInt::from_u32(0), b"going away");
    let served = timeout(LIMIT, served).await.unwrap().unwrap();
    assert!(matches!(served, Err(Ended::Closed)), "{served:?}");

    // A path that falls silent, with no close: the node's keepalives go
    // unanswered, and its silence of 5 s ends the connection.
    let (edge, addr, roots) = self::edge();
    let (through, cut) = forwarder(addr).await;
    let (at_edge, served, mut steps) = node(&edge, through, &roots).await;
    let _control = register(&at_edge, RETURN_DETAILS).await;
    assert_eq!(steps.next().await, Some(Step::Registered { location: "msp01".into() }));
    let started = tokio::time::Instant::now();
    cut.store(true, Ordering::SeqCst);
    let served = timeout(LIMIT, served).await.unwrap().unwrap();
    let took = started.elapsed();
    assert!(matches!(served, Err(Ended::Silent)), "{served:?}");
    assert!(took >= quic::SILENCE - std::time::Duration::from_secs(1) && took < quic::SILENCE * 2, "{took:?}");
}

/// The edge as `podssh doctor` probes it (T-359): one region at `host`.
fn found(hosts: &[&str], port: u16) -> podssh_relay::quick::edge::Edge {
    podssh_relay::quick::edge::Edge { regions: hosts.iter().map(|h| h.to_string()).collect(), port, fixed: None }
}

#[tokio::test(flavor = "multi_thread")]
async fn doctors_handshake_answers_and_closes_with_nothing_registered() {
    let (edge, addr, roots) = edge();
    let region = found(&["127.0.0.1"], addr.port());
    let probe = tokio::spawn(async move { quic::handshake(&region, quic::tls(&roots).unwrap()).await });
    let incoming = timeout(LIMIT, edge.accept()).await.unwrap().expect("a connection");
    let at_edge = timeout(LIMIT, incoming).await.unwrap().expect("the handshake");
    let (answered, took) = timeout(LIMIT, probe).await.unwrap().unwrap().expect("an answer");
    assert_eq!(answered, addr);
    assert!(took < quic::HANDSHAKE_WAIT, "{took:?}");
    // Closed at once, with no stream: nothing is registered at the edge.
    assert!(timeout(LIMIT, at_edge.accept_bi()).await.expect("an end in time").is_err(), "a stream was opened");
    let closed = timeout(LIMIT, at_edge.closed()).await.expect("closed in time");
    assert!(matches!(closed, noq::ConnectionError::ApplicationClosed(_)), "{closed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn doctors_handshake_with_a_silent_edge_says_that_none_answered() {
    // A port that takes each datagram and answers none, as a network that
    // drops UDP further on.
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (_edge, _, roots) = edge();
    let region = found(&["127.0.0.1"], silent.local_addr().unwrap().port());
    let started = std::time::Instant::now();
    let why = timeout(LIMIT, quic::handshake(&region, quic::tls(&roots).unwrap()))
        .await
        .unwrap()
        .expect_err("no answer from a silent edge");
    let took = started.elapsed();
    assert!(why.contains("no region of the edge answered over QUIC") && why.contains("within 5 s"), "{why}");
    let wait = quic::HANDSHAKE_WAIT;
    assert!(took >= wait - std::time::Duration::from_millis(100) && took < wait * 2, "{took:?}");
    drop(silent);
}

/// The regions at once, where the node tries them in turn: a silent first
/// region costs doctor no wait. Linux only, where all of 127/8 is the
/// loopback.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn doctors_handshake_tries_the_regions_at_once() {
    let (edge, addr, roots) = edge();
    let silent = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), addr.port())).unwrap();
    let regions = found(&["127.0.0.2", "127.0.0.1"], addr.port());
    let started = std::time::Instant::now();
    let probe = tokio::spawn(async move { quic::handshake(&regions, quic::tls(&roots).unwrap()).await });
    let incoming = timeout(LIMIT, edge.accept()).await.unwrap().expect("a connection");
    let _at_edge = timeout(LIMIT, incoming).await.unwrap().expect("the handshake");
    let (answered, _) = timeout(LIMIT, probe).await.unwrap().unwrap().expect("an answer");
    let took = started.elapsed();
    assert_eq!(answered, addr, "the region that answers, not the silent one");
    assert!(took < quic::HANDSHAKE_WAIT, "the silent region was waited for: {took:?}");
    drop(silent);
}
