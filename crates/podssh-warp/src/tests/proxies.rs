//! The road through the proxies of a cage, each a stand-in on the loopback
//! that reads the CONNECT with podssh-ws's reader of requests: one that
//! carries the tunnel, one that allows listed names alone and refuses an
//! address, and one that re-terminates TLS with a certificate of its own
//! CA, made by rcgen.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use podssh_ws::proxy::Proxy;
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::{echo, LIMIT};
use crate::key::DeviceKey;
use crate::road::{Fault, Warp};
use crate::stand_in::{Route, StandIn};

/// What a stand-in proxy does with a CONNECT.
#[derive(Clone)]
enum Mode {
    /// Carries the bytes to the target, as a proxy that allows addresses.
    Pass,
    /// Refuses a target that is an address, with 403.
    NamesOnly,
    /// Answers 200, then TLS with its own certificate.
    Reterminate(tokio_rustls::TlsAcceptor),
}

async fn proxy(mode: Mode) -> ProxyChoice {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let mode = mode.clone();
            tokio::spawn(async move {
                let Ok((request, early)) = podssh_ws::http::read_request(&mut client, Vec::new()).await else { return };
                let Ok((host, port)) = podssh_ws::http::request::connect_target(&request.target) else { return };
                match mode {
                    Mode::NamesOnly if host.parse::<std::net::IpAddr>().is_ok() => {
                        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
                    }
                    Mode::NamesOnly | Mode::Pass => {
                        let Ok(mut target) = TcpStream::connect((host.as_str(), port)).await else { return };
                        let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
                        let _ = target.write_all(&early).await;
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                    }
                    Mode::Reterminate(acceptor) => {
                        let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
                        if let Ok(mut tls) = acceptor.accept(client).await {
                            let _ = tls.read(&mut [0u8; 1]).await;
                        }
                    }
                }
            });
        }
    });
    ProxyChoice::Via(Proxy::parse(&format!("http://{addr}")).unwrap())
}

/// A P-256 key of podssh's own, for rcgen's certificates.
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

/// A certificate for `names` under a CA called `ca`, and its server's TLS.
pub(super) fn tls_server(ca: &str, names: &[&str]) -> (tokio_rustls::TlsAcceptor, rustls::RootCertStore) {
    let (ca_key, leaf_key) = (Signer::new(), Signer::new());
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, ca);
    // With no crypto feature, rcgen draws no serial number of its own.
    ca_params.serial_number = Some(rcgen::SerialNumber::from_slice(&[1, 2, 3, 4]));
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, &ca_key);
    let mut leaf = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    leaf.serial_number = Some(rcgen::SerialNumber::from_slice(&[5, 6, 7, 8]));
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    let certified = rustls::sign::CertifiedKey::new(vec![leaf.der().clone()], leaf_key.0.signer());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(podssh_ws::crypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    (tokio_rustls::TlsAcceptor::from(Arc::new(config)), roots)
}

async fn edge_for(key: &DeviceKey) -> StandIn {
    let route = Route { inside: "192.0.2.10:22".parse().unwrap(), outside: echo().await };
    StandIn::start(vec![key.point()], vec![route]).await.unwrap()
}

/// Through a proxy that allows an address, the tunnel opens, says its
/// proxy, and carries a stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_that_allows_an_address_carries_the_tunnel() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let via = proxy(Mode::Pass).await;
    let warp = Warp::open(&edge.device(key), &via, LIMIT).await.expect("the tunnel through the proxy");
    assert!(warp.proxy.is_some() && warp.via().contains("through the proxy"), "{}", warp.via());
    let mut stream = warp.connect("192.0.2.10", 22, LIMIT).await.unwrap();
    stream.write_all(b"through").await.unwrap();
    let mut back = [0u8; 7];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"through");
}

/// A proxy that allows listed names alone refuses the endpoint's address,
/// and the line says so, with the doctor's line that names the case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_of_names_alone_is_named() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let via = proxy(Mode::NamesOnly).await;
    let fault = Warp::open(&edge.device(key), &via, LIMIT).await.unwrap_err();
    let Fault::Unreachable(line) = &fault else { panic!("{fault:?}") };
    assert!(line.contains("refused CONNECT 127.0.0.1:") && line.contains("403"), "{line}");
    assert!(line.contains("egress takes"), "{line}");
    assert_eq!(edge.tunnels(), 0);
}

/// A proxy that re-terminates TLS is named by its CA, and the road is not
/// tried again through it in the run; the same endpoint without it opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_that_re_terminates_tls_is_named_by_its_ca() {
    let key = DeviceKey::generate().unwrap();
    let edge = edge_for(&key).await;
    let (acceptor, _) = tls_server("Corp Proxy CA", &[crate::SERVER_NAME]);
    let via = proxy(Mode::Reterminate(acceptor)).await;
    let device = edge.device(key);
    let first = Warp::open(&device, &via, LIMIT).await.unwrap_err();
    let Fault::Intercepted(line) = &first else { panic!("{first:?}") };
    assert!(line.contains("CN=Corp Proxy CA") && line.contains("re-terminates TLS"), "{line}");
    let again = Warp::open(&device, &via, LIMIT).await.unwrap_err();
    assert!(again.to_string().contains("not tried again"), "{again}");
    assert_eq!(edge.tunnels(), 0, "no byte of the tunnel went to the proxy's TLS");
    let direct: SocketAddr = edge.addr;
    assert_eq!(device.endpoint, direct);
    assert!(Warp::open(&device, &ProxyChoice::Direct, LIMIT).await.is_ok(), "directly, the pin holds");
}
