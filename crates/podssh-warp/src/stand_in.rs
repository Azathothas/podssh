//! A stand-in of WARP's edge on the loopback, for tests here and in another
//! crate (feature `stand-in`): TLS 1.3 with ALPN `h2`, a certificate of its
//! own key, which a device pins, and a client's certificate required, whose
//! key must be one that it enrolled, else the alert `access_denied`, as the
//! edge refuses a key that it does not know (usque: "tls: access denied").
//! HTTP/2 is h2's server; the CONNECT must be connect-ip's as the edge reads
//! it. Inside, a smoltcp stack of its own answers at each route's address
//! and port, and carries each connection to a service of the loopback, as
//! Cloudflare's network carries one to its target. It counts what it saw,
//! so that a test can tell that a stream went through it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use rustls_pki_types::{CertificateDer, UnixTime};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;

use crate::device::Device;
use crate::key::DeviceKey;
use crate::stack::{Stack, Why};

/// The device's address inside the stand-in's tunnel.
pub const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(172, 16, 0, 2);

/// A connection inside the tunnel to `inside`, carried to `outside` on the
/// loopback.
#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub inside: SocketAddr,
    pub outside: SocketAddr,
}

/// What the stand-in saw.
#[derive(Debug)]
pub struct Seen {
    /// TLS connections that it accepted.
    pub connections: AtomicUsize,
    /// CONNECTs that it answered with 200.
    pub tunnels: AtomicUsize,
    /// Connections inside that it carried to the loopback.
    pub carried: AtomicUsize,
    /// The headers of the last CONNECT, names in lower case, and its
    /// authority.
    pub headers: Mutex<Vec<(String, String)>>,
    pub authority: Mutex<Option<String>>,
    /// Set to end each connection at once, as an edge that goes away.
    cut: tokio::sync::watch::Sender<bool>,
}

impl Default for Seen {
    fn default() -> Seen {
        Seen {
            connections: AtomicUsize::new(0),
            tunnels: AtomicUsize::new(0),
            carried: AtomicUsize::new(0),
            headers: Mutex::new(Vec::new()),
            authority: Mutex::new(None),
            cut: tokio::sync::watch::Sender::new(false),
        }
    }
}

/// The stand-in, which serves until it is dropped.
pub struct StandIn {
    pub addr: SocketAddr,
    key: DeviceKey,
    pub seen: Arc<Seen>,
    task: AbortHandle,
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug)]
struct Enrolled {
    points: Vec<Vec<u8>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for Enrolled {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let point = crate::der::spki_of_certificate(end_entity).and_then(crate::der::p256_point);
        match point {
            Some(point) if self.points.iter().any(|enrolled| enrolled.as_slice() == point) => {
                Ok(ClientCertVerified::assertion())
            }
            // rustls answers this with the alert access_denied.
            _ => Err(Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl StandIn {
    /// A stand-in on 127.0.0.1 that enrolled the keys of the SEC1 points
    /// `enrolled`, with `routes` inside.
    pub async fn start(enrolled: Vec<Vec<u8>>, routes: Vec<Route>) -> std::io::Result<StandIn> {
        StandIn::start_with(DeviceKey::generate().map_err(std::io::Error::other)?, enrolled, routes).await
    }

    /// [`StandIn::start`] with the endpoint's key `key`, as a stand-in of
    /// the API gave it to a device.
    pub async fn start_with(key: DeviceKey, enrolled: Vec<Vec<u8>>, routes: Vec<Route>) -> std::io::Result<StandIn> {
        let provider = Arc::new(podssh_ws::crypto::provider());
        let verifier = Arc::new(Enrolled { points: enrolled, algorithms: provider.signature_verification_algorithms });
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let certified = key.certified(now as i64 - 60);
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(std::io::Error::other)?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
        config.alpn_protocols = vec![crate::tls::ALPN.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let seen = Arc::new(Seen::default());
        let (routes, counted) = (Arc::new(routes), seen.clone());
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(serve(tcp, acceptor.clone(), routes.clone(), counted.clone()));
            }
        });
        Ok(StandIn { addr, key, seen, task: task.abort_handle() })
    }

    /// The point of the stand-in's key, which a device pins.
    pub fn point(&self) -> Vec<u8> {
        self.key.point()
    }

    /// A device of `key` whose endpoint is this stand-in.
    pub fn device(&self, key: DeviceKey) -> Device {
        let pem = crate::der::pem(&self.key.spki(), "PUBLIC KEY");
        let registered = "2026-10-31T00:00:00.000+00:00".to_string();
        let (id, token) = ("stand-in".to_string(), "stand-in".to_string());
        Device::new(id, token, key, &pem, self.addr, Some(CLIENT_V4), None, registered, false)
            .expect("the stand-in's own key reads")
    }

    pub fn tunnels(&self) -> usize {
        self.seen.tunnels.load(Ordering::SeqCst)
    }

    /// End each connection of a client at once, with no word.
    pub fn cut(&self) {
        self.seen.cut.send_replace(true);
    }

    pub fn carried(&self) -> usize {
        self.seen.carried.load(Ordering::SeqCst)
    }
}

/// One connection of a client: TLS, HTTP/2, and each CONNECT that it asks.
async fn serve(tcp: TcpStream, acceptor: tokio_rustls::TlsAcceptor, routes: Arc<Vec<Route>>, seen: Arc<Seen>) {
    let Ok(tls) = acceptor.accept(tcp).await else { return };
    seen.connections.fetch_add(1, Ordering::SeqCst);
    let handshake = h2::server::Builder::new()
        .initial_window_size(crate::tunnel::STREAM_WINDOW)
        .initial_connection_window_size(crate::tunnel::CONNECTION_WINDOW)
        .handshake::<_, Bytes>(tls);
    let Ok(mut connection) = handshake.await else { return };
    let mut cut = seen.cut.subscribe();
    // Each request; the loop drives the connection while its streams run.
    loop {
        let next = tokio::select! {
            next = connection.accept() => next,
            _ = cut.wait_for(|cut| *cut) => return,
        };
        let Some(Ok((request, mut respond))) = next else { return };
        let authority = request.uri().authority().map(|a| a.as_str().to_string());
        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.to_str().unwrap_or_default().to_string()))
            .collect();
        let connect_ip = request.method() == http::Method::CONNECT
            && authority.as_deref() == Some(crate::AUTHORITY)
            && request.headers().get("cf-connect-proto").is_some_and(|v| v == "cf-connect-ip");
        *seen.authority.lock().unwrap_or_else(PoisonError::into_inner) = authority;
        *seen.headers.lock().unwrap_or_else(PoisonError::into_inner) = headers;
        let status = if connect_ip { 200 } else { 400 };
        let Ok(response) = http::Response::builder().status(status).body(()) else { continue };
        let Ok(send) = respond.send_response(response, !connect_ip) else { continue };
        if !connect_ip {
            continue;
        }
        seen.tunnels.fetch_add(1, Ordering::SeqCst);
        let link = crate::tunnel::pump(request.into_body(), send, Why::default());
        far(link, &routes, &seen);
    }
}

/// The far end of one tunnel: a stack at the routes' addresses, and each
/// connection that comes to a route carried to its service.
fn far(link: crate::stack::Link, routes: &[Route], seen: &Arc<Seen>) {
    let mut addresses: Vec<IpAddr> = Vec::new();
    for route in routes {
        if !addresses.contains(&route.inside.ip()) {
            addresses.push(route.inside.ip());
        }
    }
    if addresses.is_empty() {
        addresses.push(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    }
    let Ok(stack) = Stack::start(&addresses, link) else { return };
    for route in routes.iter().copied() {
        let Ok(mut listener) = stack.listen(route.inside) else { continue };
        let seen = seen.clone();
        tokio::spawn(async move {
            while let Ok(mut inside) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let Ok(mut outside) = TcpStream::connect(route.outside).await else { return };
                    seen.carried.fetch_add(1, Ordering::SeqCst);
                    let _ = tokio::io::copy_bidirectional(&mut inside, &mut outside).await;
                });
            }
        });
    }
    // The stack lives as long as its tunnel, with a route or none.
    tokio::spawn(async move { stack.closed().await });
}
