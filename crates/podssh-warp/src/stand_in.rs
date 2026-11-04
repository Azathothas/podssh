//! A stand-in of WARP's edge on the loopback, for tests here and in another
//! crate (feature `stand-in`): TLS 1.3 with ALPN `h2`, a certificate of its
//! own key, which a device pins, and a client's certificate required, whose
//! key must be one that it enrolled, else the alert `access_denied`, as the
//! edge refuses a key that it does not know (usque: "tls: access denied").
//! HTTP/2 is h2's server; the CONNECT must be connect-ip's as the edge reads
//! it. Inside, a smoltcp stack of its own answers at each route's address
//! and port, and carries each connection to a service of the loopback, as
//! Cloudflare's network carries one to its target. It counts what it saw,
//! so that a test can tell that a stream went through it. A test can change
//! the key that it shows, as WARP's front door showed a new device another
//! key than its record's (T-399). Its far end answers the probe of a tunnel
//! (T-560) at Cloudflare's resolver, as WARP's network does; silenced, it is
//! a front door that takes TLS and the CONNECT, then relays nothing.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
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
    /// Probes of a tunnel (T-560) that its far end answered.
    pub probes: AtomicUsize,
    /// The headers of the last CONNECT, names in lower case, and its
    /// authority.
    pub headers: Mutex<Vec<(String, String)>>,
    pub authority: Mutex<Option<String>>,
    /// Set to end each connection at once, as an edge that goes away.
    cut: tokio::sync::watch::Sender<bool>,
    /// Set to relay nothing in each tunnel answered from then on.
    silent: AtomicBool,
    /// The stack of each tunnel's far end, while it lasts, for a test that
    /// stalls (T-599).
    stacks: Mutex<Vec<std::sync::Weak<crate::stack::Core>>>,
}

impl Default for Seen {
    fn default() -> Seen {
        Seen {
            connections: AtomicUsize::new(0),
            tunnels: AtomicUsize::new(0),
            carried: AtomicUsize::new(0),
            probes: AtomicUsize::new(0),
            headers: Mutex::new(Vec::new()),
            authority: Mutex::new(None),
            cut: tokio::sync::watch::Sender::new(false),
            silent: AtomicBool::new(false),
            stacks: Mutex::new(Vec::new()),
        }
    }
}

/// The stand-in, which serves until it is dropped.
pub struct StandIn {
    pub addr: SocketAddr,
    shown: Arc<Shown>,
    pub seen: Arc<Seen>,
    task: AbortHandle,
}

/// The keys that the stand-in shows, one for each TLS handshake in turn,
/// the last one kept for each after it.
#[derive(Debug)]
struct Shown {
    keys: Mutex<VecDeque<(DeviceKey, Arc<CertifiedKey>)>>,
    hellos: AtomicUsize,
}

impl Shown {
    /// `keys` in turn, each with its certificate of a minute ago.
    fn set(&self, keys: Vec<DeviceKey>) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let certified = keys.into_iter().map(|key| {
            let certified = Arc::new(key.certified(now as i64 - 60));
            (key, certified)
        });
        *self.keys.lock().unwrap_or_else(PoisonError::into_inner) = certified.collect();
    }

    /// The key that stays once the others were shown.
    fn last(&self) -> Option<DeviceKey> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner).back().map(|(key, _)| key.clone())
    }
}

impl ResolvesServerCert for Shown {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.hellos.fetch_add(1, Ordering::SeqCst);
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        if keys.len() > 1 {
            keys.pop_front().map(|(_, certified)| certified)
        } else {
            keys.front().map(|(_, certified)| certified.clone())
        }
    }
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
        let shown = Arc::new(Shown { keys: Mutex::new(VecDeque::new()), hellos: AtomicUsize::new(0) });
        shown.set(vec![key]);
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(std::io::Error::other)?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(shown.clone());
        config.alpn_protocols = vec![crate::tls::ALPN.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        crate::road::forget(addr);
        let seen = Arc::new(Seen::default());
        let (routes, counted) = (Arc::new(routes), seen.clone());
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(serve(tcp, acceptor.clone(), routes.clone(), counted.clone()));
            }
        });
        Ok(StandIn { addr, shown, seen, task: task.abort_handle() })
    }

    /// The key that the stand-in shows, which a device pins: the last of
    /// [`StandIn::show`]'s.
    fn key(&self) -> DeviceKey {
        self.shown.last().expect("the stand-in shows a key")
    }

    /// The point of the stand-in's key, which a device pins.
    pub fn point(&self) -> Vec<u8> {
        self.key().point()
    }

    /// Show `keys` from now on, one for each TLS handshake in turn, the last
    /// one for each after it, as WARP's front door changes its key; none
    /// leaves the keys as they were.
    pub fn show(&self, keys: Vec<DeviceKey>) {
        if !keys.is_empty() {
            self.shown.set(keys);
        }
    }

    /// The TLS handshakes that asked for the stand-in's certificate.
    pub fn hellos(&self) -> usize {
        self.shown.hellos.load(Ordering::SeqCst)
    }

    /// A device of `key` whose endpoint is this stand-in.
    pub fn device(&self, key: DeviceKey) -> Device {
        let pem = crate::der::pem(&self.key().spki(), "PUBLIC KEY");
        let registered = "2026-10-31T00:00:00.000+00:00".to_string();
        let (id, token) = ("stand-in".to_string(), "stand-in".to_string());
        Device::new(id, token, key, &pem, self.addr, Some(CLIENT_V4), None, registered, false)
            .expect("the stand-in's own key reads")
    }

    pub fn tunnels(&self) -> usize {
        self.seen.tunnels.load(Ordering::SeqCst)
    }

    /// The TLS connections that it accepted.
    pub fn connections(&self) -> usize {
        self.seen.connections.load(Ordering::SeqCst)
    }

    /// End each connection of a client at once, with no word.
    pub fn cut(&self) {
        self.seen.cut.send_replace(true);
    }

    /// Each far end's counts and connections, while its tunnel lasts
    /// (T-599).
    pub fn words(&self) -> String {
        let stacks = self.seen.stacks.lock().unwrap_or_else(PoisonError::into_inner);
        let said: Vec<String> = stacks.iter().filter_map(std::sync::Weak::upgrade).map(|core| core.words()).collect();
        if said.is_empty() {
            "no tunnel".to_string()
        } else {
            said.join(" | ")
        }
    }

    pub fn carried(&self) -> usize {
        self.seen.carried.load(Ordering::SeqCst)
    }

    /// The probes of a tunnel (T-560) that the far end answered.
    pub fn probes(&self) -> usize {
        self.seen.probes.load(Ordering::SeqCst)
    }

    /// From now on, each tunnel that the stand-in answers relays nothing:
    /// TLS, HTTP/2 and the CONNECT's 200 as before, then each packet of the
    /// client read and dropped, and none sent back, as a front door that
    /// relays nothing (T-560); `false` carries again.
    pub fn silence(&self, silent: bool) {
        self.seen.silent.store(silent, Ordering::SeqCst);
    }
}

/// A connection whose handshake was refused, after its alert went out. In
/// TLS 1.3 a client's certificate is judged after the client's Finished,
/// so the client's HTTP/2 is already here, unread; a socket closed with
/// unread bytes is reset on Windows, and the reset can reach the client
/// before the alert that names the refusal. The client's end ends it.
async fn drain(mut tcp: TcpStream) {
    use tokio::io::AsyncReadExt as _;
    let mut buf = [0u8; 4096];
    let read_all = async { while matches!(tcp.read(&mut buf).await, Ok(n) if n > 0) {} };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), read_all).await;
}

/// One connection of a client: TLS, HTTP/2, and each CONNECT that it asks.
async fn serve(tcp: TcpStream, acceptor: tokio_rustls::TlsAcceptor, routes: Arc<Vec<Route>>, seen: Arc<Seen>) {
    let tls = match acceptor.accept(tcp).into_fallible().await {
        Ok(tls) => tls,
        Err((_, tcp)) => return drain(tcp).await,
    };
    seen.connections.fetch_add(1, Ordering::SeqCst);
    // The client's budget of small frames too: a test's volume never ends
    // the stand-in's side as h2's own budget would (T-398).
    let handshake = h2::server::Builder::new()
        .initial_window_size(crate::tunnel::STREAM_WINDOW)
        .initial_connection_window_size(crate::tunnel::CONNECTION_WINDOW)
        .data_frame_budget(crate::tunnel::FRAME_BUDGET)
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
        if seen.silent.load(Ordering::SeqCst) {
            tokio::spawn(relay_nothing(request.into_body(), send));
            continue;
        }
        let link = crate::tunnel::pump(request.into_body(), send, Why::default());
        far(link, &routes, &seen);
    }
}

/// A tunnel of a front door that relays nothing (T-560): each packet of the
/// client is read, its window given back, and dropped; the stream of the
/// answer stays open and carries nothing, and the connection's PINGs are
/// answered still, as h2's server answers them.
async fn relay_nothing(mut body: h2::RecvStream, send: h2::SendStream<Bytes>) {
    while let Some(Ok(chunk)) = body.data().await {
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    drop(send);
}

/// The far end of one tunnel: a stack at the routes' addresses, and each
/// connection that comes to a route carried to its service; and the probe's
/// target (T-560), where a route does not take its place.
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
    // The stack keeps two addresses at most: a test with routes at two
    // others gets no answer to the probe, and skips it on its device
    // (`Device::probing`).
    let probe = crate::probe::TARGET_V4;
    if !addresses.contains(&probe.ip()) && addresses.len() < 2 {
        addresses.push(probe.ip());
    }
    let Ok(stack) = Stack::start(&addresses, link) else { return };
    seen.stacks.lock().unwrap_or_else(PoisonError::into_inner).push(Arc::downgrade(stack.core()));
    if addresses.contains(&probe.ip()) && !routes.iter().any(|route| route.inside == probe) {
        answer_probes(&stack, probe, seen);
    }
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

/// The probe's target inside the tunnel: each connection to `at` is taken,
/// counted and closed, as Cloudflare's resolver takes one on its port of
/// TLS; it is never carried to the loopback.
fn answer_probes(stack: &Stack, at: SocketAddr, seen: &Arc<Seen>) {
    let Ok(mut listener) = stack.listen(at) else { return };
    let seen = seen.clone();
    tokio::spawn(async move {
        while let Ok(probe) = listener.accept().await {
            seen.probes.fetch_add(1, Ordering::SeqCst);
            drop(probe);
        }
    });
}
