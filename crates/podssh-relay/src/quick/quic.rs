//! The quick tunnel over QUIC (T-301), as cloudflared makes one when no
//! protocol is named: QUIC to UDP port 7844 of the edge, with the name
//! `quic.cftunnel.com` and the ALPN `argotunnel` (`connection/protocol.go`),
//! and cloudflared's settings of the transport (`quic/constants.go`,
//! `connection/quic_config.go`): 5 s for the handshake and for a silence, a
//! keepalive each second, first packets of 1232 bytes over IPv4 and 1252 over
//! IPv6, and datagrams on. QUIC is UDP, which no HTTP proxy carries, so the
//! node takes it only with no proxy set; its socket is the connection's own,
//! on a port that the system picks, and nothing listens on it.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use noq::crypto::rustls::QuicClientConfig;
use noq::crypto::{CryptoError, HmacKey};
use noq::{ClientConfig, Connection, Endpoint, EndpointConfig, IdleTimeout, TokioRuntime, TransportConfig, VarInt};
use podssh_ws::tls::TlsRoots;
use sha2::Sha256;

use super::edge;

/// The name of the edge's certificate over QUIC, and the ALPN.
pub const SERVER_NAME: &str = "quic.cftunnel.com";
pub const ALPN: &[u8] = b"argotunnel";
/// cloudflared's `HandshakeIdleTimeout`, `MaxIdleTimeout` and
/// `MaxIdlePingPeriod`.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);
pub const SILENCE: Duration = Duration::from_secs(5);
pub const KEEPALIVE: Duration = Duration::from_secs(1);
/// cloudflared's first packets, for paths whose MTU is 1280.
pub const FIRST_PACKET_V4: u16 = 1232;
pub const FIRST_PACKET_V6: u16 = 1252;
/// The streams that the edge may open at once: as HTTP/2's, as a quick
/// tunnel takes 200 requests in flight.
pub const MAX_STREAMS: u32 = 256;
/// The datagrams that may wait: podssh routes no private network and reads
/// none, but takes them as cloudflared does.
const DATAGRAMS: usize = 64 * 1024;

/// TLS 1.3 alone, as QUIC needs, with `roots` and the ALPN.
pub fn tls(roots: &TlsRoots) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(podssh_ws::crypto::provider());
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots.roots.clone()), provider.clone())
            .build()
            .map_err(|e| format!("the edge's certificate verifier: {e}"))?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// The settings of the transport toward an address of the family `v6`.
fn transport(v6: bool) -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(IdleTimeout::try_from(SILENCE).ok())
        .keep_alive_interval(Some(KEEPALIVE))
        .initial_mtu(if v6 { FIRST_PACKET_V6 } else { FIRST_PACKET_V4 })
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS))
        .datagram_receive_buffer_size(Some(DATAGRAMS));
    transport
}

/// The key of the stateless resets that the endpoint could send: random for
/// each endpoint, as noq's default is, and HMAC-SHA-256 in pure Rust.
struct ResetKey(Hmac<Sha256>);

impl ResetKey {
    fn random() -> Result<ResetKey, String> {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut key).map_err(|e| format!("no randomness for QUIC: {e}"))?;
        Hmac::new_from_slice(&key).map(ResetKey).map_err(|e| e.to_string())
    }
}

impl HmacKey for ResetKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut mac = self.0.clone();
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        let n = signature_out.len().min(tag.len());
        signature_out[..n].copy_from_slice(&tag[..n]);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut mac = self.0.clone();
        mac.update(data);
        mac.verify_slice(signature).map_err(|_| CryptoError)
    }
}

/// The configuration of an endpoint, with a reset key of its own.
pub fn endpoint_config() -> Result<EndpointConfig, String> {
    Ok(EndpointConfig::new(Arc::new(ResetKey::random()?)))
}

/// An endpoint for one connection: a UDP socket of the family `v6`, on a
/// port that the system picks. A socket that does not bind is the probe's
/// answer: no QUIC here.
pub fn endpoint(v6: bool) -> Result<Endpoint, String> {
    let socket = match v6 {
        true => UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)),
        false => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)),
    }
    .map_err(|e| format!("no UDP socket for QUIC: {e}"))?;
    Endpoint::new(endpoint_config()?, None, socket, Arc::new(TokioRuntime))
        .map_err(|e| format!("no QUIC endpoint: {e}"))
}

/// A QUIC connection to `addr` as `server_name`, within the handshake's wait.
pub async fn connect(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Connection, String> {
    let crypto = QuicClientConfig::try_from(tls).map_err(|e| format!("QUIC's TLS: {e}"))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport(addr.is_ipv6())));
    let connecting = endpoint.connect_with(config, addr, server_name).map_err(|e| format!("{addr}: {e}"))?;
    match tokio::time::timeout(HANDSHAKE_WAIT, connecting).await {
        Ok(Ok(connection)) => Ok(connection),
        Ok(Err(e)) => Err(format!("{addr}: QUIC: {e}")),
        Err(_) => Err(format!("{addr}: no answer over QUIC within {} s", HANDSHAKE_WAIT.as_secs())),
    }
}

/// A connection to the edge over QUIC, with the endpoint that carries it.
pub struct EdgeConnection {
    endpoint: Endpoint,
    connection: Connection,
}

impl EdgeConnection {
    /// Serve it as `quic_serve::serve` does, then let the endpoint go.
    pub async fn serve<V, F>(
        self,
        registration: &super::register::Registration<'_>,
        visit: V,
        steps: tokio::sync::mpsc::UnboundedSender<super::serve::Step>,
        stop: impl std::future::Future<Output = ()>,
    ) -> Result<(), super::serve::Ended>
    where
        V: FnMut(tokio::io::DuplexStream) -> F,
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let served = super::quic_serve::serve(self.connection, registration, visit, steps, stop).await;
        self.endpoint.close(VarInt::from_u32(0), b"");
        served
    }
}

/// QUIC to the edge: each region in turn, at its first address of each
/// family that it has.
pub async fn connect_edge() -> Result<EdgeConnection, String> {
    let tls = tls(&edge::roots()?)?;
    let mut failed = Vec::new();
    for region in edge::REGIONS {
        let deadline = tokio::time::Instant::now() + edge::DIAL_LIMIT;
        let addrs = match podssh_ws::resolve::resolve(region, edge::PORT, deadline).await {
            Ok(addrs) => addrs,
            Err(e) => {
                failed.push(format!("{region}: {e}"));
                continue;
            }
        };
        let firsts = [addrs.iter().find(|a| a.is_ipv4()), addrs.iter().find(|a| a.is_ipv6())];
        for addr in firsts.into_iter().flatten() {
            let endpoint = match endpoint(addr.is_ipv6()) {
                Ok(endpoint) => endpoint,
                Err(e) => {
                    failed.push(e);
                    continue;
                }
            };
            match connect(&endpoint, *addr, SERVER_NAME, tls.clone()).await {
                Ok(connection) => return Ok(EdgeConnection { endpoint, connection }),
                Err(e) => failed.push(format!("{region} {e}")),
            }
        }
    }
    Err(format!("no region of the edge answered over QUIC: {}", failed.join("; ")))
}
