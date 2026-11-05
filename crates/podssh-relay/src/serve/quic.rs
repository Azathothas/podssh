//! The relay role over QUIC (T-667): an endpoint on the UDP socket that
//! `podssh relay serve --quic yes` binds beside its TCP listener, at the same
//! address and port. TLS 1.3 with the certificate that the listener presents
//! now ([`Served`], read again on SIGHUP and renewed by ACME), and the ALPN
//! [`ALPN`] alone, so that a client of HTTP/3, or a CA's TLS-ALPN-01, gets no
//! connection here. Each bidirectional stream that a client opens is one
//! connection of HTTP/1.1 to the role's routes ([`super::serve_from`]): its
//! token, its checks, its brake by the client's address and its limits are
//! those of a connection over TCP. The role opens no stream, and keeps
//! nothing of a connection once its streams end.

use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use noq::crypto::rustls::{HandshakeData, QuicServerConfig};
use noq::crypto::{CryptoError, HandshakeTokenKey};
use noq::{Endpoint, IdleTimeout, Incoming, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use podssh_ws::tls_server::Served;
use sha2::Sha256;

use super::Config;
use crate::quic_road::stream::QuicStream;
use crate::quic_road::ALPN;

/// The sessions that one connection may hold at once.
pub const STREAMS: u32 = 64;
/// How long a client has for QUIC's handshake.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);
/// A silence that ends a connection: the client's keepalive is 10 s.
pub const SILENCE: Duration = Duration::from_secs(30);
/// The length of a handshake token's tag.
const TAG: usize = 32;

/// The key that tags the tokens of address validation (a Retry's, and those
/// that a connection gives for the next): HMAC-SHA-256 in pure Rust, of a
/// random key of the process, as noq's own needs a provider of AEAD that
/// podssh's provider does not lend. A token holds the client's own address
/// and a time, nothing secret from it: the tag keeps it from being forged,
/// which is all that a validation needs.
pub struct TokenKey(Hmac<Sha256>);

impl TokenKey {
    pub fn random() -> Result<TokenKey, String> {
        use rand::TryRng;
        let mut key = [0u8; 32];
        rand::rngs::SysRng.try_fill_bytes(&mut key).map_err(|e| format!("no randomness for QUIC: {e}"))?;
        Hmac::new_from_slice(&key).map(TokenKey).map_err(|e| e.to_string())
    }

    fn mac(&self, nonce: u128, data: &[u8]) -> Hmac<Sha256> {
        let mut mac = self.0.clone();
        mac.update(&nonce.to_be_bytes());
        mac.update(data);
        mac
    }
}

impl HandshakeTokenKey for TokenKey {
    fn seal(&self, nonce: u128, data: &mut Vec<u8>) -> Result<(), CryptoError> {
        let tag = self.mac(nonce, data).finalize().into_bytes();
        data.extend_from_slice(&tag[..TAG]);
        Ok(())
    }

    fn open<'a>(&self, nonce: u128, data: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        let data: &'a [u8] = data;
        let len = data.len().checked_sub(TAG).ok_or(CryptoError)?;
        let (body, tag) = data.split_at(len);
        self.mac(nonce, body).verify_slice(tag).map_err(|_| CryptoError)?;
        Ok(body)
    }
}

/// The settings of a connection at the role.
fn transport() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(IdleTimeout::try_from(SILENCE).ok())
        .max_concurrent_bidi_streams(VarInt::from_u32(STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(0));
    transport
}

/// The configuration of the role's QUIC: TLS 1.3 with what `served` holds
/// at each handshake, and [`ALPN`] alone.
pub fn server_config(served: Arc<Served>) -> Result<ServerConfig, String> {
    let provider = Arc::new(podssh_ws::crypto::provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("QUIC's TLS: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(served);
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls).map_err(|e| format!("QUIC's TLS: {e}"))?;
    let mut server = ServerConfig::new(Arc::new(crypto), Arc::new(TokenKey::random()?));
    server.transport_config(Arc::new(transport()));
    Ok(server)
}

/// The role's endpoint on `socket`, a UDP socket that the caller bound; it
/// must be made in a runtime, which drives it.
pub fn endpoint(socket: UdpSocket, served: Arc<Served>) -> Result<Endpoint, String> {
    let server = server_config(served)?;
    let config = crate::quick::quic::endpoint_config()?;
    Endpoint::new(config, Some(server), socket, Arc::new(TokioRuntime)).map_err(|e| format!("no QUIC endpoint: {e}"))
}

/// Serve each connection that `endpoint` takes, until it is closed.
pub async fn serve(endpoint: Endpoint, cfg: Arc<Config>) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(connection(incoming, cfg.clone()));
    }
}

/// One client's connection: its handshake, then each stream that it opens,
/// served as a connection over TCP is, for its address.
async fn connection(incoming: Incoming, cfg: Arc<Config>) {
    // An IPv4 client of a socket of both families, by its IPv4 address, as
    // the brake counts the client over TCP.
    let peer: IpAddr = incoming.remote_address().ip().to_canonical();
    let Ok(connecting) = incoming.accept() else { return };
    let Ok(Ok(connection)) = tokio::time::timeout(HANDSHAKE_WAIT, connecting).await else { return };
    // The name that the client asked for, which a key's signed mint must
    // name (T-448), as over TCP.
    let sni = connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.server_name);
    // A harness counts the connections, as `h2` for HTTP/2's.
    cfg.event("quic");
    while let Ok((send, recv)) = connection.accept_bi().await {
        let stream = QuicStream::new(send, recv, connection.clone());
        tokio::spawn(super::serve_from(stream, cfg.clone(), sni.clone(), Some(peer)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token opens with its own nonce and its bytes, and with nothing
    /// else: a changed byte, another nonce, a cut tag or another key's.
    #[test]
    fn a_token_opens_only_as_it_was_sealed() {
        let (key, other) = (TokenKey::random().unwrap(), TokenKey::random().unwrap());
        let mut token = b"192.0.2.7:51000 at 1793577600".to_vec();
        key.seal(7, &mut token).unwrap();
        assert_eq!(token.len(), 29 + TAG);
        assert_eq!(key.open(7, &mut token.clone()).unwrap(), b"192.0.2.7:51000 at 1793577600");
        assert!(key.open(8, &mut token.clone()).is_err(), "another nonce");
        assert!(other.open(7, &mut token.clone()).is_err(), "another key");
        let mut changed = token.clone();
        changed[3] ^= 1;
        assert!(key.open(7, &mut changed).is_err(), "a changed byte");
        assert!(key.open(7, &mut token[..TAG - 1].to_vec()).is_err(), "shorter than a tag");
    }

    /// The role's TLS takes QUIC's configuration, with no certificate yet as
    /// an ACME role's before its first.
    #[test]
    fn the_role_s_configuration_is_tls_1_3_with_its_alpn_alone() {
        assert!(server_config(Served::new(None)).is_ok());
    }
}
