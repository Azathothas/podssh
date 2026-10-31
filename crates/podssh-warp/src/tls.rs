//! TLS with WARP's endpoint, in its own rustls configuration outside
//! podssh-ws's rules (T-352's Approach): TLS 1.3, ALPN `h2`, the device's
//! certificate, and the endpoint's key pinned. No public root signs the
//! endpoint (GitHub #63's first comment), so its chain and its name are not
//! verified; its key is, as usque pins it (`api/masque.go`,
//! `PrepareTlsConfig`). A certificate of another key is what a proxy that
//! re-terminates TLS shows, and the verifier keeps its issuer, so that the
//! road names that proxy.

use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::key::DeviceKey;

/// The ALPN that the endpoint takes over TCP.
pub const ALPN: &[u8] = b"h2";

/// The verifier that holds the endpoint to its key.
#[derive(Debug)]
pub struct Pinned {
    point: Vec<u8>,
    algorithms: WebPkiSupportedAlgorithms,
    refused: Mutex<Option<String>>,
}

impl Pinned {
    /// The issuer of the certificate whose key was not the endpoint's, once
    /// a handshake refused one.
    pub fn refused(&self) -> Option<String> {
        self.refused.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let spki = crate::der::spki_of_certificate(end_entity);
        let Some(point) = spki.and_then(crate::der::p256_point) else {
            *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = Some(crate::der::issuer_words(end_entity));
            return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
        };
        // SEC1 has two forms of a point: compared in the uncompressed one.
        let same = p256::PublicKey::from_sec1_bytes(point).ok().map(|key| {
            use p256::elliptic_curve::sec1::ToSec1Point as _;
            key.to_sec1_point(false).as_bytes().to_vec()
        });
        if same.as_deref() == Some(self.point.as_slice()) {
            return Ok(ServerCertVerified::assertion());
        }
        *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = Some(crate::der::issuer_words(end_entity));
        Err(Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The configuration of one connection to the endpoint whose key is the
/// SEC1 point `endpoint_point`, presenting `key`'s certificate made at
/// `now`; and its verifier, which says what it refused.
pub fn config(key: &DeviceKey, endpoint_point: &[u8], now: i64) -> Result<(Arc<ClientConfig>, Arc<Pinned>), String> {
    let provider = Arc::new(podssh_ws::crypto::provider());
    let pinned = Arc::new(Pinned {
        point: endpoint_point.to_vec(),
        algorithms: provider.signature_verification_algorithms,
        refused: Mutex::new(None),
    });
    let certified = Arc::new(key.certified(now));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS 1.3: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(pinned.clone())
        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok((Arc::new(config), pinned))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration offers `h2` alone, TLS 1.3 alone, and a client
    /// certificate.
    #[test]
    fn the_configuration_offers_h2_and_a_certificate() {
        let (key, endpoint) = (DeviceKey::generate().unwrap(), DeviceKey::generate().unwrap());
        let (config, pinned) = config(&key, &endpoint.point(), 1_791_440_989).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(config.client_auth_cert_resolver.has_certs());
        assert_eq!(pinned.refused(), None);
    }

    /// The endpoint's own certificate passes; another key's is refused, and
    /// its issuer kept.
    #[test]
    fn only_the_endpoint_s_key_passes() {
        let (key, endpoint, other) =
            (DeviceKey::generate().unwrap(), DeviceKey::generate().unwrap(), DeviceKey::generate().unwrap());
        let (_, pinned) = config(&key, &endpoint.point(), 0).unwrap();
        let name = ServerName::try_from(crate::SERVER_NAME).unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_791_440_989));
        let own = CertificateDer::from(endpoint.certificate(1_791_440_989));
        assert!(pinned.verify_server_cert(&own, &[], &name, &[], now).is_ok());
        assert_eq!(pinned.refused(), None);
        let theirs = CertificateDer::from(other.certificate(1_791_440_989));
        assert!(pinned.verify_server_cert(&theirs, &[], &name, &[], now).is_err());
        assert_eq!(pinned.refused().as_deref(), Some("an unnamed issuer"));
    }
}
