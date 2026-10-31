//! The device's key: P-256, as the API enrols it (`key_type` `secp256r1`),
//! and the self-signed certificate over it that the client presents in
//! TLS, made for each connection, as usque makes one for a day.

use std::fmt;
use std::sync::Arc;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use rustls::crypto::SecureRandom as _;
use rustls::{SignatureAlgorithm, SignatureScheme};
use zeroize::Zeroizing;

/// How long the device's certificate is valid: a day, as usque's.
pub const VALIDITY: i64 = 24 * 3600;

/// The device's key. Its scalar is wiped when the last copy is dropped
/// (ecdsa's `SigningKey`), and no `Debug` shows it.
#[derive(Clone)]
pub struct DeviceKey {
    signing: Arc<SigningKey>,
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceKey(P-256)")
    }
}

impl DeviceKey {
    /// A new key from this host's random source. A draw that is zero or not
    /// below the group's order is drawn again, eight times at most, as
    /// podssh-ws draws its P-256 secrets.
    pub fn generate() -> Result<DeviceKey, String> {
        for _ in 0..8 {
            let mut bytes = Zeroizing::new([0u8; 32]);
            podssh_ws::crypto::random::OsRandom
                .fill(&mut bytes[..])
                .map_err(|_| "this host's random source gave no bytes".to_string())?;
            if let Ok(key) = DeviceKey::from_scalar(&bytes[..]) {
                return Ok(key);
            }
        }
        Err("this host's random source gave no usable P-256 key".into())
    }

    /// The key of the 32 bytes of its scalar.
    pub fn from_scalar(bytes: &[u8]) -> Result<DeviceKey, String> {
        if bytes.len() != 32 {
            return Err(format!("a P-256 key is 32 bytes, not {}", bytes.len()));
        }
        let signing = SigningKey::from_slice(bytes).map_err(|_| "not a P-256 key".to_string())?;
        Ok(DeviceKey { signing: Arc::new(signing) })
    }

    /// The 32 bytes of its scalar, for the device's private file.
    pub fn scalar(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing.to_bytes().to_vec())
    }

    /// Its public point, uncompressed (SEC1).
    pub fn point(&self) -> Vec<u8> {
        self.signing.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    /// Its SubjectPublicKeyInfo, as the API enrols it.
    pub fn spki(&self) -> Vec<u8> {
        crate::der::spki_p256(&self.point())
    }

    /// An ECDSA signature with SHA-256 of `message`, in DER, as X.509 and
    /// TLS carry it. RFC 6979's nonce: no random source at each signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing.sign(message);
        signature.to_der().as_bytes().to_vec()
    }

    /// The certificate that the client presents, valid from `now` (seconds
    /// since the epoch) for [`VALIDITY`].
    pub fn certificate(&self, now: i64) -> Vec<u8> {
        crate::der::self_signed(&self.spki(), now, now + VALIDITY, |tbs| self.sign(tbs))
    }

    /// The certificate and the key, as rustls presents them.
    pub fn certified(&self, now: i64) -> rustls::sign::CertifiedKey {
        let cert = rustls_pki_types::CertificateDer::from(self.certificate(now));
        rustls::sign::CertifiedKey::new(vec![cert], self.signer())
    }

    /// The key as rustls signs with it, for a certificate made elsewhere.
    pub fn signer(&self) -> Arc<dyn rustls::sign::SigningKey> {
        Arc::new(TlsKey(self.clone()))
    }
}

/// The key as rustls signs with it: ECDSA P-256 with SHA-256 alone, the one
/// scheme of a P-256 key in TLS 1.3.
#[derive(Debug)]
struct TlsKey(DeviceKey);

impl rustls::sign::SigningKey for TlsKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        let scheme = SignatureScheme::ECDSA_NISTP256_SHA256;
        offered.contains(&scheme).then(|| Box::new(TlsSigner(self.0.clone())) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct TlsSigner(DeviceKey);

impl rustls::sign::Signer for TlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(message))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;

    /// A key reads back from its scalar, with the same point.
    #[test]
    fn a_key_reads_back_from_its_scalar() {
        let key = DeviceKey::generate().unwrap();
        let again = DeviceKey::from_scalar(&key.scalar()).unwrap();
        assert_eq!(key.point(), again.point());
        assert_eq!(key.point().len(), 65);
        assert_eq!(key.point()[0], 0x04);
        assert!(DeviceKey::from_scalar(&[0u8; 32]).is_err(), "zero is no key");
        assert!(DeviceKey::from_scalar(&[1u8; 31]).is_err(), "31 bytes");
        assert_eq!(format!("{key:?}"), "DeviceKey(P-256)");
    }

    /// The certificate as a reader that podssh did not write reads it:
    /// version 3, serial 0, empty names, a day, no extension, the key's
    /// SPKI, ECDSA with SHA-256, and a signature of the key over the TBS.
    #[test]
    fn the_certificate_reads_as_go_writes_usque_s() {
        let key = DeviceKey::generate().unwrap();
        let now = 1_791_440_989;
        let der = key.certificate(now);
        let (rest, cert) = x509_parser::parse_x509_certificate(&der).expect("x509-parser reads it");
        assert!(rest.is_empty());
        assert_eq!(cert.version(), x509_parser::x509::X509Version::V3);
        assert_eq!(cert.raw_serial(), [0]);
        assert_eq!(cert.issuer().iter().count(), 0, "an empty issuer");
        assert_eq!(cert.subject().iter().count(), 0, "an empty subject");
        assert_eq!(cert.validity().not_before.timestamp(), now);
        assert_eq!(cert.validity().not_after.timestamp(), now + VALIDITY);
        assert!(cert.extensions().is_empty());
        assert_eq!(cert.signature_algorithm.algorithm.to_id_string(), "1.2.840.10045.4.3.2");
        assert_eq!(cert.public_key().raw, key.spki().as_slice());
        let signature = Signature::from_der(cert.signature_value.data.as_ref()).unwrap();
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.point()).unwrap();
        verifying.verify(cert.tbs_certificate.as_ref(), &signature).expect("signed by the key");
        // podssh's own reader finds the same key, as the stand-in's check does.
        assert_eq!(crate::der::spki_of_certificate(&der), Some(key.spki().as_slice()));
        assert_eq!(crate::der::p256_point(&key.spki()), Some(key.point().as_slice()));
    }

    /// rustls's signer gives what the key gives, and only for its scheme.
    #[test]
    fn the_signer_of_tls_is_the_key_s() {
        use rustls::sign::SigningKey as _;
        let key = DeviceKey::generate().unwrap();
        let tls = TlsKey(key.clone());
        assert!(tls.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256]).is_none());
        let signer = tls.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256]).unwrap();
        let signature = Signature::from_der(&signer.sign(b"message").unwrap()).unwrap();
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.point()).unwrap();
        verifying.verify(b"message", &signature).unwrap();
    }
}
