//! The keys and certificates of ACME (T-447): P-256 keys of aws-lc-rs, kept
//! as PKCS #8 in PEM, which podssh-ws's server reads as it reads `--key`;
//! the CSR of a name; the self-signed certificate of TLS-ALPN-01 (RFC 8737,
//! section 3); and what a leaf says, its names and its life. rcgen writes
//! the DER with no crypto of its own: each signature is aws-lc-rs's.

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use base64::Engine as _;
use rustls::sign::CertifiedKey;
use sha2::Digest as _;
use x509_parser::prelude::*;
use zeroize::Zeroizing;

/// How long the certificate of a challenge holds: a CA validates within
/// minutes, and a clock a day off still takes it.
const CHALLENGE_DAYS: i64 = 7;

/// A P-256 key: its PKCS #8, and its pair for the signatures of X.509.
pub struct Key {
    pkcs8: Zeroizing<Vec<u8>>,
    pair: EcdsaKeyPair,
    /// The uncompressed point, as a SubjectPublicKeyInfo holds it.
    public: Vec<u8>,
}

impl Key {
    /// A new key, from the system's source of randomness.
    pub fn generate() -> Result<Key, String> {
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .map_err(|_| "no P-256 key could be made".to_string())?;
        Key::from_pkcs8(document.as_ref())
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<Key, String> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der)
            .map_err(|e| format!("not a P-256 key in PKCS #8: {e}"))?;
        let public = pair.public_key().as_ref().to_vec();
        Ok(Key { pkcs8: Zeroizing::new(der.to_vec()), pair, public })
    }

    /// The key as PEM (`PRIVATE KEY`), as the files of `--key` hold one.
    pub fn pem(&self) -> Zeroizing<String> {
        Zeroizing::new(pem("PRIVATE KEY", &self.pkcs8))
    }
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
    /// ECDSA with SHA-256, in DER, as X.509 and PKCS #10 carry it.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature = self.pair.sign(&SystemRandom::new(), message).map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature.as_ref().to_vec())
    }
}

/// `der` as a PEM block of `label`, its lines of 64 characters.
pub fn pem(label: &str, der: &[u8]) -> String {
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in text.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The DER of the first PEM block of `label` in `text`.
pub fn pem_block(text: &str, label: &str) -> Option<Zeroizing<Vec<u8>>> {
    x509_parser::pem::Pem::iter_from_buffer(text.as_bytes())
        .filter_map(Result::ok)
        .find(|block| block.label == label)
        .map(|block| Zeroizing::new(block.contents))
}

/// The CSR of `name` and `key` (RFC 2986), as an order's finalization sends
/// it: the name in subjectAltName alone, and no subject, as RFC 8555 lets a
/// CA read the names from there.
pub fn csr(name: &str, key: &Key) -> Result<Vec<u8>, String> {
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).map_err(|e| format!("{name}: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let request = params.serialize_request(key).map_err(|e| format!("the CSR of {name}: {e}"))?;
    Ok(request.der().as_ref().to_vec())
}

/// The certificate of TLS-ALPN-01 for `name`, and its key, as PEM: self-signed,
/// its one name in subjectAltName, and the critical acmeIdentifier extension
/// that holds the SHA-256 of `key_authorization` (RFC 8737, section 3). Its
/// key is made for it, and goes with it.
pub fn challenge(name: &str, key_authorization: &str, now_secs: i64) -> Result<(String, Zeroizing<String>), String> {
    let key = Key::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).map_err(|e| format!("{name}: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, name);
    // With no crypto feature, rcgen draws no serial number of its own.
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    // The day of a time, at midnight UTC, as rcgen takes it.
    let day = |secs: i64| {
        let (y, m, d) = podssh_ws::clock::civil_from_days(secs.div_euclid(86_400));
        rcgen::date_time_ymd(y as i32, m as u8, d as u8)
    };
    params.not_before = day(now_secs - 86_400);
    params.not_after = day(now_secs + CHALLENGE_DAYS * 86_400);
    let digest = sha2::Sha256::digest(key_authorization.as_bytes());
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(&digest[..])];
    let cert = params.self_signed(&key).map_err(|e| format!("the challenge's certificate for {name}: {e}"))?;
    Ok((pem("CERTIFICATE", cert.der()), key.pem()))
}

/// What a leaf says: its DNS names, lower-cased, and its life in seconds
/// since the epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub names: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
}

/// The facts of the leaf `der`.
pub fn leaf(der: &[u8]) -> Result<Leaf, String> {
    let (_, cert) = parse_x509_certificate(der).map_err(|e| format!("the leaf cannot be read: {e}"))?;
    let names = match cert.subject_alternative_name() {
        Ok(Some(san)) => san
            .value
            .general_names
            .iter()
            .filter_map(|n| if let GeneralName::DNSName(d) = n { Some(d.to_ascii_lowercase()) } else { None })
            .collect(),
        _ => Vec::new(),
    };
    let validity = cert.validity();
    Ok(Leaf { names, not_before: validity.not_before.timestamp(), not_after: validity.not_after.timestamp() })
}

/// A file of a key and a chain (or a chain alone, with its key in
/// `key_text`), loaded as the server takes it, with the facts of its leaf.
pub fn load(cert_text: &[u8], key_text: &[u8]) -> Result<(Arc<CertifiedKey>, Leaf), String> {
    let pair = podssh_ws::tls_server::certified(cert_text, key_text)?;
    let first = pair.cert.first().ok_or("the chain is empty")?;
    let facts = leaf(first.as_ref())?;
    Ok((pair, facts))
}

#[cfg(test)]
#[path = "certs_tests.rs"]
pub(crate) mod tests;
