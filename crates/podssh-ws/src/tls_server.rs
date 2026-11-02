//! TLS for a server of podssh's (T-169, `podssh relay serve`): a certificate
//! chain and a P-256 key from PEM files, served with podssh's own provider,
//! so that the server needs no C either. podssh's provider verifies and holds
//! no key (`crypto::sign`), so the key is signed here with `p256`, as the
//! tests' servers sign theirs. Only P-256: the key that `openssl req -newkey
//! ec` and an ACME client make by default; another key is refused by name.

use std::sync::Arc;

use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature, SigningKey};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{SignatureAlgorithm, SignatureScheme};
use rustls_pki_types::CertificateDer;
pub use tokio_rustls::TlsAcceptor;

/// The ALPN of a relay's upgrade: HTTP/1.1, which the WebSocket of RFC 6455
/// needs (the relay's contract offers no h2 for it).
pub const HTTP1: &[u8] = b"http/1.1";

/// A TLS acceptor that presents `cert_pem`'s chain with `key_pem`'s key,
/// over TLS 1.3 and 1.2, offering `alpn`.
pub fn acceptor(cert_pem: &[u8], key_pem: &[u8], alpn: &[&[u8]]) -> Result<TlsAcceptor, String> {
    let chain = crate::bundle::pem_certificates(cert_pem).map_err(|e| format!("the certificate: {e}"))?;
    if chain.is_empty() {
        return Err("the certificate file holds no CERTIFICATE block".into());
    }
    let key = signing_key(key_pem)?;
    let certified = CertifiedKey::new(chain, Arc::new(P256Key(key)));
    let provider = crate::crypto::provider();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("the TLS versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(One(Arc::new(certified))));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The P-256 key of a PEM file: `EC PRIVATE KEY` (SEC1) or `PRIVATE KEY`
/// (PKCS #8, as OpenSSL 3 writes one).
pub fn signing_key(pem: &[u8]) -> Result<SigningKey, String> {
    let text = std::str::from_utf8(pem).map_err(|_| "the key file is not text")?.replace("\r\n", "\n");
    if text.contains("ENCRYPTED PRIVATE KEY") {
        return Err("the key is encrypted; give a key with no passphrase, in a file only its owner can read".into());
    }
    let (der, pkcs8) = if let Some(b) = block(&text, "EC PRIVATE KEY") {
        (b, false)
    } else if let Some(b) = block(&text, "PRIVATE KEY") {
        (b, true)
    } else {
        return Err("the key file holds no EC PRIVATE KEY or PRIVATE KEY block".into());
    };
    let der = base64::engine::general_purpose::STANDARD.decode(der).map_err(|_| "the key is not valid base64")?;
    let sec1 = if pkcs8 { pkcs8_inner(&der)? } else { der };
    let scalar = sec1_scalar(&sec1)?;
    SigningKey::from_slice(&scalar).map_err(|_| "the key is not a valid P-256 key".to_string())
}

/// The base64 body of the first block of `label`, whitespace removed.
fn block(text: &str, label: &str) -> Option<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = start + text[start..].find(&end)?;
    Some(text[start..stop].chars().filter(|c| !c.is_ascii_whitespace()).collect())
}

/// One DER element at the start of `der`: its tag, its contents, and what
/// follows it.
fn element(der: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let bad = || "the key's DER is cut short".to_string();
    let (&tag, rest) = der.split_first().ok_or_else(bad)?;
    let (&first, rest) = rest.split_first().ok_or_else(bad)?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 3 || rest.len() < n {
            return Err(bad());
        }
        (rest[..n].iter().fold(0usize, |acc, b| acc << 8 | *b as usize), &rest[n..])
    };
    if rest.len() < len {
        return Err(bad());
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

/// The OID of id-ecPublicKey and of prime256v1, as DER contents.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// The SEC1 key inside a PKCS #8 `PrivateKeyInfo` of a P-256 key.
fn pkcs8_inner(der: &[u8]) -> Result<Vec<u8>, String> {
    let (_, info, _) = element(der)?;
    let (_, _version, rest) = element(info)?;
    let (_, algorithm, rest) = element(rest)?;
    let (_, oid, params) = element(algorithm)?;
    if oid != EC_PUBLIC_KEY {
        return Err("the key is not an elliptic-curve key; podssh serves a P-256 key".into());
    }
    let (_, curve, _) = element(params)?;
    if curve != PRIME256V1 {
        return Err("the key's curve is not P-256 (prime256v1), the one that podssh serves".into());
    }
    let (tag, key, _) = element(rest)?;
    if tag != 0x04 {
        return Err("the PKCS #8 key holds no OCTET STRING".into());
    }
    Ok(key.to_vec())
}

/// The 32-byte private scalar of a SEC1 `ECPrivateKey`.
fn sec1_scalar(der: &[u8]) -> Result<[u8; 32], String> {
    let (_, key, _) = element(der)?;
    let (_, version, rest) = element(key)?;
    if version != [1] {
        return Err("the EC key's version is not 1".into());
    }
    let (tag, scalar, rest) = element(rest)?;
    if tag != 0x04 {
        return Err("the EC key holds no OCTET STRING".into());
    }
    // The optional parameters, when there, must name P-256.
    if let Ok((0xa0, params, _)) = element(rest) {
        let (_, curve, _) = element(params)?;
        if curve != PRIME256V1 {
            return Err("the key's curve is not P-256 (prime256v1), the one that podssh serves".into());
        }
    }
    <[u8; 32]>::try_from(scalar).map_err(|_| "the EC key is not 32 bytes: not a P-256 key".to_string())
}

/// One certificate for each client, whatever name it asked for: a relay of
/// the user's serves one name.
#[derive(Debug)]
struct One(Arc<CertifiedKey>);

impl ResolvesServerCert for One {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[derive(Debug)]
struct P256Key(SigningKey);

impl rustls::sign::SigningKey for P256Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        // SHA-256 is P-256's hash in TLS 1.3, and the one podssh signs with.
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(P256Signer(self.0.clone())) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct P256Signer(SigningKey);

impl rustls::sign::Signer for P256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let signature: DerSignature = self.0.sign(message);
        Ok(signature.as_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// The certificates of a PEM file, for a caller that checks one.
pub fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    crate::bundle::pem_certificates(pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PEM block of `label` holding `der`.
    fn pem(label: &str, der: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n")
    }

    /// A SEC1 `ECPrivateKey` of a fixed scalar, with its curve named.
    fn sec1(scalar: &[u8; 32]) -> Vec<u8> {
        let mut body = vec![0x02, 0x01, 0x01, 0x04, 0x20];
        body.extend_from_slice(scalar);
        body.extend_from_slice(&[0xa0, (PRIME256V1.len() + 2) as u8, 0x06, PRIME256V1.len() as u8]);
        body.extend_from_slice(PRIME256V1);
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        der
    }

    #[test]
    fn a_sec1_key_and_its_pkcs8_form_give_one_scalar() {
        let scalar = [7u8; 32];
        let inner = sec1(&scalar);
        let from_sec1 = signing_key(pem("EC PRIVATE KEY", &inner).as_bytes()).expect("the SEC1 form");
        assert_eq!(from_sec1.to_bytes().as_slice(), &scalar[..]);
        // PKCS #8 wraps the same SEC1 bytes: version 0, the algorithm of
        // P-256, and the key in an OCTET STRING.
        let mut algorithm = vec![0x06, EC_PUBLIC_KEY.len() as u8];
        algorithm.extend_from_slice(EC_PUBLIC_KEY);
        algorithm.extend_from_slice(&[0x06, PRIME256V1.len() as u8]);
        algorithm.extend_from_slice(PRIME256V1);
        let mut body = vec![0x02, 0x01, 0x00, 0x30, algorithm.len() as u8];
        body.extend_from_slice(&algorithm);
        body.extend_from_slice(&[0x04, inner.len() as u8]);
        body.extend_from_slice(&inner);
        let mut der = vec![0x30, 0x81, body.len() as u8];
        der.extend_from_slice(&body);
        let from_pkcs8 = signing_key(pem("PRIVATE KEY", &der).as_bytes()).expect("the PKCS #8 form");
        assert_eq!(from_sec1.to_bytes(), from_pkcs8.to_bytes());
    }

    #[test]
    fn a_key_that_is_not_p256_or_is_encrypted_is_refused_by_name() {
        let encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(signing_key(encrypted.as_bytes()).unwrap_err().contains("encrypted"));
        let none = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(signing_key(none.as_bytes()).unwrap_err().contains("no EC PRIVATE KEY"));
    }
}
