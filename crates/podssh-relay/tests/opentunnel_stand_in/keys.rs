//! The keys and certificates of the stand-in OpenTunnel server (T-530): P-256
//! keys of p256, PKCS #8 written by hand as the binary's ACME client writes
//! it, the stand-in's own CA (as OpenTunnel's server with `ISSUER=local`),
//! and the credentials of a test's node, a key and the CSR of its name, made
//! by rcgen with no crypto feature, as the binary makes them with aws-lc-rs.

use std::sync::Arc;

use base64::Engine as _;
use podssh_relay::opentunnel::Credentials;
use zeroize::Zeroizing;

/// A P-256 key, for rcgen's certificates and CSRs.
#[derive(Clone)]
pub struct Key {
    signing: Arc<p256::ecdsa::SigningKey>,
    public: Vec<u8>,
}

impl Key {
    pub fn new() -> Key {
        use p256::elliptic_curve::Generate;
        Key::of(p256::ecdsa::SigningKey::generate())
    }

    pub fn of(signing: p256::ecdsa::SigningKey) -> Key {
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key { signing: Arc::new(signing), public }
    }

    /// The key as PKCS #8 in PEM: the fixed head of a P-256 key's
    /// `PrivateKeyInfo`, then its scalar in an `ECPrivateKey`.
    pub fn pkcs8_pem(&self) -> String {
        // SEQUENCE { 0, { id-ecPublicKey, prime256v1 }, OCTET STRING {
        // SEQUENCE { 1, OCTET STRING (32 bytes) } } }
        #[rustfmt::skip]
        const HEAD: [u8; 35] = [
            0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
            0x01, 0x04, 0x20,
        ];
        let mut der = HEAD.to_vec();
        der.extend_from_slice(&self.signing.to_bytes());
        pem("PRIVATE KEY", &der)
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
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = self.signing.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// The public point of a CSR, for the leaf that the stand-in issues.
pub struct Point(pub Vec<u8>);

impl rcgen::PublicKeyData for Point {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

/// `der` as a PEM block of `label`, its lines of 64 characters.
pub fn pem(label: &str, der: &[u8]) -> String {
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// The DER of the first PEM block of `label` in `text`.
pub fn der(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = start + text[start..].find(&end)?;
    let body: String = text[start..stop].chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

fn serial() -> rcgen::SerialNumber {
    // With no crypto feature, rcgen draws no serial number of its own.
    rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>())
}

/// The stand-in's CA: its certificate, and an issuer of leaves.
pub struct Ca {
    pub pem: String,
    issuer: rcgen::Issuer<'static, Key>,
}

impl Ca {
    pub fn new() -> Ca {
        let key = Key::new();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-opentunnel-ca");
        params.serial_number = Some(serial());
        let cert = params.self_signed(&key).unwrap();
        Ca { pem: pem("CERTIFICATE", cert.der()), issuer: rcgen::Issuer::new(params, key) }
    }

    /// A leaf for `names`, its common name the first, for the key of `point`.
    pub fn leaf(&self, names: &[String], point: &[u8]) -> String {
        let mut params = rcgen::CertificateParams::new(names.to_vec()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, names[0].as_str());
        params.serial_number = Some(serial());
        let cert = params.signed_by(&Point(point.to_vec()), &self.issuer).unwrap();
        pem("CERTIFICATE", cert.der())
    }

    /// A leaf and its key for `name`, as PEM: the TLS of the API's host in
    /// the tests of the command line.
    pub fn pair(&self, name: &str) -> (String, String) {
        let key = Key::new();
        (self.leaf(&[name.to_string()], &key.public), key.pkcs8_pem())
    }
}

/// The credentials of a test's node: a new P-256 key, and the CSR of a
/// tunnel's name, as the binary makes them.
pub struct TestCredentials;

impl Credentials for TestCredentials {
    fn key(&self) -> Result<Zeroizing<String>, String> {
        Ok(Zeroizing::new(Key::new().pkcs8_pem()))
    }

    fn csr(&self, key_pem: &str, hostname: &str) -> Result<String, String> {
        let key = Key::of(podssh_ws::tls_server::signing_key(key_pem.as_bytes())?);
        let names = vec![hostname.to_string(), format!("*.{hostname}")];
        let mut params = rcgen::CertificateParams::new(names).map_err(|e| e.to_string())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, hostname);
        let request = params.serialize_request(&key).map_err(|e| e.to_string())?;
        Ok(pem("CERTIFICATE REQUEST", request.der()))
    }
}

/// Credentials whose CSR names the tunnel alone, with no wildcard: the
/// service refuses such a CSR, as OpenTunnel's server does.
pub struct NoWildcard;

impl Credentials for NoWildcard {
    fn key(&self) -> Result<Zeroizing<String>, String> {
        TestCredentials.key()
    }

    fn csr(&self, key_pem: &str, hostname: &str) -> Result<String, String> {
        let key = Key::of(podssh_ws::tls_server::signing_key(key_pem.as_bytes())?);
        let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()]).map_err(|e| e.to_string())?;
        params.distinguished_name.push(rcgen::DnType::CommonName, hostname);
        let request = params.serialize_request(&key).map_err(|e| e.to_string())?;
        Ok(pem("CERTIFICATE REQUEST", request.der()))
    }
}
