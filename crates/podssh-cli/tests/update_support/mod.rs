//! The stand-in release of `tests/update.rs` (T-375): the test's own
//! Fulcio (a root and an intermediate), a leaf of it for the release
//! workflow at a tag, the test's own Rekor, and a TLS server on the loopback
//! that serves a release's files as GitHub serves them: its list in the API,
//! its feed, and each file through a redirect. Each certificate is made by
//! rcgen with no crypto feature and signed with p256, so that the test
//! builds with no C compiler.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use podssh_cli::update::sigstore::{Roots, ISSUER};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const REPO: &str = "Azathothas/podssh";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A certificate's DER as PEM; rcgen's `pem` feature is off.
fn pem(der: &[u8]) -> String {
    let text = b64(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A P-256 key, for rcgen's certificates, rustls's handshake and a bundle.
#[derive(Clone)]
pub struct Key {
    signing: Arc<p256::ecdsa::SigningKey>,
    public: Vec<u8>,
}

impl Key {
    pub fn new() -> Key {
        use p256::elliptic_curve::Generate;
        let signing = p256::ecdsa::SigningKey::generate();
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key { signing: Arc::new(signing), public }
    }

    /// An ECDSA signature with SHA-256, in DER, as X.509 and Sigstore carry
    /// it.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        sign(&self.signing, message)
    }

    /// The key as a SubjectPublicKeyInfo in DER: the fixed head of P-256's,
    /// then the point.
    pub fn spki(&self) -> Vec<u8> {
        let mut der = hex_bytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");
        der.extend_from_slice(&self.public);
        der
    }
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn sign(key: &p256::ecdsa::SigningKey, message: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::Signature = key.sign(message);
    signature.to_der().as_bytes().to_vec()
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
        Ok(sign(&self.signing, message))
    }
}

/// With no crypto feature, rcgen draws no serial number of its own.
fn serial() -> rcgen::SerialNumber {
    rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>())
}

fn ca(name: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "podssh-test");
    params.distinguished_name.push(rcgen::DnType::CommonName, name);
    params.serial_number = Some(serial());
    params
}

/// A DER UTF8String, as Fulcio writes the issuer of a token.
fn utf8_string(text: &str) -> Vec<u8> {
    assert!(text.len() < 128);
    let mut der = vec![0x0c, text.len() as u8];
    der.extend_from_slice(text.as_bytes());
    der
}

/// What a leaf holds, each part plantable.
pub struct Leaf<'a> {
    pub uri: String,
    pub issuer: &'a str,
    pub code_signing: bool,
    /// Its validity, as years; else rcgen's, from 1975 to 4096.
    pub years: Option<(i32, i32)>,
}

impl Leaf<'_> {
    /// The leaf that Fulcio gives the release workflow at `tag`.
    pub fn of_tag(tag: &str) -> Leaf<'static> {
        Leaf {
            uri: format!("https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{tag}"),
            issuer: ISSUER,
            code_signing: true,
            years: None,
        }
    }
}

/// The test's Sigstore: Fulcio's root and intermediate, and Rekor's key.
pub struct Sigstore {
    root: (Key, rcgen::CertificateParams),
    intermediate: (Key, rcgen::CertificateParams),
    rekor: Key,
    pub roots: Roots,
}

impl Sigstore {
    pub fn new() -> Sigstore {
        Sigstore::with_rekor(Key::new())
    }

    /// Another Fulcio, of the same names, beside this Rekor: its leaves are
    /// logged as this one's are, and signed by another key.
    pub fn other_fulcio(&self) -> Sigstore {
        Sigstore::with_rekor(self.rekor.clone())
    }

    fn with_rekor(rekor: Key) -> Sigstore {
        let (root_key, root) = (Key::new(), ca("test-sigstore"));
        let (mid_key, mid) = (Key::new(), ca("test-sigstore-intermediate"));
        let root_cert = root.self_signed(&root_key).unwrap();
        let mid_cert = mid.signed_by(&mid_key, &rcgen::Issuer::new(root.clone(), &root_key)).unwrap();
        let roots = Roots { fulcio: vec![mid_cert.der().to_vec(), root_cert.der().to_vec()], rekor: rekor.spki() };
        Sigstore { root: (root_key, root), intermediate: (mid_key, mid), rekor, roots }
    }

    /// A bundle that signs `artifact` with a new leaf as `leaf` says, logged
    /// by the test's Rekor now, as cosign's `sign-blob --bundle` writes one.
    pub fn bundle(&self, artifact: &[u8], leaf: &Leaf<'_>) -> Vec<u8> {
        let key = Key::new();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.serial_number = Some(serial());
        params.subject_alt_names =
            vec![rcgen::SanType::URI(rcgen::string::Ia5String::try_from(leaf.uri.clone()).unwrap())];
        if leaf.code_signing {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
        }
        params.custom_extensions =
            vec![rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 57264, 1, 8], utf8_string(leaf.issuer))];
        if let Some((from, to)) = leaf.years {
            params.not_before = rcgen::date_time_ymd(from, 1, 1);
            params.not_after = rcgen::date_time_ymd(to, 1, 1);
        }
        let (mid_key, mid) = &self.intermediate;
        let cert = params.signed_by(&key, &rcgen::Issuer::new(mid.clone(), mid_key)).unwrap();
        let signature = key.sign(artifact);
        let digest = Sha256::digest(artifact);
        let body = serde_json::json!({
            "apiVersion": "0.0.1", "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": hex(&digest)}},
                "signature": {"content": b64(&signature), "publicKey": {"content": b64(pem(cert.der()).as_bytes())}},
            },
        });
        let body = b64(body.to_string().as_bytes());
        let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let log_id = Sha256::digest(self.rekor.spki());
        let canonical =
            serde_json::json!({"body": body, "integratedTime": time, "logID": hex(&log_id), "logIndex": 42});
        let promise = self.rekor.sign(canonical.to_string().as_bytes());
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": {"rawBytes": b64(cert.der())},
                "tlogEntries": [{
                    "logIndex": "42", "logId": {"keyId": b64(&log_id)},
                    "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                    "integratedTime": time.to_string(),
                    "inclusionPromise": {"signedEntryTimestamp": b64(&promise)},
                    "canonicalizedBody": body,
                }],
            },
            "messageSignature": {
                "messageDigest": {"algorithm": "SHA2_256", "digest": b64(&digest)},
                "signature": b64(&signature),
            },
        });
        bundle.to_string().into_bytes()
    }
}

/// What the stand-in answers for a path.
#[derive(Clone)]
pub enum Answer {
    Body(Arc<Vec<u8>>),
    Redirect(String),
    Status(u16),
    /// A status with a body that says why, as iroh's relay refuses (T-348).
    Refuse(u16, String),
}

/// A TLS server on the loopback, of the test's own CA, that answers each
/// GET from its routes and keeps each path that it was asked.
pub struct Server {
    pub addr: SocketAddr,
    /// The CA of its certificate, in PEM, for the client's `Trust::File`.
    pub ca_file: PathBuf,
    routes: Arc<Mutex<HashMap<String, Answer>>>,
    pub asked: Arc<Mutex<Vec<String>>>,
}

/// The stand-in's TLS key, for rustls.
#[derive(Debug)]
struct TlsKey(Arc<p256::ecdsa::SigningKey>);

impl rustls::sign::SigningKey for TlsKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        let scheme = rustls::SignatureScheme::ECDSA_NISTP256_SHA256;
        offered.contains(&scheme).then(|| Box::new(TlsKey(self.0.clone())) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

impl rustls::sign::Signer for TlsKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(sign(&self.0, message))
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[derive(Debug)]
struct OneCertificate(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for OneCertificate {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl Server {
    /// The server, its CA's PEM written in `dir`.
    pub async fn start(dir: &Path) -> Server {
        Server::start_for(dir, &["127.0.0.1"]).await
    }

    /// [`Server::start`] with a certificate for `names`, each a name or an
    /// address, as a stand-in for a host of another address (T-366).
    pub async fn start_for(dir: &Path, names: &[&str]) -> Server {
        let (acceptor, ca_file) = acceptor(dir, names);
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let routes: Arc<Mutex<HashMap<String, Answer>>> = Arc::default();
        let asked: Arc<Mutex<Vec<String>>> = Arc::default();
        let (r, a) = (routes.clone(), asked.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, routes, asked) = (acceptor.clone(), r.clone(), a.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = answer(tls, &routes, &asked).await;
                    }
                });
            }
        });
        Server { addr, ca_file, routes, asked }
    }

    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    pub fn route(&self, path: &str, answer: Answer) {
        self.routes.lock().unwrap().insert(path.to_string(), answer);
    }

    pub fn body(&self, path: &str, body: Vec<u8>) {
        self.route(path, Answer::Body(Arc::new(body)));
    }

    pub fn was_asked(&self, path: &str) -> bool {
        self.asked.lock().unwrap().iter().any(|p| p == path)
    }
}

/// A TLS acceptor with a certificate for `names`, each a name or an
/// address, of a CA of the test's own, whose PEM is written in `dir` as
/// `ca.pem`: the acceptor, and that file. A stand-in of another protocol
/// takes it too (the DERP servers of `tests/derp_road.rs`, T-379).
pub fn acceptor(dir: &Path, names: &[&str]) -> (tokio_rustls::TlsAcceptor, PathBuf) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let ca_params = ca("test-github-ca");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    let mut leaf = rcgen::CertificateParams::new(names).unwrap();
    leaf.serial_number = Some(serial());
    let leaf = leaf.signed_by(&leaf_key, &rcgen::Issuer::new(ca_params, &ca_key)).unwrap();
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, pem(ca_cert.der())).unwrap();
    let certified =
        rustls::sign::CertifiedKey::new(vec![leaf.der().clone()], Arc::new(TlsKey(leaf_key.signing.clone())));
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(podssh_ws::crypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OneCertificate(Arc::new(certified))));
    (tokio_rustls::TlsAcceptor::from(Arc::new(tls)), ca_file)
}

/// One request and its answer.
async fn answer<S>(
    mut tls: S,
    routes: &Mutex<HashMap<String, Answer>>,
    asked: &Mutex<Vec<String>>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 << 10 {
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&head);
    let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
    asked.lock().unwrap().push(path.clone());
    let found = routes.lock().unwrap().get(&path).cloned();
    let (status, extra, body): (u16, String, Arc<Vec<u8>>) = match found {
        Some(Answer::Body(body)) => (200, String::new(), body),
        Some(Answer::Redirect(to)) => (302, format!("Location: {to}\r\n"), Arc::default()),
        Some(Answer::Status(code)) => (code, String::new(), Arc::new(b"refused by the stand-in".to_vec())),
        Some(Answer::Refuse(code, why)) => (code, String::new(), Arc::new(why.into_bytes())),
        None => (404, String::new(), Arc::new(b"Not Found".to_vec())),
    };
    let reply = format!("HTTP/1.1 {status} X\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    tls.write_all(reply.as_bytes()).await?;
    tls.write_all(&body).await?;
    tls.shutdown().await
}
