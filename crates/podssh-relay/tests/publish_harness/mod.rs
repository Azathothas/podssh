//! What the tests of a published name (T-649) share: a CA of the test's and
//! its leaves, for the role's own name and for the published one, each with a
//! leaf of TLS-ALPN-01 beside it; the node's HTTPS server, which ends TLS
//! itself; a TLS client by a name or an address; and the capture of a
//! ClientHello as rustls writes it.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use podssh_ws::tls_server::{acceptor_for, certified, Served, ACME_TLS_1, HTTP1};
use podssh_ws::Trust;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

/// The role's own name, and the name that it publishes.
pub const ROLE: &str = "relay.publish.test";
pub const SITE: &str = "site.publish.test";
/// The bound of each handshake of a client of the test's.
const HANDSHAKE: Duration = Duration::from_secs(20);

/// A P-256 key of p256, for rcgen's certificates, and its PKCS #8 in PEM.
struct Key {
    signing: p256::ecdsa::SigningKey,
    public: Vec<u8>,
}

impl Key {
    fn new() -> Key {
        use p256::elliptic_curve::Generate;
        let signing = p256::ecdsa::SigningKey::generate();
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key { signing, public }
    }

    fn pkcs8_pem(&self) -> String {
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

fn pem(label: &str, der: &[u8]) -> String {
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

fn serial() -> rcgen::SerialNumber {
    // With no crypto feature, rcgen draws no serial number of its own.
    rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>())
}

/// A leaf of the test's CA: its chain and key as PEM, and its DER, by which
/// a client tells whose it got.
pub struct Leaf {
    pub cert: String,
    pub key: String,
    pub der: Vec<u8>,
}

/// The test's CA in a file, and its leaves: the role's for [`ROLE`] and the
/// loopback's address, the node's for [`SITE`], and for each name a second
/// leaf, the one that a validation of TLS-ALPN-01 gets.
pub struct Certs {
    pub dir: PathBuf,
    pub root: PathBuf,
    pub role: Leaf,
    pub role_challenge: Leaf,
    pub site: Leaf,
    pub site_challenge: Leaf,
}

impl Certs {
    pub fn new(tag: &str) -> Certs {
        let ca_key = Key::new();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-publish-ca");
        ca.serial_number = Some(serial());
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let leaf = |names: &[&str]| {
            let key = Key::new();
            let mut params =
                rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
            params.serial_number = Some(serial());
            let cert = params.signed_by(&key, &issuer).unwrap();
            Leaf { cert: pem("CERTIFICATE", cert.der()), key: key.pkcs8_pem(), der: cert.der().to_vec() }
        };
        // An address beside the role's name: a client that dials one sends
        // no name, and still checks the leaf that it gets.
        let (role, role_challenge) = (leaf(&[ROLE, "127.0.0.1"]), leaf(&[ROLE]));
        let (site, site_challenge) = (leaf(&[SITE]), leaf(&[SITE]));
        let dir = std::env::temp_dir().join(format!("podssh-relay-serve-publish-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.join("root.pem");
        std::fs::write(&root, pem("CERTIFICATE", ca_cert.der())).unwrap();
        Certs { dir, root, role, role_challenge, site, site_challenge }
    }

    pub fn trust(&self) -> Trust {
        Trust::File(self.root.clone())
    }

    /// What a TLS server presents: `leaf` to each client, and `challenge`
    /// to a validation of `name` that offers `acme-tls/1` alone.
    pub fn served(leaf: &Leaf, name: &str, challenge: &Leaf) -> Arc<Served> {
        let served = Served::new(Some(certified(leaf.cert.as_bytes(), leaf.key.as_bytes()).unwrap()));
        served.set_challenge(name, certified(challenge.cert.as_bytes(), challenge.key.as_bytes()).unwrap());
        served
    }
}

impl Drop for Certs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The node's HTTPS server on a free port of the loopback, which ends TLS
/// with the site's leaf, or its leaf of TLS-ALPN-01 for a validation, and
/// then echoes each byte until its client's end.
pub async fn site(certs: &Certs) -> u16 {
    let served = Certs::served(&certs.site, SITE, &certs.site_challenge);
    let acceptor = acceptor_for(served, &[HTTP1, ACME_TLS_1]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                // A validation wants the handshake alone (RFC 8737).
                if tls.get_ref().1.alpn_protocol() != Some(ACME_TLS_1) {
                    let mut buf = vec![0u8; 16 * 1024];
                    while let Ok(n) = tls.read(&mut buf).await {
                        if n == 0 || tls.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// What a TLS client got: the leaf that the server presented and the
/// protocol that it chose, and the stream.
pub struct Visit {
    pub leaf: Vec<u8>,
    pub alpn: Option<Vec<u8>>,
    pub tls: TlsStream<TcpStream>,
}

/// TLS to `port` of the loopback as a client of `name`, an address when it
/// parses as one (and then with no name in its hello), offering `alpn` and
/// checking the leaf against the test's CA.
pub async fn visit(certs: &Certs, port: u16, name: &str, alpn: &[&[u8]]) -> Result<Visit, String> {
    let mut config = (*podssh_ws::tls::config_for(&certs.trust()).unwrap()).clone();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let server = match name.parse::<IpAddr>() {
        Ok(ip) => ServerName::from(ip),
        Err(_) => ServerName::try_from(name.to_string()).unwrap(),
    };
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls = match tokio::time::timeout(HANDSHAKE, connector.connect(server, tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("no handshake in time".into()),
    };
    let (_, conn) = tls.get_ref();
    let leaf = conn.peer_certificates().and_then(|chain| chain.first()).map(|c| c.as_ref().to_vec());
    let leaf = leaf.unwrap_or_default();
    let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
    Ok(Visit { leaf, alpn, tls })
}

/// The ClientHello that rustls writes for `name`, offering `alpn`: its first
/// record, read whole by a listener of the test's, which never answers.
pub async fn captured_hello(certs: &Certs, name: &str, alpn: &[&[u8]]) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut config = (*podssh_ws::tls::config_for(&certs.trust()).unwrap()).clone();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let server = ServerName::try_from(name.to_string()).unwrap();
    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let _ = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(server, tcp).await;
    });
    let (mut tcp, _) = listener.accept().await.unwrap();
    let mut head = [0u8; 5];
    tcp.read_exact(&mut head).await.unwrap();
    let mut record = head.to_vec();
    record.resize(5 + usize::from(u16::from_be_bytes([head[3], head[4]])), 0);
    tcp.read_exact(&mut record[5..]).await.unwrap();
    client.abort();
    record
}
