//! A stand-in for the clouds' own tunnels, for `tests/iap_cli.rs` and
//! `tests/eice_cli.rs` (T-351): an HTTP CONNECT proxy on the loopback that
//! re-terminates TLS, as a proxy that intercepts TLS does, with a
//! certificate of the test's own CA for each name that it is asked for.
//! Behind it a handler of the test plays the cloud for that name. podssh
//! is pointed at it by `https_proxy` and `--ca-file` alone, so its own
//! code reaches it as it would reach Google or AWS through such a proxy.
//! Each certificate is made by rcgen with no crypto feature and signed
//! with p256, as `tests/update_support` makes its own, so that no C is
//! compiled.

#![allow(dead_code)]

use std::future::Future;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use podssh_ws::frame::{self, Frame, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A P-256 key, for rcgen's certificates and rustls's handshake.
#[derive(Clone)]
struct Key {
    signing: Arc<p256::ecdsa::SigningKey>,
    public: Vec<u8>,
}

impl Key {
    fn new() -> Key {
        use p256::elliptic_curve::Generate;
        let signing = p256::ecdsa::SigningKey::generate();
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key { signing: Arc::new(signing), public }
    }
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

fn pem(der: &[u8]) -> String {
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

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

/// The TLS stream of one name, as the handler gets it.
pub type Stream = tokio_rustls::server::TlsStream<TcpStream>;
/// What plays the cloud: the name that the client asked the proxy for, and
/// the stream that it reaches it by.
pub type Handler = Arc<dyn Fn(String, Stream) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// The proxy, the CA of its certificates, and each CONNECT that it took.
pub struct Proxy {
    pub port: u16,
    pub ca_file: PathBuf,
    pub connects: Arc<Mutex<Vec<String>>>,
}

impl Proxy {
    /// The proxy, its CA's PEM written in `dir`.
    pub async fn start(dir: &Path, handler: Handler) -> Proxy {
        let ca_key = Key::new();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name = rcgen::DistinguishedName::new();
        ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-intercepting-proxy");
        ca.serial_number = Some(serial());
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let ca_file = dir.join("cloud-ca.pem");
        std::fs::write(&ca_file, pem(ca_cert.der())).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connects: Arc<Mutex<Vec<String>>> = Arc::default();
        let (issuer, seen) = (Arc::new((ca, ca_key)), connects.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (issuer, handler, seen) = (issuer.clone(), handler.clone(), seen.clone());
                tokio::spawn(async move {
                    let _ = serve(tcp, &issuer, handler, &seen).await;
                });
            }
        });
        Proxy { port, ca_file, connects }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// One CONNECT: its 200, then TLS for the name it asked, then the handler.
async fn serve(
    mut tcp: TcpStream,
    issuer: &(rcgen::CertificateParams, Key),
    handler: Handler,
    seen: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let head = read_head(&mut tcp).await?;
    let target = head.strip_prefix("CONNECT ").and_then(|r| r.split_whitespace().next()).unwrap_or_default();
    seen.lock().unwrap().push(target.to_string());
    let host = target.rsplit_once(':').map_or(target, |(host, _)| host).to_string();
    tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    let leaf_key = Key::new();
    let mut leaf = rcgen::CertificateParams::new(vec![host.clone()]).unwrap();
    leaf.serial_number = Some(serial());
    let leaf = leaf.signed_by(&leaf_key, &rcgen::Issuer::new(issuer.0.clone(), &issuer.1)).unwrap();
    let certified =
        rustls::sign::CertifiedKey::new(vec![leaf.der().clone()], Arc::new(TlsKey(leaf_key.signing.clone())));
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(podssh_ws::crypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OneCertificate(Arc::new(certified))));
    let stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls)).accept(tcp).await?;
    handler(host, stream).await;
    Ok(())
}

/// A request's head, up to its blank line.
pub async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        head.push(byte[0]);
        if head.len() > 64 * 1024 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// A header's value in a request's head.
pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The 101 to an upgrade whose head is `head`, with `protocol` when the
/// cloud names one.
pub async fn accept_upgrade(stream: &mut Stream, head: &str, protocol: Option<&str>) {
    let key = header(head, "Sec-WebSocket-Key").expect("a key");
    let mut answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        podssh_ws::handshake::accept_key(key)
    );
    if let Some(protocol) = protocol {
        answer.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n"));
    }
    answer.push_str("\r\n");
    stream.write_all(answer.as_bytes()).await.unwrap();
}

/// A server's frame.
pub async fn send(stream: &mut Stream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let f = Frame { fin: true, opcode, payload: payload.to_vec() };
    stream.write_all(&frame::encode(&f, Role::Server, [0; 4])).await
}

/// The client's frames, read off a stream.
#[derive(Default)]
pub struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    /// The next frame of the client, or `None` at the end of its stream.
    pub async fn next(&mut self, stream: &mut Stream) -> Option<Frame> {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            if let Some((f, used)) = frame::decode(&self.buf, Role::Client).ok()? {
                self.buf.drain(..used);
                return Some(f);
            }
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// A scratch directory of the test.
pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cloud-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A file of `body` that only this user can read.
pub fn private_file(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

/// `podssh ARGS` with only `set` of the variables that reach a road, its
/// home in `dir`, and its proxy the stand-in at `proxy` when one is given.
pub fn command(dir: &Path, args: &[&str], proxy: Option<&Proxy>, set: &[(&str, &str)]) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("HOME", dir).env("USERPROFILE", dir);
    for name in [
        "PODSSH_OFFLINE",
        "PODSSH_TIMEOUT",
        "PODSSH_IAP_TOKEN_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "PODSSH_EICE_CREDENTIALS_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_PROFILE",
        "PODSSH_EICE_MAX_TUNNEL_DURATION",
        "XDG_CONFIG_HOME",
        "APPDATA",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "SSL_CERT_FILE",
    ] {
        cmd.env_remove(name);
    }
    if let Some(proxy) = proxy {
        cmd.env("https_proxy", proxy.url());
    }
    for (name, value) in set {
        cmd.env(name, value);
    }
    cmd
}
