//! The WebSocket over HTTP/2's extended CONNECT at podssh's relay role
//! (T-321, RFC 8441), on the loopback. The role takes each connection as
//! `podssh relay serve` takes it (`serve::listener::connection`), its TLS a
//! leaf of the test's CA, offering `h2` then `http/1.1` as `--http2 yes`
//! does. podssh's client (`podssh_ws::h2_road`) opens eight sessions at once
//! on one TLS connection, 4 MiB each way to an echo with equal digests;
//! OpenSSH's sshd, where this host has one, says its version line through a
//! session on the road; a wrong token gets the role's refusal on the road;
//! `podssh_relay::open` takes the road to a host that the user named; the
//! documents and the mint answer over HTTP/2, and a request of another path
//! is asked for again over HTTP/1.1. With `h2` not offered, as `--http2 no`,
//! the upgrade goes on the one connection.
//!
//!     cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_h2
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod http_road_harness;
mod role_harness;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use http_road_harness::{bytes, echo_target, sshd, LIMIT, MIB};
use podssh_relay::failover::Mode;
use podssh_relay::open::Request;
use podssh_relay::relay::{Relay, RelayList};
use podssh_relay::serve::listener::{connection, Door};
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Mint};
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::h2_road::{self, Fallback, Road};
use podssh_ws::tls_server::HTTP1;
use podssh_ws::{ConnectError, Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};
use role_harness::Role;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};

const NAME: &str = "relay.h2.test";
const GREETING: &[u8] = b"SSH-2.0-echo-of-the-test\r\n";
const H2: &[u8] = podssh_relay::serve::http2::H2;

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

/// A leaf for [`NAME`] and its key, as PEM, and the CA that signed it.
fn certificates() -> (String, String, String) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-h2-ca");
    ca.serial_number = Some(serial());
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let mut leaf = rcgen::CertificateParams::new(vec![NAME.to_string()]).unwrap();
    leaf.serial_number = Some(serial());
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    (pem("CERTIFICATE", leaf.der()), leaf_key.pkcs8_pem(), pem("CERTIFICATE", ca_cert.der()))
}

/// The role behind TLS on the loopback, as `podssh relay serve` serves it,
/// minting for anyone and dialing the loopback; its TLS connections counted.
struct Tls {
    role: Role,
    port: u16,
    accepted: Arc<AtomicUsize>,
    root: PathBuf,
}

impl Tls {
    async fn start(alpn: &'static [&'static [u8]], tag: &str) -> Tls {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        podssh_ws::resolve::set_pins(vec![(NAME.into(), lo)]);
        let policy = Policy { private: true, ..Policy::default() };
        let role = Role::configured(Mint::Anyone, policy, Default::default()).await;
        let (cert, key, ca) = certificates();
        let dir = std::env::temp_dir().join(format!("podssh-relay-serve-h2-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.join("root.pem");
        std::fs::write(&root, ca).unwrap();
        let acceptor = podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), alpn).expect("an acceptor");
        let door = Door { acceptor, cleartext: false, sshd: None, published: Default::default() };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let (cfg, counted) = (role.cfg.clone(), accepted.clone());
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(connection(tcp, peer.ip(), door.clone(), cfg.clone()));
            }
        });
        Tls { role, port, accepted, root }
    }

    fn trust(&self) -> Trust {
        Trust::File(self.root.clone())
    }

    fn config(&self, target: u16) -> WsClientConfig {
        let path = podssh_relay::relay::forward_path("127.0.0.1", target).unwrap();
        WsClientConfig {
            endpoint: Endpoint { host: NAME.into(), port: self.port, path },
            trust: self.trust(),
            server_name: NAME.into(),
            timeout: LIMIT,
            idle_timeout: Some(LIMIT),
            proxy: ProxyChoice::Direct,
        }
    }

    fn token(&self) -> String {
        self.role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS).0
    }

    /// How many times the role said `line`, whole.
    fn said(&self, line: &str) -> usize {
        self.role.events.lock().unwrap().iter().filter(|l| *l == line).count()
    }
}

impl Drop for Tls {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.root.parent().unwrap());
    }
}

/// The greeting, then `size` bytes out through `session` in messages of 64
/// KiB while the echo is read: each byte back once, in order, by digest.
async fn each_way(session: RelaySession, size: usize, seed: u64) {
    let session = Arc::new(session);
    let out = bytes(size, seed);
    let sent = Sha256::digest(&out);
    let writer = {
        let session = session.clone();
        tokio::spawn(async move {
            for chunk in out.chunks(64 * 1024) {
                session.send_binary(chunk).await.expect("a message out");
            }
        })
    };
    let (mut back, mut got, mut greeting) = (Sha256::new(), 0, Vec::new());
    let read = async {
        while got < size {
            let frame = session.read_frame().await.expect("a message back");
            assert_eq!(frame.opcode, OPCODE_BINARY);
            let mut payload = &frame.payload[..];
            if greeting.len() < GREETING.len() {
                let n = (GREETING.len() - greeting.len()).min(payload.len());
                greeting.extend_from_slice(&payload[..n]);
                payload = &payload[n..];
            }
            got += payload.len();
            back.update(payload);
        }
    };
    tokio::time::timeout(LIMIT, read).await.expect("the echo within the limit");
    writer.await.unwrap();
    assert_eq!(greeting, GREETING, "the target's greeting first");
    assert_eq!(got, size, "each byte came back once");
    assert_eq!(back.finalize(), sent, "the digests are equal");
    let _ = session.send_close(1000, "").await;
}

/// Eight sessions of one process at once are eight streams of one TLS
/// connection to the role, each with its own 4 MiB each way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_sessions_of_one_process_share_one_connection_to_the_role() {
    let tls = Tls::start(&[H2, HTTP1], "eight").await;
    let target = echo_target(GREETING).await;
    let mut tasks = Vec::new();
    for seed in 1..=8u64 {
        let (config, token) = (tls.config(target), tls.token());
        tasks.push(tokio::spawn(async move {
            let (session, road) = h2_road::connect(&config, &token).await.expect("a session on the road");
            each_way(session, 4 * MIB, seed).await;
            road
        }));
    }
    let mut roads = Vec::new();
    for task in tasks {
        roads.push(task.await.unwrap());
    }
    assert!(roads.iter().all(|r| matches!(r, Road::Stream { .. })), "the role offered no extended CONNECT: {roads:?}");
    assert_eq!(tls.accepted.load(Ordering::SeqCst), 1, "one TLS connection for the eight sessions");
    assert_eq!(roads.iter().filter(|r| **r == Road::Stream { shared: false }).count(), 1, "{roads:?}");
    assert_eq!(tls.said("h2"), 1, "{:?}", tls.role.events.lock().unwrap());
    assert_eq!(tls.said("upgrade"), 8, "each session is the role's upgrade of its path");
}

/// OpenSSH's sshd, software that podssh did not write, says its version
/// line first through a session on the road.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openssh_s_sshd_says_its_version_line_through_a_session_on_the_road() {
    let server = match sshd("h2") {
        Ok(server) => server,
        Err(why) => return eprintln!("did not run: {why}"),
    };
    let tls = Tls::start(&[H2, HTTP1], "sshd").await;
    let (session, road) = h2_road::connect(&tls.config(server.port), &tls.token()).await.expect("a session");
    assert_eq!(road, Road::Stream { shared: false });
    let mut line = Vec::new();
    while !line.ends_with(b"\n") {
        let frame = tokio::time::timeout(LIMIT, session.read_frame()).await.expect("in time").expect("a frame");
        line.extend_from_slice(&frame.payload);
    }
    assert!(line.starts_with(b"SSH-2.0-OpenSSH"), "{:?}", String::from_utf8_lossy(&line));
}

/// A wrong token is the role's refusal on the road, with its words, and no
/// upgrade of HTTP/1.1 follows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_token_gets_the_role_s_refusal_on_the_road() {
    let tls = Tls::start(&[H2, HTTP1], "refused").await;
    let target = echo_target(GREETING).await;
    let Err(refused) = h2_road::connect(&tls.config(target), "not-a-token-of-the-role").await else {
        panic!("a refusal")
    };
    let words = "forward: missing or wrong token";
    assert!(matches!(&refused, ConnectError::Refused { status: 403, body } if body == words), "{refused:?}");
    assert_eq!(tls.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(tls.said("upgrade"), 0);
}

/// HTTP/2 to the role, as a client of the test's own: TLS for [`NAME`] that
/// offers `h2` alone.
async fn h2_client(tls: &Tls) -> h2::client::SendRequest<Bytes> {
    let mut config = (*podssh_ws::tls::config_for(&tls.trust()).unwrap()).clone();
    config.alpn_protocols = vec![H2.to_vec()];
    let tcp = TcpStream::connect(("127.0.0.1", tls.port)).await.unwrap();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(NAME.to_string()).unwrap();
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.unwrap();
    let (sender, connection) = h2::client::handshake(stream).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

/// One request on `sender`, with `body`: its status and its body as text.
async fn ask(
    sender: &h2::client::SendRequest<Bytes>,
    request: http::Request<()>,
    body: &[u8],
) -> Result<(u16, String), h2::Error> {
    let mut sender = sender.clone().ready().await?;
    let (response, mut send) = sender.send_request(request, body.is_empty())?;
    if !body.is_empty() {
        send.send_data(Bytes::copy_from_slice(body), true)?;
    }
    let response = tokio::time::timeout(LIMIT, response).await.expect("an answer in time")?;
    let status = response.status().as_u16();
    let mut recv = response.into_body();
    let mut text = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk?;
        let _ = recv.flow_control().release_capacity(chunk.len());
        text.extend_from_slice(&chunk);
    }
    Ok((status, String::from_utf8_lossy(&text).into_owned()))
}

/// Over HTTP/2: `/health` and the mint answer, a CONNECT of another
/// protocol is refused, and a request of another path is asked for again
/// over HTTP/1.1, which the HTTP road and the probes keep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_documents_and_the_mint_answer_over_http2_and_another_request_asks_for_http1() {
    let tls = Tls::start(&[H2, HTTP1], "documents").await;
    let sender = h2_client(&tls).await;
    let at = |path: &str| format!("https://{NAME}:{}{path}", tls.port);
    let get = |path: &str| http::Request::builder().method("GET").uri(at(path)).body(()).unwrap();
    let (status, body) = ask(&sender, get("/health"), b"").await.expect("an answer");
    assert!(status == 200 && body.contains("tcp-ssh-relay"), "{status}: {body}");
    let mint = http::Request::builder().method("POST").uri(at("/v1/mint")).header("content-type", "application/json");
    let (status, body) = ask(&sender, mint.body(()).unwrap(), b"{}").await.expect("an answer");
    let minted: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    assert!(status == 200 && minted["token"].is_string() && minted["scope"] == "forward", "{status}: {body}");
    let mut other = http::Request::builder().method("CONNECT").uri(at("/connect/127.0.0.1/22")).body(()).unwrap();
    other.extensions_mut().insert(h2::ext::Protocol::from_static("connect-udp"));
    let (status, _) = ask(&sender, other, b"").await.expect("an answer");
    assert_eq!(status, 501, "an extended CONNECT of another protocol");
    let Err(reset) = ask(&sender, get("/v1/probe/drip?duration=1&numbytes=1"), b"").await else { panic!("a reset") };
    assert_eq!(reset.reason(), Some(h2::Reason::HTTP_1_1_REQUIRED), "{reset}");
    assert_eq!(tls.accepted.load(Ordering::SeqCst), 1);
}

/// With `h2` not offered, as `--http2 no`, the road's TLS chooses
/// HTTP/1.1, and the upgrade goes on that one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_h2_not_offered_the_upgrade_goes_on_the_one_connection() {
    let tls = Tls::start(&[HTTP1], "http1").await;
    let target = echo_target(GREETING).await;
    let (session, road) = h2_road::connect(&tls.config(target), &tls.token()).await.expect("a session");
    assert_eq!(road, Road::Http1(Fallback::NotChosen));
    assert_eq!(tls.accepted.load(Ordering::SeqCst), 1);
    each_way(session, MIB, 21).await;
    assert_eq!((tls.said("h2"), tls.said("upgrade")), (0, 1));
}

/// The one test of this file that reads the environment: `PODSSH_H2`
/// unset, `podssh_relay::open` takes the road to a host that the user
/// named, and its words say so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_opener_takes_the_road_to_a_host_that_the_user_named() {
    for name in ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"] {
        // Edition 2024 marks a write of the environment unsafe (a read on another
        // thread at the same time is undefined); this write is as it was before.
        unsafe { std::env::remove_var(name) };
    }
    for name in ["PODSSH_RELAY_TOKEN", "PODSSH_OFFLINE", "PODSSH_H2"] {
        // Edition 2024 marks a write of the environment unsafe (a read on another
        // thread at the same time is undefined); this write is as it was before.
        unsafe { std::env::remove_var(name) };
    }
    // Edition 2024 marks a write of the environment unsafe (a read on another
    // thread at the same time is undefined); this write is as it was before.
    unsafe { std::env::set_var("PODSSH_CACHE_DIR", "none") };
    let tls = Tls::start(&[H2, HTTP1], "opener").await;
    let target = echo_target(GREETING).await;
    let relays = RelayList { hosts: vec![Relay { host: NAME.into(), port: tls.port }], explicit: true };
    let path = podssh_relay::relay::forward_path("127.0.0.1", target).unwrap();
    let (shown, trust) = (format!("127.0.0.1:{target}"), tls.trust());
    let request =
        Request { relays: &relays, path: &path, trust: &trust, target: &shown, rounds: 1, failover: Mode::Staggered };
    let mut notes: Vec<String> = Vec::new();
    let opened = podssh_relay::open(&request, &mut |note: &str| notes.push(note.to_string())).await;
    let opened = opened.unwrap_or_else(|failure| panic!("{:?}; notes {notes:?}", failure.lines(&shown)));
    assert!(opened.road().starts_with(", over HTTP/2 (RFC 8441)"), "{:?}", opened.road());
    assert_eq!(tls.said("h2"), 1);
    each_way(opened.session, MIB, 22).await;
}
