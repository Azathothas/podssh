//! QUIC to podssh's relay role (T-667), on the loopback. The role's QUIC
//! endpoint (`serve::quic`) takes the UDP port of its TLS listener, as
//! `podssh relay serve --quic yes` binds it, its certificate a leaf of the
//! test's CA for both; podssh's client is the library's. A session over QUIC
//! alone carries 4 MiB each way to an echo with equal digests, the TCP
//! listener never asked; a wrong token gets the role's refusal over QUIC,
//! which ends a race; and `podssh_relay::open` races QUIC first where the
//! host offered it, and takes TCP where UDP is refused, where UDP drops each
//! packet, and where the host offered nothing.
//!
//!     cargo test -p podssh-relay --features serve,quic,plain-ws --test relay_serve_quic
#![cfg(all(feature = "serve", feature = "quic", feature = "plain-ws"))]

mod http_road_harness;
mod role_harness;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use http_road_harness::{bytes, echo_target, LIMIT, MIB};
use podssh_relay::failover::Mode;
use podssh_relay::forward_layer::{kept, Offer};
use podssh_relay::open::Request;
use podssh_relay::quic_road::dial::{self, Learned};
use podssh_relay::quic_road::{decisive, WORDS};
use podssh_relay::relay::{Relay, RelayList};
use podssh_relay::serve::listener::{connection, Door};
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Mint};
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::tls_server::{Served, HTTP1};
use podssh_ws::{ConnectError, Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};
use role_harness::Role;
use sha2::{Digest, Sha256};

const NAME: &str = "relay.quic.test";
const GREETING: &[u8] = b"SSH-2.0-echo-of-the-test\r\n";

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
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-quic-ca");
    ca.serial_number = Some(serial());
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let mut leaf = rcgen::CertificateParams::new(vec![NAME.to_string()]).unwrap();
    leaf.serial_number = Some(serial());
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    (pem("CERTIFICATE", leaf.der()), leaf_key.pkcs8_pem(), pem("CERTIFICATE", ca_cert.der()))
}

/// What the role's port of UDP does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Udp {
    /// The role's QUIC.
    Quic,
    /// A socket that takes each packet and answers none, as a network that
    /// drops UDP further on.
    Dropped,
    /// Nothing: the system refuses each packet.
    Refused,
}

/// A TCP listener on the loopback whose port of UDP is free too, as the
/// role's two sockets share one port.
fn ports() -> (std::net::TcpListener, std::net::UdpSocket) {
    for _ in 0..20 {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        if let Ok(udp) = std::net::UdpSocket::bind(tcp.local_addr().unwrap()) {
            return (tcp, udp);
        }
    }
    panic!("no port of the loopback was free for both TCP and UDP");
}

/// The role behind TLS on the loopback, and its port of UDP as `udp` says.
struct Both {
    role: Role,
    port: u16,
    /// The TLS connections that the listener took.
    accepted: Arc<AtomicUsize>,
    root: PathBuf,
    /// The socket that drops each packet, held for the test's time.
    _dropping: Option<std::net::UdpSocket>,
}

impl Both {
    /// `tcp_wait` holds each TLS connection before its handshake, so that a
    /// race's TCP road cannot win where QUIC answers.
    async fn start(udp: Udp, tcp_wait: Duration, tag: &str) -> Both {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        podssh_ws::resolve::set_pins(vec![(NAME.into(), lo)]);
        let policy = Policy { private: true, ..Policy::default() };
        let role = Role::configured(Mint::Anyone, policy, Default::default()).await;
        let (cert, key, ca) = certificates();
        let dir = std::env::temp_dir().join(format!("podssh-relay-serve-quic-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.join("root.pem");
        std::fs::write(&root, ca).unwrap();
        let pair = podssh_ws::tls_server::certified(cert.as_bytes(), key.as_bytes()).expect("the leaf and its key");
        let served = Served::new(Some(pair));
        let acceptor = podssh_ws::tls_server::acceptor_for(served.clone(), &[HTTP1]).expect("an acceptor");
        let door = Door { acceptor, cleartext: false, sshd: None, published: Default::default() };
        let (tcp, socket) = ports();
        let port = tcp.local_addr().unwrap().port();
        tcp.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(tcp).unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let (cfg, counted) = (role.cfg.clone(), accepted.clone());
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let (door, cfg) = (door.clone(), cfg.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(tcp_wait).await;
                    connection(tcp, peer.ip(), door, cfg).await;
                });
            }
        });
        let dropping = match udp {
            Udp::Quic => {
                let endpoint = podssh_relay::serve::quic::endpoint(socket, served).expect("the role's QUIC");
                tokio::spawn(podssh_relay::serve::quic::serve(endpoint, role.cfg.clone()));
                None
            }
            Udp::Dropped => Some(socket),
            Udp::Refused => None,
        };
        Both { role, port, accepted, root, _dropping: dropping }
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

    fn relay(&self) -> Relay {
        Relay { host: NAME.into(), port: self.port }
    }
}

impl Drop for Both {
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

/// A session over QUIC alone: the role's upgrade on one stream, the TCP
/// listener never asked, and 4 MiB each way with equal digests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_over_quic_carries_each_byte_once() {
    let both = Both::start(Udp::Quic, Duration::ZERO, "session").await;
    let target = echo_target(GREETING).await;
    let session = dial::session(&both.config(target), &both.token(), both.port).await.expect("a session over QUIC");
    assert_eq!(session.road(), Some(WORDS));
    each_way(session, 4 * MIB, 1).await;
    assert_eq!(both.accepted.load(Ordering::SeqCst), 0, "no TCP connection");
    assert_eq!((both.said("quic"), both.said("upgrade")), (1, 1), "{:?}", both.role.events.lock().unwrap());
    let answered = dial::learned(NAME, both.port);
    assert!(matches!(answered, Some(Learned::Answered(at)) if at.port() == both.port), "{answered:?}");
}

/// A wrong token is the role's refusal over QUIC, with its words, which
/// ends a race as on TCP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_token_gets_the_role_s_refusal_over_quic() {
    let both = Both::start(Udp::Quic, Duration::ZERO, "refused").await;
    let target = echo_target(GREETING).await;
    let Err(refused) = dial::session(&both.config(target), "not-a-token-of-the-role", both.port).await else {
        panic!("a refusal")
    };
    let words = "forward: missing or wrong token";
    assert!(matches!(&refused, ConnectError::Refused { status: 403, body } if body == words), "{refused:?}");
    assert!(decisive(&refused), "the relay's answer ends the race");
    assert_eq!((both.said("quic"), both.said("upgrade")), (1, 0));
}

/// The opener of each command, as a run takes it, with `PODSSH_QUIC` unset:
/// the session to `both`, its road's words, and how long it took.
async fn open_raced(both: &Both, target: u16) -> (podssh_relay::Opened, Duration) {
    let relays = RelayList { hosts: vec![both.relay()], explicit: true };
    let path = podssh_relay::relay::forward_path("127.0.0.1", target).unwrap();
    let (shown, trust) = (format!("127.0.0.1:{target}"), both.trust());
    let request =
        Request { relays: &relays, path: &path, trust: &trust, target: &shown, rounds: 1, failover: Mode::Staggered };
    let mut notes: Vec<String> = Vec::new();
    let began = Instant::now();
    let opened = podssh_relay::open(&request, &mut |note: &str| notes.push(note.to_string())).await;
    let opened = opened.unwrap_or_else(|failure| panic!("{:?}; notes {notes:?}", failure.lines(&shown)));
    (opened, began.elapsed())
}

/// The one test of this file that reads the environment. A host that
/// offered QUIC is raced over QUIC first, and its session kept; where its
/// UDP is refused, or drops each packet, the race takes TCP, and the run
/// does not try that host over QUIC again; a host that offered nothing
/// takes TCP alone, and its QUIC hears nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_opener_races_quic_where_offered_and_takes_tcp_where_udp_fails() {
    for name in ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"] {
        std::env::remove_var(name);
    }
    for name in ["PODSSH_OFFLINE", "PODSSH_H2", "PODSSH_QUIC", "PODSSH_RELAY_LAYER"] {
        std::env::remove_var(name);
    }
    let cache = std::env::temp_dir().join(format!("podssh-relay-serve-quic-{}-cache", std::process::id()));
    std::fs::create_dir_all(&cache).unwrap();
    std::env::set_var("PODSSH_CACHE_DIR", &cache);
    let target = echo_target(GREETING).await;
    // QUIC answers: its session is kept, as the TCP road waits 3 s.
    let quic = Both::start(Udp::Quic, Duration::from_secs(3), "opener-quic").await;
    std::env::set_var("PODSSH_RELAY_TOKEN", quic.token());
    kept::keep_now(&quic.relay(), &Offer { quic: Some(quic.port), ..Offer::default() });
    let (opened, _) = open_raced(&quic, target).await;
    assert_eq!(opened.road(), format!(", {WORDS}"));
    each_way(opened.session, MIB, 31).await;
    // UDP refused, then UDP that drops: TCP, and QUIC not asked again. The
    // TCP road waits 1 s, so that QUIC's arm has failed, and said so, first.
    for (udp, tag) in [(Udp::Refused, "opener-refused"), (Udp::Dropped, "opener-dropped")] {
        let both = Both::start(udp, Duration::from_secs(1), tag).await;
        kept::keep_now(&both.relay(), &Offer { quic: Some(both.port), ..Offer::default() });
        let (opened, took) = open_raced(&both, target).await;
        assert!(!opened.road().contains("QUIC"), "{tag}: {:?}", opened.road());
        assert!(took < Duration::from_secs(4), "{tag}: no wait of QUIC's handshake: {took:?}");
        assert_eq!(dial::learned(NAME, both.port), Some(Learned::Failed), "{tag}");
        each_way(opened.session, MIB, 32).await;
    }
    // Nothing offered: TCP alone, though the role serves QUIC.
    let unoffered = Both::start(Udp::Quic, Duration::ZERO, "opener-unoffered").await;
    let (opened, _) = open_raced(&unoffered, target).await;
    assert!(!opened.road().contains("QUIC"), "{:?}", opened.road());
    assert_eq!(unoffered.said("quic"), 0, "no QUIC to a host that offered none");
    std::env::remove_var("PODSSH_RELAY_TOKEN");
    let _ = std::fs::remove_dir_all(&cache);
}
