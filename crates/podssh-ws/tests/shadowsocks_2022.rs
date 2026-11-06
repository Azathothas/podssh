//! Shadowsocks 2022 (SIP022, T-492), against a stand-in server written here
//! from shadowsocks.org's `sip022.html` with the AEAD crates and BLAKE3
//! themselves, not podssh's codec: each stream's key by `derive_key` with
//! "shadowsocks 2022 session subkey" over the key and the salt; the
//! request's fixed header (type 0, a timestamp, the next header's length)
//! and its variable one (the address, then padding); the response's fixed
//! header (type 1, a timestamp, the request's salt, the first payload's
//! length). With each method: `open` names the target and carries bytes
//! each way; a wrong key ends in silence that names the server; a server
//! whose clock is 60 s off, and one that names another request's salt, are
//! refused with their words. The specification gives no test vectors of
//! TCP, so the stand-in is the reader of record. The plant of the Prove (the
//! timestamp in milliseconds) is refused by the stand-in as a replay, and
//! the first test fails.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use podssh_ws::shadowsocks::{self, ChunkError, Method, Node, OpenError};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONTEXT: &str = "shadowsocks 2022 session subkey";

/// The specification's cipher of one direction: BLAKE3's key, and the count
/// of operations as the nonce, from zero.
enum Spec {
    Chacha(Box<ChaCha20Poly1305>),
    Aes256(Box<Aes256Gcm>),
    Aes128(Box<Aes128Gcm>),
}

impl Spec {
    fn new(method: Method, psk: &[u8], salt: &[u8]) -> Spec {
        let mut hasher = blake3::Hasher::new_derive_key(CONTEXT);
        hasher.update(psk).update(salt);
        let mut key = vec![0u8; psk.len()];
        hasher.finalize_xof().fill(&mut key);
        match method {
            Method::Blake3Chacha20Poly1305 => Spec::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(&key).unwrap())),
            Method::Blake3Aes256Gcm => Spec::Aes256(Box::new(Aes256Gcm::new_from_slice(&key).unwrap())),
            Method::Blake3Aes128Gcm => Spec::Aes128(Box::new(Aes128Gcm::new_from_slice(&key).unwrap())),
            other => panic!("{other:?} is no method of SIP022"),
        }
    }

    fn nonce(n: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&n.to_le_bytes());
        nonce
    }

    fn seal(&self, n: u64, plain: &[u8]) -> Vec<u8> {
        let nonce = Spec::nonce(n);
        let gcm: aes_gcm::Nonce<aes_gcm::aead::consts::U12> = nonce.into();
        match self {
            Spec::Chacha(c) => c.encrypt(&chacha20poly1305::Nonce::from(nonce), plain).unwrap(),
            Spec::Aes256(c) => c.encrypt(&gcm, plain).unwrap(),
            Spec::Aes128(c) => c.encrypt(&gcm, plain).unwrap(),
        }
    }

    fn open(&self, n: u64, sealed: &[u8]) -> Option<Vec<u8>> {
        let nonce = Spec::nonce(n);
        let gcm: aes_gcm::Nonce<aes_gcm::aead::consts::U12> = nonce.into();
        match self {
            Spec::Chacha(c) => c.decrypt(&chacha20poly1305::Nonce::from(nonce), sealed).ok(),
            Spec::Aes256(c) => c.decrypt(&gcm, sealed).ok(),
            Spec::Aes128(c) => c.decrypt(&gcm, sealed).ok(),
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// A key of `method`'s length, and its base64.
fn key_of(method: Method, seed: u8) -> (Vec<u8>, String) {
    use base64::Engine as _;
    let key: Vec<u8> = (0..method.key_len()).map(|i| seed.wrapping_add(i as u8)).collect();
    let text = base64::engine::general_purpose::STANDARD.encode(&key);
    (key, text)
}

/// How the stand-in answers: its clock's offset from this host's, and
/// whether it names another request's salt.
#[derive(Clone, Copy)]
struct Answer {
    skew: i64,
    other_salt: bool,
}

const RIGHT: Answer = Answer { skew: 0, other_salt: false };

/// The stand-in's task: the target that it read, when the key was right.
type Served = tokio::task::JoinHandle<Option<String>>;

/// Read until `buf` holds `n` bytes; `false` when the client went first.
async fn fill(tcp: &mut TcpStream, wire: &mut Vec<u8>, n: usize) -> bool {
    let mut buf = vec![0u8; 65536];
    while wire.len() < n {
        match tcp.read(&mut buf).await {
            Ok(0) | Err(_) => return false,
            Ok(k) => wire.extend_from_slice(&buf[..k]),
        }
    }
    true
}

/// A stand-in server of SIP022 for one connection: with the right key and a
/// timestamp within 30 s it answers `banner` and echoes; a wrong key is
/// silence until the client goes, and a timestamp out of the window a
/// close, as shadowsocks-rust does. The target that it read comes back.
async fn stand_in(method: Method, psk: Vec<u8>, banner: &'static [u8], answer: Answer) -> (u16, Served) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let salt_len = method.salt_len();
        let mut wire = Vec::new();
        if !fill(&mut tcp, &mut wire, salt_len + 11 + 16).await {
            return None;
        }
        let request_salt = wire[..salt_len].to_vec();
        let reader = Spec::new(method, &psk, &request_salt);
        let Some(fixed) = reader.open(0, &wire[salt_len..salt_len + 27]) else {
            let mut buf = [0u8; 4096];
            while tcp.read(&mut buf).await.unwrap_or(0) > 0 {}
            return None;
        };
        assert_eq!(fixed[0], 0, "a request's type");
        let stamp = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
        if stamp.abs_diff(now()) > 30 {
            return None;
        }
        let var_len = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
        let at = salt_len + 27;
        assert!(fill(&mut tcp, &mut wire, at + var_len + 16).await, "the variable header came whole");
        let variable = reader.open(1, &wire[at..at + var_len + 16]).expect("the variable header opens");
        let (host, port, used) = shadowsocks::parse_address(&variable).expect("an address");
        let padding = usize::from(u16::from_be_bytes([variable[used], variable[used + 1]]));
        assert!((1..=900).contains(&padding), "padding, as no payload came with the header: {padding}");
        assert_eq!(variable.len(), used + 2 + padding, "nothing after the padding");
        let target = Some(format!("{host}:{port}"));

        let server_salt = vec![0x5au8; salt_len];
        let writer = Spec::new(method, &psk, &server_salt);
        let named = if answer.other_salt { vec![0xa5u8; salt_len] } else { request_salt.clone() };
        let mut head = vec![1u8];
        head.extend_from_slice(&((now() as i64 + answer.skew) as u64).to_be_bytes());
        head.extend_from_slice(&named);
        head.extend_from_slice(&(banner.len() as u16).to_be_bytes());
        let mut out = server_salt.clone();
        out.extend(writer.seal(0, &head));
        out.extend(writer.seal(1, banner));
        tcp.write_all(&out).await.unwrap();
        // Echo each later chunk: its sealed length, then its payload.
        let (mut n_in, mut n_out) = (2u64, 2u64);
        let mut rest = wire.split_off(at + var_len + 16);
        loop {
            while rest.len() >= 18 {
                let Some(l) = reader.open(n_in, &rest[..18]) else { return target };
                let l = usize::from(u16::from_be_bytes([l[0], l[1]]));
                if rest.len() < 18 + l + 16 {
                    break;
                }
                let plain = reader.open(n_in + 1, &rest[18..18 + l + 16]).unwrap();
                n_in += 2;
                rest.drain(..18 + l + 16);
                let mut back = writer.seal(n_out, &(plain.len() as u16).to_be_bytes());
                back.extend(writer.seal(n_out + 1, &plain));
                n_out += 2;
                tcp.write_all(&back).await.unwrap();
            }
            let more = rest.len() + 1;
            if !fill(&mut tcp, &mut rest, more).await {
                return target;
            }
        }
    });
    (port, task)
}

fn dial(answer: Duration) -> shadowsocks::Dial<'static> {
    static DIRECT: ProxyChoice = ProxyChoice::Direct;
    static TRUST: podssh_ws::Trust = podssh_ws::Trust::Default;
    let timeout = Duration::from_secs(10);
    shadowsocks::Dial { proxy: &DIRECT, trust: &TRUST, timeout, answer: Some(answer), silence_is_ready: false }
}

#[tokio::test]
async fn each_2022_method_names_the_target_reads_the_answer_and_carries_bytes_each_way() {
    for method in Method::SIP022 {
        let (psk, text) = key_of(method, 3);
        let (port, server) = stand_in(method, psk, b"SSH-2.0-stand-in\r\n", RIGHT).await;
        let node = Node::new(method, &text, "127.0.0.1", port).unwrap();
        let opened = shadowsocks::open(&node, "target.test", 2222, &dial(Duration::from_secs(5))).await.unwrap();
        assert!(opened.answered_in.is_some(), "{method:?}");
        let mut stream = opened.carried.stream;
        let mut banner = [0u8; 18];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-stand-in\r\n", "{method:?}");
        let sent: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let (mut read, mut write) = tokio::io::split(stream);
        let up = sent.clone();
        let writer = tokio::spawn(async move {
            write.write_all(&up).await.unwrap();
            write.shutdown().await.unwrap();
        });
        let mut back = vec![0u8; sent.len()];
        read.read_exact(&mut back).await.unwrap();
        writer.await.unwrap();
        assert_eq!(back, sent, "{method:?}");
        assert_eq!(server.await.unwrap().as_deref(), Some("target.test:2222"), "{method:?}");
        assert_eq!(opened.carried.status.get(), None, "an ordinary end");
    }
}

#[tokio::test]
async fn a_wrong_key_ends_in_silence_that_names_the_server_and_not_the_key() {
    let method = Method::Blake3Aes256Gcm;
    let (psk, _) = key_of(method, 1);
    let (_, wrong) = key_of(method, 2);
    let (port, _server) = stand_in(method, psk, b"SSH-2.0-x\r\n", RIGHT).await;
    let node = Node::new(method, &wrong, "127.0.0.1", port).unwrap();
    let e = shadowsocks::open(&node, "target.test", 22, &dial(Duration::from_millis(400))).await.unwrap_err();
    assert!(matches!(e, OpenError::Silent { ended: None, .. }), "{e:?}");
    let line = e.line(&node.shown(), "target.test:22");
    assert!(line.contains(&format!("ss://127.0.0.1:{port}")) && line.contains("password or the method"), "{line}");
    assert!(!line.contains(&wrong) && !format!("{node:?}").contains(&wrong), "no key in the words");
}

#[tokio::test]
async fn a_server_60_s_off_and_one_that_names_another_salt_are_refused_with_their_words() {
    let method = Method::Blake3Aes128Gcm;
    for (answer, want) in [
        (Answer { skew: 60, other_salt: false }, "this host's clock, which reads"),
        (Answer { skew: 0, other_salt: true }, "another request's salt"),
    ] {
        let (psk, text) = key_of(method, 7);
        let (port, _server) = stand_in(method, psk, b"SSH-2.0-x\r\n", answer).await;
        let node = Node::new(method, &text, "127.0.0.1", port).unwrap();
        let e = shadowsocks::open(&node, "target.test", 22, &dial(Duration::from_secs(5))).await.unwrap_err();
        let line = e.line(&node.shown(), "target.test:22");
        match (&e, answer.skew) {
            (OpenError::Chunk(ChunkError::Clock { skew, .. }), 60) => assert!((59..=61).contains(skew), "{skew}"),
            (OpenError::Chunk(ChunkError::Salt), 0) => {}
            other => panic!("{other:?}"),
        }
        assert!(line.contains("its answer was refused") && line.contains(want), "{line}");
    }
}

#[test]
fn a_2022_key_is_read_from_an_ss_line_and_one_of_several_users_is_refused() {
    let (_, text) = key_of(Method::Blake3Aes256Gcm, 9);
    // Percent-encoded, as SIP002 asks of the 2022 methods: `+`, `/` and `=`.
    let encoded: String = text.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
    let line = ["ss://", "2022-blake3-aes-256-gcm", ":", &encoded, "@127.0.0.1:8388#t"].concat();
    let node = Node::parse(&line).unwrap();
    assert_eq!(node.method, Method::Blake3Aes256Gcm);
    assert_eq!(node.master_key().len(), 32);
    // Kept and read back.
    assert!(Node::parse(&node.to_uri()).unwrap().same_server(&node));
    let users = ["ss://", "2022-blake3-aes-256-gcm", ":", &encoded, "%3A", &encoded, "@127.0.0.1:8388"].concat();
    let e = Node::parse(&users).unwrap_err();
    assert!(e.contains("SIP023") && !e.contains(&text[..8]), "{e}");
    let short = ["ss://", "2022-blake3-aes-128-gcm", ":", &encoded, "@127.0.0.1:8388"].concat();
    let e = Node::parse(&short).unwrap_err();
    assert!(e.contains("base64 of 16 bytes"), "{e}");
}
