//! Encrypted Client Hello against a TLS server of rustls's on the loopback
//! (T-642). rustls serves no ECH, so the server is one that does not take
//! it, as most are: it holds a certificate for each name, presents the one
//! that its hello asks for, and keeps each ClientHello as it read it.
//!
//! What this shows: the sealed hello names the list's public name and never
//! the host's; the host's name is inside it, under the list's key, which
//! podssh's HPKE opens with the AAD and the info that rustls's ECH made; the
//! server's refusal goes on with one plain hello, after which the name is
//! left alone; `strict` sends no plain hello; a name with no list goes plain.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_ws::crypto::hpke::{derive_key_pair, X25519_SHA256_AES_128_GCM};
use podssh_ws::ech::{self, Cache, Dial, Mode, Outcome};
use podssh_ws::{ProxyChoice, Trust};
use rustls::crypto::hpke::{EncapsulatedSecret, Hpke, HpkePrivateKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

/// The public name of the test's list, which the sealed hello names.
const PUBLIC: &str = "public.ech.test";
const LIMIT: Duration = Duration::from_secs(20);

/// Each hello that the server read: the name that it asked for, and its
/// bytes.
type Hellos = Arc<Mutex<Vec<(Option<String>, Vec<u8>)>>>;

/// A stream that keeps each byte read from it.
struct Tap {
    inner: TcpStream,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tap {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut me.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &polled {
            me.seen.lock().unwrap().extend_from_slice(&buf.filled()[before..]);
        }
        polled
    }
}

impl AsyncWrite for Tap {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A server that holds a certificate for each of `names`, and the hellos
/// that it read.
async fn server(names: &[&str]) -> (SocketAddr, Hellos) {
    let configs: Vec<(String, Arc<rustls::ServerConfig>)> = names
        .iter()
        .map(|name| (name.to_string(), cert::server_for(name).expect("a server for the name").0.config().clone()))
        .collect();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("an address");
    let hellos: Hellos = Arc::default();
    let log = hellos.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let tap = Tap { inner: tcp, seen: seen.clone() };
            let (configs, log) = (configs.clone(), log.clone());
            tokio::spawn(async move {
                let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tap);
                let Ok(start) = acceptor.await else { return };
                let asked = start.client_hello().server_name().map(str::to_string);
                log.lock().unwrap().push((asked.clone(), seen.lock().unwrap().clone()));
                let config = configs.iter().find(|(name, _)| Some(name.as_str()) == asked.as_deref());
                let Some((_, config)) = config else { return };
                if let Ok(mut tls) = start.into_stream(config.clone()).await {
                    let mut rest = Vec::new();
                    let _ = tokio::time::timeout(LIMIT, tls.read_to_end(&mut rest)).await;
                }
            });
        }
    });
    (addr, hellos)
}

/// A test's directory of its own, gone when the test ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A trust of the roots of `names`' certificates, in a file under `tag`.
fn trust(tag: &str, names: &[&str]) -> (Trust, Scratch) {
    let dir = std::env::temp_dir().join(format!("podssh-ech-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory for the roots");
    let path = dir.join("roots.pem");
    let pems: String = names
        .iter()
        .map(|name| {
            cert::encoding::pem(&cert::encoding::self_signed_inner(&cert::encoding::anchor_name(name), true).der)
        })
        .collect();
    std::fs::write(&path, pems).expect("the roots are written");
    (Trust::File(path), Scratch(dir))
}

/// An ECHConfigList of one config for `public_key`: id 7, X25519,
/// HKDF-SHA256 with AES-128-GCM, the public name [`PUBLIC`], no extension;
/// and the config alone, which HPKE's info holds.
fn list(public_key: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut contents = vec![7, 0x00, 0x20, 0x00, 0x20];
    contents.extend_from_slice(public_key);
    contents.extend_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, PUBLIC.len() as u8]);
    contents.extend_from_slice(PUBLIC.as_bytes());
    contents.extend_from_slice(&[0x00, 0x00]);
    let mut config = vec![0xfe, 0x0d];
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);
    let mut list = (config.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&config);
    (list, config)
}

fn contains(bytes: &[u8], part: &[u8]) -> bool {
    bytes.windows(part.len()).any(|w| w == part)
}

fn u16_at(bytes: &[u8], at: usize) -> usize {
    usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]))
}

/// The ClientHello of one record: its body (no handshake header), the `enc`
/// of its ECH extension, and where that extension's payload is in the body.
fn sealed_part(record: &[u8]) -> (Vec<u8>, Vec<u8>, std::ops::Range<usize>) {
    assert_eq!((record[0], record[5]), (22, 1), "a record of a handshake, holding a ClientHello");
    let len = usize::from(record[6]) << 16 | usize::from(record[7]) << 8 | usize::from(record[8]);
    let body = record[9..9 + len].to_vec();
    // The version and the random; the session id, the suites, compression.
    let mut at = 2 + 32;
    at += 1 + usize::from(body[at]);
    at += 2 + u16_at(&body, at);
    at += 1 + usize::from(body[at]);
    let end = at + 2 + u16_at(&body, at);
    at += 2;
    while at + 4 <= end {
        let (kind, len, data) = (u16_at(&body, at), u16_at(&body, at + 2), at + 4);
        if kind == 0xfe0d {
            // ECHClientHello: outer (0), the suite, the config id, enc, the payload.
            assert_eq!(body[data], 0, "an outer ECH extension");
            let enc_at = data + 1 + 4 + 1;
            let enc = body[enc_at + 2..enc_at + 2 + u16_at(&body, enc_at)].to_vec();
            let payload_at = enc_at + 2 + enc.len();
            return (body.clone(), enc, payload_at + 2..payload_at + 2 + u16_at(&body, payload_at));
        }
        at = data + len;
    }
    panic!("the ClientHello holds no ECH extension");
}

fn dial<'a>(addr: SocketAddr, name: &'a str, trust: &'a Trust, proxy: &'a ProxyChoice) -> Dial<'a> {
    Dial { host: "127.0.0.1", port: addr.port(), server_name: name, trust, proxy, limit: LIMIT, alpn: &[] }
}

#[tokio::test]
async fn a_sealed_hello_names_the_public_name_alone_and_a_refusal_goes_on_plain() {
    const NAME: &str = "relay.ech.test";
    let (addr, hellos) = server(&[PUBLIC, NAME]).await;
    let (trust, _scratch) = trust("refused", &[PUBLIC, NAME]);
    let (sk, pk) = derive_key_pair(b"the key of the test's list").expect("a key pair");
    let (list, config) = list(&pk);
    let cache = Cache::new();
    cache.remember(NAME, list, Duration::from_secs(300));
    let direct = ProxyChoice::Direct;

    let opened = ech::open_with(&cache, Mode::On, &dial(addr, NAME, &trust, &direct)).await;
    assert!(opened.is_ok(), "the plain hello after the refusal: {:?}", opened.err());
    let seen = hellos.lock().unwrap().clone();
    let asked: Vec<Option<&str>> = seen.iter().map(|(name, _)| name.as_deref()).collect();
    assert_eq!(asked, [Some(PUBLIC), Some(NAME)], "a sealed hello, then one plain hello");
    let sealed = &seen[0].1;
    assert!(!contains(sealed, NAME.as_bytes()), "the sealed hello names the host in the clear");
    // The host's name is inside, under the list's key: the AAD is the hello
    // with the payload's bytes at zero, the info "tls ech", 0 and the config.
    let (body, enc, payload) = sealed_part(sealed);
    let mut aad = body.clone();
    aad[payload.clone()].fill(0);
    let info = [&b"tls ech\0"[..], &config[..]].concat();
    let key = HpkePrivateKey::from(sk.to_vec());
    let inner = X25519_SHA256_AES_128_GCM
        .open(&EncapsulatedSecret(enc), &info, &aad, &body[payload], &key)
        .expect("the sealed hello opens with the key of the list");
    assert!(contains(&inner, NAME.as_bytes()), "the inner hello names the host");
    match ech::outcome(NAME) {
        Some(Outcome::Refused(why)) => assert!(why.contains("no retry configs"), "{why}"),
        other => panic!("the refusal was not noted: {other:?}"),
    }

    // Within 5 minutes, the name goes plain at once.
    let again = ech::open_with(&cache, Mode::On, &dial(addr, NAME, &trust, &direct)).await;
    assert!(again.is_ok(), "{:?}", again.err());
    let asked: Vec<Option<String>> = hellos.lock().unwrap().iter().map(|(name, _)| name.clone()).collect();
    assert_eq!(asked.last().cloned().flatten().as_deref(), Some(NAME));
    assert_eq!(asked.len(), 3, "one hello more, and plain");
    assert_eq!(ech::outcome(NAME), Some(Outcome::Cooled));
}

#[tokio::test]
async fn strict_sends_no_plain_hello() {
    const NAME: &str = "strict.ech.test";
    let (addr, hellos) = server(&[PUBLIC, NAME]).await;
    let (trust, _scratch) = trust("strict", &[PUBLIC, NAME]);
    let (_, pk) = derive_key_pair(b"the key of the strict list").expect("a key pair");
    let cache = Cache::new();
    cache.remember(NAME, list(&pk).0, Duration::from_secs(300));
    let direct = ProxyChoice::Direct;
    match ech::open_with(&cache, Mode::Strict, &dial(addr, NAME, &trust, &direct)).await {
        Err(e) => assert!(e.to_string().contains("PODSSH_ECH=strict"), "{e}"),
        Ok(_) => panic!("strict went on with a plain hello"),
    }
    let asked: Vec<Option<String>> = hellos.lock().unwrap().iter().map(|(name, _)| name.clone()).collect();
    assert_eq!(asked, [Some(PUBLIC.to_string())], "the sealed hello alone");
    assert!(matches!(ech::outcome(NAME), Some(Outcome::Strict(_))));
}

#[tokio::test]
async fn a_name_with_no_list_goes_plain_and_strict_refuses_it() {
    const NAME: &str = "plain.ech.test";
    let (addr, hellos) = server(&[NAME]).await;
    let (trust, _scratch) = trust("plain", &[NAME]);
    let cache = Cache::new();
    // The name's record holds no list, as the read said.
    let read = cache.lookup(NAME, || std::future::ready(Ok(None))).await;
    assert_eq!(read, ech::Lookup::None(ech::Why::NotPublished));
    let direct = ProxyChoice::Direct;
    let opened = ech::open_with(&cache, Mode::On, &dial(addr, NAME, &trust, &direct)).await;
    assert!(opened.is_ok(), "{:?}", opened.err());
    assert_eq!(ech::outcome(NAME), Some(Outcome::NotPublished));
    assert!(ech::open_with(&cache, Mode::Strict, &dial(addr, NAME, &trust, &direct)).await.is_err());
    let asked: Vec<Option<String>> = hellos.lock().unwrap().iter().map(|(name, _)| name.clone()).collect();
    assert_eq!(asked, [Some(NAME.to_string())], "one plain hello, and none in strict");
}
