//! A name published on podssh's relay role (T-649, GitHub #147), on the
//! loopback. The role takes each connection as `podssh relay serve` takes it
//! (`serve::listener::connection`), its TLS a leaf of the test's CA for its
//! own name and the loopback's address, with the cleartext road beside it;
//! its table publishes `site.publish.test` to a pair whose node, podssh's
//! own, dials an HTTPS server of the test's, which ends TLS itself with its
//! own leaf. A TLS client of the published name gets the server's leaf, never
//! the role's, in any case of the name, and its bytes come back whole; a
//! client of the role's own name, a client by address, a request in
//! cleartext and a ClientHello cut short go to the role as before; a CA's
//! validation (`acme-tls/1`) of the role's name gets the role's leaf of
//! TLS-ALPN-01, and one of the published name the node's. A published name
//! whose pair has no node, or that names no pair, closes. The ClientHellos
//! that rustls writes are read as the role reads them.
//!
//!     cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_publish
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod publish_harness;
mod role_harness;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::pair::Pair;
use podssh_relay::reverse::{self, Exit, Handler, NodeConfig, Opening, SessionId, Settings, Wire};
use podssh_relay::serve::listener::{connection, Door};
use podssh_relay::serve::published::Published;
use podssh_relay::serve::sni;
use podssh_ws::tls_server::{acceptor_for, ACME_TLS_1, HTTP1};
use podssh_ws::{ProxyChoice, Trust};
use publish_harness::{captured_hello, site, visit, Certs, ROLE, SITE};
use role_harness::{Role, LIMIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// How long the role waits for a ClientHello here: the 10 s of
/// `published::WAIT`, made short so that a test of a cut hello is.
const HELLO_WAIT: Duration = Duration::from_secs(1);

/// The node's side: each session one connection to the HTTPS server at
/// `port`, counted.
struct Site {
    port: u16,
    opened: Arc<AtomicUsize>,
}

impl Handler for Site {
    type Stream = TcpStream;

    fn open(&self, _id: SessionId) -> Opening<TcpStream> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        let port = self.port;
        Box::pin(async move { TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string()) })
    }
}

/// podssh's node for `pair`, on the plain wire, until `stop`.
async fn node(pair: Pair, handler: Site, stop: oneshot::Receiver<()>) -> Exit {
    let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
    let mut config = NodeConfig {
        pair,
        label: None,
        trust: &trust,
        proxy: &proxy,
        timeout: LIMIT,
        settings: Settings::default(),
        repair: None,
        wire: Wire::PlainLoopback,
        say: None,
    };
    reverse::run(&mut config, Arc::new(handler), async {
        let _ = stop.await;
    })
    .await
}

/// The role, its node's sessions counted, the port of its door of TLS, and
/// what stops its node.
struct Rig {
    role: Role,
    certs: Certs,
    door: u16,
    opened: Arc<AtomicUsize>,
    pair: String,
    _stop: Option<oneshot::Sender<()>>,
}

/// The role with its door of TLS, which publishes [`SITE`] to a pair of its
/// own: with its node online when `online`, and to a pair of no such name
/// when `pair` names one.
async fn start(tag: &str, online: bool, pair: Option<&str>) -> Rig {
    let role = Role::start().await;
    let certs = Certs::new(tag);
    let made = role.pair();
    let name = pair.map_or(made.name.clone(), str::to_string);
    let opened = Arc::new(AtomicUsize::new(0));
    let stop = match online {
        true => {
            let handler = Site { port: site(&certs).await, opened: opened.clone() };
            let (stop, stopped) = oneshot::channel();
            tokio::spawn(node(made, handler, stopped));
            role.until_said("reverse node").await;
            Some(stop)
        }
        false => None,
    };
    let table = Published::of(&[format!("{SITE}={name}")]).unwrap().waiting(HELLO_WAIT);
    let served = Certs::served(&certs.role, ROLE, &certs.role_challenge);
    let acceptor = acceptor_for(served, &[HTTP1, ACME_TLS_1]).unwrap();
    let door = Door { acceptor, cleartext: true, sshd: None, published: Arc::new(table) };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = role.cfg.clone();
    tokio::spawn(async move {
        while let Ok((tcp, peer)) = listener.accept().await {
            tokio::spawn(connection(tcp, peer.ip(), door.clone(), cfg.clone()));
        }
    });
    Rig { role, certs, door: port, opened, pair: name, _stop: stop }
}

impl Rig {
    fn sessions(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }

    fn published_lines(&self) -> usize {
        self.role.events.lock().unwrap().iter().filter(|line| line.starts_with("publish ")).count()
    }
}

/// Bytes from a fixed xorshift, so that a byte out of place shows.
fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// `GET /health` on `stream`, and the status line of its answer.
async fn health<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(stream: &mut S) -> String {
    let ask = format!("GET /health HTTP/1.1\r\nHost: {ROLE}\r\nConnection: close\r\n\r\n");
    stream.write_all(ask.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(LIMIT, stream.read_to_end(&mut answer)).await;
    String::from_utf8_lossy(&answer).lines().next().unwrap_or_default().to_string()
}

/// T-649: the published name, in its case and in another, reaches the
/// node's HTTPS server, whose leaf the client gets, never the role's; 256
/// KiB go up and come back whole; the role says the name and the visitor,
/// at the start and at the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_published_name_reaches_the_node_s_server_with_its_own_certificate() {
    let p = start("reach", true, None).await;
    for asked in [SITE, "Site.Publish.TEST"] {
        let got = visit(&p.certs, p.door, asked, &[HTTP1]).await.unwrap_or_else(|why| panic!("{asked}: {why}"));
        assert!(got.leaf == p.certs.site.der, "{asked}: the node's server's leaf");
        assert!(got.leaf != p.certs.role.der, "{asked}: not the role's");
        let (mut down, mut up) = tokio::io::split(got.tls);
        let sent = pattern(256 * 1024);
        // Its close_notify after the bytes: the server's echo, then its own,
        // ends the session at the node.
        let writer = {
            let sent = sent.clone();
            tokio::spawn(async move {
                let _ = up.write_all(&sent).await;
                let _ = up.shutdown().await;
            })
        };
        let mut back = vec![0u8; sent.len()];
        let read = tokio::time::timeout(LIMIT, down.read_exact(&mut back)).await;
        assert!(matches!(read, Ok(Ok(_))), "{asked}: the echo came back: {read:?}");
        assert!(back == sent, "{asked}: each byte, in order");
        writer.await.unwrap();
    }
    assert_eq!(p.sessions(), 2, "one session of the node for each visit");
    p.role.until_said(&format!("publish {SITE} from 127.0.0.1: to the node of {}", p.pair)).await;
    p.role.until_said(&format!("publish {SITE} from 127.0.0.1 ended after")).await;
}

/// T-649: the role's own name, an address with no name, and a request in
/// cleartext are the role's, as before: no session of the node, and no
/// line of a published name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_role_s_own_name_an_address_and_cleartext_go_to_the_role() {
    let p = start("own", true, None).await;
    for asked in [ROLE, "127.0.0.1"] {
        let mut got = visit(&p.certs, p.door, asked, &[HTTP1]).await.unwrap_or_else(|why| panic!("{asked}: {why}"));
        assert!(got.leaf == p.certs.role.der, "{asked}: the role's own leaf");
        assert_eq!(health(&mut got.tls).await, "HTTP/1.1 200 OK", "{asked}");
    }
    let mut plain = TcpStream::connect(("127.0.0.1", p.door)).await.unwrap();
    assert_eq!(health(&mut plain).await, "HTTP/1.1 200 OK", "the cleartext road");
    assert_eq!((p.sessions(), p.published_lines()), (0, 0));
}

/// T-649: a ClientHello of the published name, as rustls writes it, cut
/// short: the role waits for it within its bound, then gives what came to
/// its own TLS, which answers the rest; the node never hears of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_hello_cut_short_goes_to_the_role_s_tls() {
    let p = start("cut", true, None).await;
    let hello = captured_hello(&p.certs, SITE, &[HTTP1]).await;
    let mut tcp = TcpStream::connect(("127.0.0.1", p.door)).await.unwrap();
    tcp.write_all(&hello[..hello.len() / 2]).await.unwrap();
    tokio::time::sleep(HELLO_WAIT * 2).await;
    tcp.write_all(&hello[hello.len() / 2..]).await.unwrap();
    let mut first = [0u8; 1];
    let read = tokio::time::timeout(LIMIT, tcp.read_exact(&mut first)).await;
    assert!(matches!(read, Ok(Ok(_))), "the role's TLS answered: {read:?}");
    // A record of TLS's: its ServerHello, or its alert.
    assert!(matches!(first[0], 0x15 | 0x16), "{first:?}");
    assert_eq!((p.sessions(), p.published_lines()), (0, 0));
}

/// T-649: a CA's validation of the role's own name gets the role's leaf of
/// TLS-ALPN-01, and the handshake alone; one of the published name goes to
/// the node, whose server answers it with its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acme_tls_1_of_the_role_s_name_is_the_role_s_and_of_the_published_name_the_node_s() {
    let p = start("acme", true, None).await;
    let mut own = visit(&p.certs, p.door, ROLE, &[ACME_TLS_1]).await.expect("the role's validation");
    assert!(own.leaf == p.certs.role_challenge.der, "the role's leaf of TLS-ALPN-01");
    assert_eq!(own.alpn.as_deref(), Some(ACME_TLS_1));
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(LIMIT, own.tls.read_to_end(&mut rest)).await;
    assert!(rest.is_empty(), "the handshake alone");
    assert_eq!((p.sessions(), p.published_lines()), (0, 0), "the role's own validation");
    let theirs = visit(&p.certs, p.door, SITE, &[ACME_TLS_1]).await.expect("the node's validation");
    assert!(theirs.leaf == p.certs.site_challenge.der, "the node's leaf of TLS-ALPN-01");
    assert_eq!(theirs.alpn.as_deref(), Some(ACME_TLS_1));
    assert_eq!(p.sessions(), 1);
    p.role.until_said(&format!("publish a CA's validation of {SITE} from 127.0.0.1: to the node of")).await;
}

/// T-649: a published name whose pair's node is away closes, and so does
/// one that names no pair of the role's; each says why on the role's lines.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_published_name_with_no_node_closes_and_says_why() {
    let away = start("away", false, None).await;
    assert!(visit(&away.certs, away.door, SITE, &[HTTP1]).await.is_err(), "no TLS answers for the name");
    away.role.until_said("node unavailable").await;
    let none = start("none", false, Some("p-nopairofthisname")).await;
    assert!(visit(&none.certs, none.door, SITE, &[HTTP1]).await.is_err(), "no TLS answers for the name");
    none.role.until_said("its pair p-nopairofthisname is not one of this relay's").await;
}

/// T-649: the ClientHellos that rustls writes, read as the role reads them:
/// the name as written, and a CA's validation by its ALPN alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_hellos_of_rustls_are_read_as_the_role_reads_them() {
    let certs = Certs::new("rustls");
    let read = |name: &str, acme: bool| sni::Read::Hello(sni::Hello { name: Some(name.to_string()), acme });
    assert_eq!(sni::read(&captured_hello(&certs, SITE, &[HTTP1]).await), read(SITE, false));
    assert_eq!(sni::read(&captured_hello(&certs, "Site.Publish.TEST", &[]).await), read("Site.Publish.TEST", false));
    assert_eq!(sni::read(&captured_hello(&certs, SITE, &[ACME_TLS_1]).await), read(SITE, true));
    let both = captured_hello(&certs, SITE, &[&b"h2"[..], ACME_TLS_1]).await;
    assert_eq!(sni::read(&both), read(SITE, false));
    // Each part of a whole hello waits for more.
    let hello = captured_hello(&certs, ROLE, &[HTTP1]).await;
    assert!((0..hello.len()).all(|cut| sni::read(&hello[..cut]) == sni::Read::More));
}
