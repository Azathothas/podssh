//! The WebSocket over HTTP/2's extended CONNECT (T-321, RFC 8441) against
//! stand-in relays on the loopback whose HTTP/2 is h2's own server, which
//! podssh did not write: one whose SETTINGS offer extended CONNECT, which
//! takes a CONNECT with `:protocol websocket`, checks its token, answers 200
//! and echoes each message, as podssh's relay role does; one whose SETTINGS
//! offer none; and one whose TLS chooses http/1.1 alone. Each also takes the
//! upgrade of HTTP/1.1, as a relay does, and counts its TLS connections, its
//! upgrades, the CONNECTs that reach it, and each HEADERS frame that the
//! client sends on its HTTP/2, read off the wire before h2 reads it. TLS is
//! checked for the relay's name with the test's root.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::h2_road::{self, Fallback, Offered, Road};
use podssh_ws::{ConnectError, Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const NAME: &str = "relay.h2.test";
const TOKEN: &str = "token-of-the-test";
const PATH: &str = "/connect/127.0.0.1/22";
const LIMIT: Duration = Duration::from_secs(60);
const MIB: usize = 1 << 20;
const REFUSAL: &str = "forward: missing or wrong token";
const H1: &[&[u8]] = &[b"http/1.1"];
const BOTH: &[&[u8]] = &[b"h2", b"http/1.1"];

/// What a stand-in's TLS and HTTP/2 offer.
#[derive(Clone, Copy, PartialEq)]
enum Offer {
    Extended,
    NoSetting,
    Http1Only,
}

/// A CONNECT of HTTP/2 as the stand-in's application got it.
#[derive(Debug)]
struct Asked {
    protocol: Option<String>,
    scheme: Option<String>,
    authority: Option<String>,
    path: Option<String>,
    version: Option<String>,
    key: Option<String>,
}

#[derive(Default)]
struct Seen {
    accepted: AtomicUsize,
    upgrades: AtomicUsize,
    headers: AtomicUsize,
    connects: Mutex<Vec<Asked>>,
    /// Each connection's task, for a cut.
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

fn pins() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    podssh_ws::resolve::set_pins(vec![(NAME.into(), lo)]);
}

fn root_file(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-h2-road-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

fn config(port: u16, root: &Path) -> WsClientConfig {
    WsClientConfig {
        endpoint: Endpoint { host: NAME.into(), port, path: PATH.into() },
        trust: Trust::File(root.to_path_buf()),
        server_name: NAME.into(),
        timeout: LIMIT,
        idle_timeout: Some(LIMIT),
        proxy: ProxyChoice::Direct,
    }
}

/// The frames of HTTP/2 that a client sends, read past the preface by their
/// headers alone: each HEADERS (type 1) is counted.
struct Wire {
    preface: usize,
    head: Vec<u8>,
    skip: usize,
}

impl Wire {
    fn feed(&mut self, mut bytes: &[u8], seen: &Seen) {
        while !bytes.is_empty() {
            let n = if self.preface > 0 {
                let n = self.preface.min(bytes.len());
                self.preface -= n;
                n
            } else if self.skip > 0 {
                let n = self.skip.min(bytes.len());
                self.skip -= n;
                n
            } else {
                let n = (9 - self.head.len()).min(bytes.len());
                self.head.extend_from_slice(&bytes[..n]);
                if self.head.len() == 9 {
                    let h = &self.head;
                    self.skip = (h[0] as usize) << 16 | (h[1] as usize) << 8 | h[2] as usize;
                    if h[3] == 0x1 {
                        seen.headers.fetch_add(1, Ordering::SeqCst);
                    }
                    self.head.clear();
                }
                n
            };
            bytes = &bytes[n..];
        }
    }
}

/// The client's bytes on their way to h2's server, read by [`Wire`].
struct Tap<S> {
    inner: S,
    wire: Wire,
    seen: Arc<Seen>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &polled {
            this.wire.feed(&buf.filled()[before..], &this.seen);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
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

/// A stand-in relay for [`NAME`] that offers `offer`.
async fn stand_in(offer: Offer) -> (u16, Arc<Seen>) {
    let (acceptor, _) = cert::server_for(NAME).unwrap();
    let mut tls = (**acceptor.config()).clone();
    let alpn = if offer == Offer::Http1Only { H1 } else { BOTH };
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Seen> = Arc::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen) = (acceptor.clone(), kept.clone());
            let task = tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                seen.accepted.fetch_add(1, Ordering::SeqCst);
                if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
                    let wire = Wire { preface: 24, head: Vec::new(), skip: 0 };
                    serve_h2(Tap { inner: tls, wire, seen: seen.clone() }, offer, seen).await;
                } else {
                    serve_h1(tls, seen).await;
                }
            });
            kept.tasks.lock().unwrap().push(task.abort_handle());
        }
    });
    (port, seen)
}

async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: S, offer: Offer, seen: Arc<Seen>) {
    let mut builder = h2::server::Builder::new();
    builder.max_concurrent_streams(32);
    if offer == Offer::Extended {
        builder.enable_connect_protocol();
    }
    let Ok(mut connection) = builder.handshake::<_, Bytes>(io).await else { return };
    while let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(answer_h2(request, respond, seen.clone()));
    }
}

async fn answer_h2(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    seen: Arc<Seen>,
) {
    let (asked, token_ok) = {
        let field = |name: &str| request.headers().get(name).and_then(|v| v.to_str().ok()).map(String::from);
        let asked = Asked {
            protocol: request.extensions().get::<h2::ext::Protocol>().map(|p| p.as_str().to_string()),
            scheme: request.uri().scheme_str().map(String::from),
            authority: request.uri().authority().map(|a| a.to_string()),
            path: request.uri().path_and_query().map(|p| p.to_string()),
            version: field("sec-websocket-version"),
            key: field("sec-websocket-key"),
        };
        (asked, field("x-relay-token").as_deref() == Some(TOKEN))
    };
    seen.connects.lock().unwrap().push(asked);
    if !token_ok {
        let answer = http::Response::builder().status(403).header("content-type", "text/plain").body(()).unwrap();
        if let Ok(mut send) = respond.send_response(answer, false) {
            let _ = send.send_data(Bytes::from(format!("{REFUSAL}\n")), true);
        }
        return;
    }
    let Ok(send) = respond.send_response(http::Response::builder().status(200).body(()).unwrap(), false) else {
        return;
    };
    echo(podssh_ws::server::session(h2_road::duplex(send, request.into_body()), Vec::new(), None)).await;
}

async fn serve_h1<S: AsyncRead + AsyncWrite + Unpin>(mut tls: S, seen: Arc<Seen>) {
    let Ok((head, pending)) = podssh_ws::http::request::read_request(&mut tls, Vec::new()).await else { return };
    if head.header("x-relay-token") != Some(TOKEN) {
        let _ = tls.write_all(&podssh_ws::http::request::refusal(403, REFUSAL, &[])).await;
        return;
    }
    let key = match podssh_ws::server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => {
            let _ = tls.write_all(&refused.answer()).await;
            return;
        }
    };
    seen.upgrades.fetch_add(1, Ordering::SeqCst);
    if tls.write_all(&podssh_ws::server::switching(&key)).await.is_ok() {
        echo(podssh_ws::server::session(tls, pending, None)).await;
    }
}

/// Each binary message back as it came, until the Close, which the
/// session's reader answers.
async fn echo<S: AsyncRead + AsyncWrite>(session: RelaySession<S>) {
    while let Ok(frame) = session.read_frame().await {
        if frame.opcode != OPCODE_BINARY || session.send_binary(&frame.payload).await.is_err() {
            return;
        }
    }
}

/// Bytes that a seed fixes (xorshift64*).
fn bytes(size: usize, mut seed: u64) -> Vec<u8> {
    (0..size)
        .map(|_| {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            (seed.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// `size` bytes out through `session` in messages of 64 KiB while the echo
/// is read: each byte back once, in order, by digest; then the Close.
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
    let (mut back, mut got) = (Sha256::new(), 0);
    let read = async {
        while got < size {
            let frame = session.read_frame().await.expect("a message back");
            assert_eq!(frame.opcode, OPCODE_BINARY);
            got += frame.payload.len();
            back.update(&frame.payload);
        }
    };
    tokio::time::timeout(LIMIT, read).await.expect("the echo within the limit");
    writer.await.unwrap();
    assert_eq!(got, size, "each byte came back once");
    assert_eq!(back.finalize(), sent, "the digests are equal");
    let _ = session.send_close(1000, "").await;
}

async fn connect(config: &WsClientConfig, token: &str) -> Result<(RelaySession, Road), ConnectError> {
    tokio::time::timeout(LIMIT * 2, h2_road::connect(config, token)).await.expect("an answer within the limit")
}

/// Eight sessions at once are eight streams of one TLS connection, each
/// with its own 4 MiB each way, and each CONNECT is RFC 8441's: no key of
/// RFC 6455 and no upgrade of HTTP/1.1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_sessions_share_one_tls_connection_and_carry_4_mib_each_way() {
    pins();
    let root = root_file("eight");
    let (port, seen) = stand_in(Offer::Extended).await;
    let mut tasks = Vec::new();
    for seed in 1..=8u64 {
        let config = config(port, &root);
        tasks.push(tokio::spawn(async move {
            let (session, road) = connect(&config, TOKEN).await.expect("a session on the road");
            each_way(session, 4 * MIB, seed).await;
            road
        }));
    }
    let mut roads = Vec::new();
    for task in tasks {
        roads.push(task.await.unwrap());
    }
    assert_eq!(seen.accepted.load(Ordering::SeqCst), 1, "one TLS connection for the eight sessions: {roads:?}");
    assert_eq!(roads.iter().filter(|r| **r == Road::Stream { shared: false }).count(), 1, "{roads:?}");
    assert_eq!(roads.iter().filter(|r| **r == Road::Stream { shared: true }).count(), 7, "{roads:?}");
    let connects = seen.connects.lock().unwrap();
    assert_eq!(connects.len(), 8);
    let authority = format!("{NAME}:{port}");
    for asked in connects.iter() {
        assert_eq!(asked.protocol.as_deref(), Some("websocket"), "{asked:?}");
        assert_eq!((asked.scheme.as_deref(), asked.path.as_deref()), (Some("https"), Some(PATH)), "{asked:?}");
        assert_eq!(asked.authority.as_deref(), Some(authority.as_str()), "{asked:?}");
        assert_eq!(asked.version.as_deref(), Some("13"), "{asked:?}");
        assert_eq!(asked.key, None, "RFC 8441 drops Sec-WebSocket-Key: {asked:?}");
    }
    assert_eq!(seen.upgrades.load(Ordering::SeqCst), 0, "no upgrade of HTTP/1.1");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A server that chose `h2` and offered no extended CONNECT gets no request
/// on its HTTP/2, and the upgrade of HTTP/1.1 on a new connection; the
/// process then asks it for no HTTP/2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_offers_no_extended_connect_gets_the_upgrade_on_a_new_connection() {
    pins();
    let root = root_file("unoffered");
    let (port, seen) = stand_in(Offer::NoSetting).await;
    let (session, road) = connect(&config(port, &root), TOKEN).await.expect("a session");
    let headers = seen.headers.load(Ordering::SeqCst);
    assert_eq!(headers, 0, "a request went on an HTTP/2 connection whose SETTINGS offered no extended CONNECT");
    assert_eq!(road, Road::Http1(Fallback::NotOffered));
    assert_eq!(seen.accepted.load(Ordering::SeqCst), 2, "the upgrade on a new connection");
    assert_eq!(seen.upgrades.load(Ordering::SeqCst), 1);
    each_way(session, MIB, 9).await;
    let (session, road) = connect(&config(port, &root), TOKEN).await.expect("a second session");
    assert_eq!(road, Road::Http1(Fallback::Remembered(Box::new(Fallback::NotOffered))));
    assert_eq!(seen.accepted.load(Ordering::SeqCst), 3, "one connection for the second session");
    assert_eq!(seen.headers.load(Ordering::SeqCst), 0);
    assert!(seen.connects.lock().unwrap().is_empty());
    each_way(session, MIB, 10).await;
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A server whose TLS chose http/1.1 gets the upgrade on that connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_whose_tls_chooses_http1_gets_the_upgrade_on_the_same_connection() {
    pins();
    let root = root_file("http1");
    let (port, seen) = stand_in(Offer::Http1Only).await;
    let (session, road) = connect(&config(port, &root), TOKEN).await.expect("a session");
    assert_eq!(road, Road::Http1(Fallback::NotChosen));
    assert_eq!(seen.accepted.load(Ordering::SeqCst), 1, "the upgrade on the connection whose TLS chose it");
    assert_eq!(seen.upgrades.load(Ordering::SeqCst), 1);
    each_way(session, MIB, 11).await;
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A 403 on the CONNECT is the relay's refusal, with its words, as of the
/// upgrade; the connection stays, and the right token opens a session on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_403_on_the_connect_ends_the_session_with_the_relay_s_refusal() {
    pins();
    let root = root_file("refused");
    let (port, seen) = stand_in(Offer::Extended).await;
    let refused = connect(&config(port, &root), "a-wrong-token").await.err().expect("a refusal");
    assert!(matches!(&refused, ConnectError::Refused { status: 403, body } if body == REFUSAL), "{refused:?}");
    let accepted = seen.accepted.load(Ordering::SeqCst);
    assert_eq!(accepted, 1, "the refusal on HTTP/2 is the session's end: no connection of HTTP/1.1 after it");
    assert_eq!(seen.upgrades.load(Ordering::SeqCst), 0);
    let (session, road) = connect(&config(port, &root), TOKEN).await.expect("a session");
    assert_eq!(road, Road::Stream { shared: true });
    assert_eq!(seen.accepted.load(Ordering::SeqCst), 1);
    each_way(session, MIB, 12).await;
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A lost connection is a lost link for each of its sessions at once, and
/// the next session opens a new connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_connection_ends_each_of_its_sessions_and_the_next_opens_a_new_one() {
    pins();
    let root = root_file("lost");
    let (port, seen) = stand_in(Offer::Extended).await;
    let (first, _) = connect(&config(port, &root), TOKEN).await.expect("a first session");
    let (second, road) = connect(&config(port, &root), TOKEN).await.expect("a second session");
    assert_eq!(road, Road::Stream { shared: true });
    for task in seen.tasks.lock().unwrap().drain(..) {
        task.abort();
    }
    for session in [&first, &second] {
        let ended = async {
            loop {
                if let Err(e) = session.read_frame().await {
                    return e;
                }
            }
        };
        tokio::time::timeout(LIMIT, ended).await.expect("each session ends when its connection is lost");
    }
    let (third, road) = connect(&config(port, &root), TOKEN).await.expect("a session on a new connection");
    assert_eq!(road, Road::Stream { shared: false });
    assert_eq!(seen.accepted.load(Ordering::SeqCst), 2);
    each_way(third, MIB, 13).await;
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// The probe of `doctor` names what each stand-in offers, and sends no
/// request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_probe_names_the_alpn_and_the_setting_and_sends_no_request() {
    pins();
    let root = root_file("probe");
    let (trust, direct) = (Trust::File(root.clone()), ProxyChoice::Direct);
    let probe = |port| h2_road::probe(NAME, port, NAME, &trust, &direct, LIMIT);
    let h2 = Some("h2".to_string());
    for (offer, expected) in [
        (Offer::Extended, Offered { alpn: h2.clone(), extended: Some(true), streams: Some(32) }),
        (Offer::NoSetting, Offered { alpn: h2.clone(), extended: Some(false), streams: Some(32) }),
        (Offer::Http1Only, Offered { alpn: Some("http/1.1".into()), extended: None, streams: None }),
    ] {
        let (port, seen) = stand_in(offer).await;
        let offered = tokio::time::timeout(LIMIT, probe(port)).await.expect("within the limit").expect("a probe");
        assert_eq!(offered, expected);
        assert_eq!(seen.headers.load(Ordering::SeqCst), 0, "the probe sends no request");
        assert_eq!(seen.upgrades.load(Ordering::SeqCst), 0, "the probe sends no request");
    }
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}
