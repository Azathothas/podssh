//! Trojan (T-491) against stand-ins on the loopback, as trojan-gfw's server
//! behaves (`src/session/serversession.cpp`): after TLS it reads the request,
//! compares the 56 bytes of the hash as they come, and on a match dials the
//! target and relays; on another hash, or a request that it cannot read, it
//! hands the bytes to its fallback, an HTTP server that answers `400`. In TLS
//! alone, and in a WebSocket over TLS at `/tr`, as trojan-go and Xray-core
//! serve it. A session carries the target's version line and an echo; a
//! wrong password is said as the fallback's answer; a wrong path is a 404; a
//! pipe takes a stream whose target waits for its client. The runs against
//! trojan-gfw, trojan-go and Xray-core are `scripts/interop-trojan.sh`.

mod vless_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::session::RelaySession;
use podssh_ws::trojan::{self, Dial, Opened, Server, TrojanError};
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vless_support::{cert, pins, root_file, target, BANNER, NAME};

const LIMIT: Duration = Duration::from_secs(20);
/// The stand-ins' password.
const PASSWORD: &str = "a-trojan-password-of-the-test";
/// The fallback's answer, as nginx's or a stand-in HTTP server's.
const FALLBACK: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The hex of SHA-224 that a server keeps, in lower case.
fn hash_of(password: &str) -> Vec<u8> {
    Sha224::digest(password.as_bytes()).iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}

/// What a stand-in saw: each target that a request named, each path.
#[derive(Default)]
struct Seen {
    targets: Mutex<Vec<String>>,
    paths: Mutex<Vec<String>>,
}

/// Trojan's request at the front of `buf`, once whole: the hash, the target
/// and the request's length; `None` until it is.
fn parse(buf: &[u8]) -> Option<(Vec<u8>, String, usize)> {
    if buf.len() < 60 {
        return None;
    }
    let hash = buf[..56].to_vec();
    assert_eq!(&buf[56..58], b"\r\n");
    assert_eq!(buf[58], 0x01, "CONNECT");
    let (host, at) = match buf[59] {
        0x01 => (std::net::Ipv4Addr::from(<[u8; 4]>::try_from(buf.get(60..64)?).ok()?).to_string(), 64),
        0x03 => {
            let len = usize::from(*buf.get(60)?);
            (String::from_utf8(buf.get(61..61 + len)?.to_vec()).ok()?, 61 + len)
        }
        0x04 => (std::net::Ipv6Addr::from(<[u8; 16]>::try_from(buf.get(60..76)?).ok()?).to_string(), 76),
        kind => panic!("an address of type {kind}"),
    };
    let port = u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]);
    if buf.get(at + 2..at + 4)? != b"\r\n" {
        return None;
    }
    Some((hash, format!("{host}:{port}"), at + 4))
}

/// The target of a request whose hash is the stand-in's, else none.
async fn dial(hash: &[u8], target: &str, seen: &Seen) -> Option<TcpStream> {
    if hash != hash_of(PASSWORD).as_slice() {
        return None;
    }
    seen.targets.lock().unwrap().push(target.to_string());
    TcpStream::connect(target).await.ok()
}

/// A stand-in on TLS for [`NAME`], each connection to `serve`.
async fn listen<F, Fut>(serve: F) -> (u16, Arc<Seen>)
where
    F: Fn(tokio_rustls::server::TlsStream<TcpStream>, Arc<Seen>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (acceptor, _) = cert::server_for(NAME).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Seen> = Arc::default();
    let (kept, serve) = (seen.clone(), Arc::new(serve));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen, serve) = (acceptor.clone(), kept.clone(), serve.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                serve(tls, seen).await;
            });
        }
    });
    (port, seen)
}

/// Trojan in TLS alone: the request, then the relay; a wrong hash goes to
/// the fallback, with the bytes read so far.
async fn serve_tls<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(mut tls: S, seen: Arc<Seen>) {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let (hash, target, used) = loop {
        let Ok(n) = tls.read(&mut buf).await else { return };
        if n == 0 {
            return;
        }
        got.extend_from_slice(&buf[..n]);
        if let Some(request) = parse(&got) {
            break request;
        }
    };
    let Some(mut tcp) = dial(&hash, &target, &seen).await else {
        let _ = tls.write_all(FALLBACK).await;
        let _ = tls.shutdown().await;
        return;
    };
    let _ = tcp.write_all(&got[used..]).await;
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut tcp).await;
}

/// Trojan in a WebSocket at `/tr`: the request in the first messages, then
/// each message a piece of the stream; a wrong hash gets the fallback's bytes
/// in a message, then a Close, as trojan-go's fallback over a WebSocket.
async fn serve_ws<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(mut tls: S, seen: Arc<Seen>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let path = head.split(' ').nth(1).unwrap_or_default().to_string();
    seen.paths.lock().unwrap().push(path.clone());
    if path != "/tr" {
        let _ = tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        return;
    }
    let key = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("sec-websocket-key"))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    let accept = podssh_ws::handshake::accept_key(&key);
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \
         {accept}\r\n\r\n"
    );
    if tls.write_all(answer.as_bytes()).await.is_err() {
        return;
    }
    let session = Arc::new(RelaySession::new(tls, Vec::new(), None, Duration::from_secs(30)).as_server());
    let mut got = Vec::new();
    let (hash, target, used) = loop {
        let Ok(frame) = session.read_frame().await else { return };
        got.extend_from_slice(&frame.payload);
        if let Some(request) = parse(&got) {
            break request;
        }
    };
    let Some(tcp) = dial(&hash, &target, &seen).await else {
        let _ = session.send_binary(FALLBACK).await;
        let _ = session.send_close(1000, "").await;
        return;
    };
    let (mut rd, mut wr) = tcp.into_split();
    let _ = wr.write_all(&got[used..]).await;
    let up_session = session.clone();
    let up = async move {
        while let Ok(frame) = up_session.read_frame().await {
            if frame.opcode == podssh_ws::frame::OPCODE_CLOSE || wr.write_all(&frame.payload).await.is_err() {
                break;
            }
        }
    };
    let down = async move {
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n) = rd.read(&mut buf).await {
            if n == 0 || session.send_binary(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = session.send_close(1000, "").await;
    };
    tokio::join!(up, down);
}

/// A link of the stand-in; each password of the tests needs no encoding.
fn server(port: u16, query: &str, password: &str) -> Server {
    Server::parse(&format!("trojan://{password}@{NAME}:{port}?security=tls&{query}")).unwrap()
}

async fn open(server: &Server, port: u16, root: &std::path::Path, pipe: bool) -> Result<Opened, TrojanError> {
    let trust = Trust::File(root.to_path_buf());
    let answer = if pipe { trojan::EARLY_WAIT } else { trojan::ANSWER_WAIT };
    let proxy = ProxyChoice::Direct;
    let dial =
        Dial { trust: &trust, proxy: &proxy, timeout: LIMIT, answer, silence_is_ready: pipe, close_at_end: !pipe };
    tokio::time::timeout(LIMIT * 2, trojan::open(server, "127.0.0.1", port, &dial)).await.expect("within the limit")
}

/// The target's version line, then `sent` echoed back.
async fn carries(opened: &mut Opened, sent: &[u8]) {
    let mut banner = vec![0u8; BANNER.len()];
    let mut back = vec![0u8; sent.len()];
    let both = async {
        opened.stream.read_exact(&mut banner).await.unwrap();
        opened.stream.write_all(sent).await.unwrap();
        opened.stream.read_exact(&mut back).await.unwrap();
    };
    tokio::time::timeout(LIMIT * 2, both).await.expect("the bytes within the limit");
    assert_eq!(banner, BANNER);
    assert!(back == sent, "the bytes came back changed");
}

/// Each transport carries the session: the request names the target, the
/// target's version line comes first, and a large echo comes back whole.
/// The planted hash in upper case fails both: the stand-in compares bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_goes_in_tls_alone_and_in_a_websocket() {
    pins();
    let (root, aim) = (root_file("trojan-each"), target(true).await);
    let big = vec![7u8; 300_000];
    let (tls_port, tls_seen) = listen(serve_tls).await;
    let mut opened = open(&server(tls_port, "type=tcp", PASSWORD), aim, &root, false)
        .await
        .unwrap_or_else(|e| panic!("{}", e.line("tls", "target")));
    assert!(opened.answered && opened.how == "TLS", "{}", opened.how);
    carries(&mut opened, &big).await;
    assert_eq!(*tls_seen.targets.lock().unwrap(), vec![format!("127.0.0.1:{aim}")]);
    let (ws_port, ws_seen) = listen(serve_ws).await;
    let link = server(ws_port, &format!("type=ws&path=%2Ftr&host=front.{NAME}&sni={NAME}"), PASSWORD);
    let mut opened = open(&link, aim, &root, false).await.unwrap_or_else(|e| panic!("{}", e.line("ws", "target")));
    assert!(opened.answered && opened.how == "a WebSocket over TLS", "{}", opened.how);
    carries(&mut opened, &big).await;
    assert_eq!(*ws_seen.paths.lock().unwrap(), vec!["/tr".to_string()]);
}

/// A wrong password is the fallback's answer, said with its status line and
/// never the password; a wrong path is the upgrade's 404.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_password_is_the_fallback_s_answer_and_a_wrong_path_a_404() {
    pins();
    let (root, aim) = (root_file("trojan-wrong"), target(true).await);
    let (tls_port, tls_seen) = listen(serve_tls).await;
    let (ws_port, _) = listen(serve_ws).await;
    for link in [server(tls_port, "type=tcp", "not-the-password"), server(ws_port, "type=ws&path=%2Ftr", "nope")] {
        match open(&link, aim, &root, false).await {
            Err(TrojanError::Fallback(line)) => {
                assert_eq!(line, "HTTP/1.1 400 Bad Request");
                let said = TrojanError::Fallback(line).line(&link.shown(), "t:22");
                assert!(!said.contains("not-the-password") && said.contains("not the server's"), "{said}");
            }
            Ok(_) => panic!("{}: a wrong password carried a session", link.shown()),
            Err(e) => panic!("{}: {}", link.shown(), e.line(&link.shown(), "t:22")),
        }
    }
    assert!(tls_seen.targets.lock().unwrap().is_empty(), "no target for a wrong password");
    match open(&server(ws_port, "type=ws&path=%2Fother", PASSWORD), aim, &root, false).await {
        Err(TrojanError::Refused { status: 404, why }) => assert!(why.contains("/other"), "{why}"),
        Ok(_) => panic!("another path carried a session"),
        Err(e) => panic!("{}", e.line("ws", "t")),
    }
}

/// A pipe's target waits for its client: after the short wait the stream is
/// taken, and the echo comes back; the request's address is the target's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_takes_a_stream_whose_target_waits_for_its_client() {
    pins();
    let (root, aim) = (root_file("trojan-pipe"), target(false).await);
    let (tls_port, seen) = listen(serve_tls).await;
    let mut opened = open(&server(tls_port, "", PASSWORD), aim, &root, true)
        .await
        .unwrap_or_else(|e| panic!("{}", e.line("pipe", "t")));
    assert!(!opened.answered, "the target said nothing");
    opened.stream.write_all(b"ping\n").await.unwrap();
    let mut back = [0u8; 5];
    tokio::time::timeout(LIMIT, opened.stream.read_exact(&mut back)).await.expect("the echo in time").unwrap();
    assert_eq!(&back, b"ping\n");
    assert_eq!(seen.targets.lock().unwrap().len(), 1);
}
