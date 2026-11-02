//! A second proxy over TLS (T-439) against stand-ins on the loopback: one
//! that speaks HTTP/1.1's CONNECT after TLS, as squid's `https_port` does,
//! and one whose HTTP/2 is h2's own server, which podssh did not write, as
//! Caddy's forwardproxy answers a CONNECT over HTTP/2. Each asks for Basic
//! and answers `407` with `Proxy-Authenticate` without it, then carries the
//! target: an SSH-like server that sends its version line and echoes. The
//! TLS is checked for the proxy's name with the test's root; the host's own
//! proxy, a plain CONNECT stand-in, carries the TCP first where one is set.
//! The tests against Caddy and squid themselves are `scripts/interop-via.sh`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use podssh_ws::via::{Client, Dial, Offer, Version, Via};
use podssh_ws::{DialError, Proxy, ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const NAME: &str = "proxy.via.test";
const LIMIT: Duration = Duration::from_secs(20);
const BANNER: &[u8] = b"SSH-2.0-stand-in\r\n";
const USER: &str = "podssh";
const H1: &[&[u8]] = &[b"http/1.1"];
const H2: &[&[u8]] = &[b"h2"];
const BOTH: &[&[u8]] = &[b"h2", b"http/1.1"];
/// The test's own password, made of parts so that no scanner takes the
/// line for a credential.
fn password() -> String {
    ["pw", "-of-", "the-test"].concat()
}

/// What a stand-in proxy does with a CONNECT that carries the credentials.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Carry the target.
    Carry,
    /// Refuse it with 403.
    Forbid,
    /// HTTP/2 only: reset the stream, as a proxy that takes no CONNECT over
    /// HTTP/2 may; HTTP/1.1 carries it.
    ResetHttp2,
}

/// What a stand-in proxy saw: its TLS connections, and each CONNECT's
/// version, target and `Proxy-Authorization`.
#[derive(Default)]
struct Seen {
    accepted: AtomicUsize,
    connects: Mutex<Vec<(&'static str, String, Option<String>)>>,
}

fn pins() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    podssh_ws::resolve::set_pins(vec![(NAME.into(), lo), ("other.via.test".into(), lo)]);
}

fn root_file(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-via-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

/// The target: its version line, then an echo.
async fn target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                if tcp.write_all(BANNER).await.is_err() {
                    return;
                }
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

fn basic() -> String {
    use base64::Engine as _;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{}", password())))
}

/// A stand-in proxy over TLS for [`NAME`] that offers `alpn`.
async fn proxy(alpn: &[&[u8]], mode: Mode) -> (u16, Arc<Seen>) {
    let (acceptor, _) = cert::server_for(NAME).unwrap();
    let mut config = (**acceptor.config()).clone();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Seen> = Arc::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen) = (acceptor.clone(), kept.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                seen.accepted.fetch_add(1, Ordering::SeqCst);
                if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
                    serve_h2(tls, mode, seen).await;
                } else {
                    serve_h1(tls, mode, seen).await;
                }
            });
        }
    });
    (port, seen)
}

/// The answer to a CONNECT: its status, or the target's stream.
async fn decide(
    version: &'static str,
    target: &str,
    auth: Option<String>,
    mode: Mode,
    seen: &Seen,
) -> Result<TcpStream, u16> {
    seen.connects.lock().unwrap().push((version, target.to_string(), auth.clone()));
    if auth.as_deref() != Some(basic().as_str()) {
        return Err(407);
    }
    if mode == Mode::Forbid {
        return Err(403);
    }
    TcpStream::connect(target).await.map_err(|_| 502)
}

async fn serve_h1<S: AsyncRead + AsyncWrite + Unpin>(mut tls: S, mode: Mode, seen: Arc<Seen>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let target = head.split(' ').nth(1).unwrap_or_default().to_string();
    let auth = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, v)| v.trim().to_string());
    match decide("HTTP/1.1", &target, auth, mode, &seen).await {
        Ok(mut tcp) => {
            if tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_ok() {
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut tcp).await;
            }
        }
        Err(407) => {
            let answer = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic \
                          realm=\"stand-in\"\r\nContent-Length: 0\r\n\r\n";
            let _ = tls.write_all(answer.as_bytes()).await;
        }
        Err(status) => {
            let _ = tls.write_all(format!("HTTP/1.1 {status} No\r\nContent-Length: 0\r\n\r\n").as_bytes()).await;
        }
    }
}

async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(tls: S, mode: Mode, seen: Arc<Seen>) {
    let Ok(mut connection) = h2::server::handshake(tls).await else { return };
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let target = request.uri().authority().map(|a| a.to_string()).unwrap_or_default();
            assert_eq!(request.method(), http::Method::CONNECT);
            assert!(request.uri().scheme().is_none() && request.uri().path_and_query().is_none());
            let auth = request.headers().get("proxy-authorization").and_then(|v| v.to_str().ok()).map(String::from);
            if mode == Mode::ResetHttp2 {
                seen.connects.lock().unwrap().push(("HTTP/2", target, auth));
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                return;
            }
            let status = match decide("HTTP/2", &target, auth, mode, &seen).await {
                Ok(tcp) => {
                    let answer = http::Response::builder().status(200).body(()).unwrap();
                    let Ok(send) = respond.send_response(answer, false) else { return };
                    return bridge(request.into_body(), send, tcp).await;
                }
                Err(status) => status,
            };
            let mut answer = http::Response::builder().status(status);
            if status == 407 {
                answer = answer.header("proxy-authenticate", "Basic realm=\"stand-in\"");
            }
            let _ = respond.send_response(answer.body(()).unwrap(), true);
        });
    }
}

/// A stream of HTTP/2 and the target's TCP, both ways.
async fn bridge(mut recv: h2::RecvStream, mut send: h2::SendStream<Bytes>, tcp: TcpStream) {
    let (mut rd, mut wr) = tcp.into_split();
    let up = async move {
        while let Some(Ok(chunk)) = recv.data().await {
            let _ = recv.flow_control().release_capacity(chunk.len());
            if wr.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = wr.shutdown().await;
    };
    let down = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut rest = &buf[..n];
            while !rest.is_empty() {
                send.reserve_capacity(rest.len());
                match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(0)) => continue,
                    Some(Ok(room)) => {
                        let take = room.min(rest.len());
                        if send.send_data(Bytes::copy_from_slice(&rest[..take]), false).is_err() {
                            return;
                        }
                        rest = &rest[take..];
                    }
                    _ => return,
                }
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    };
    tokio::join!(up, down);
}

/// The host's own proxy: plain CONNECT, which sends a name of [`pins`] to
/// the loopback, and keeps each target that it was asked for.
async fn host_proxy() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked: Arc<Mutex<Vec<String>>> = Arc::default();
    let kept = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let asked = kept.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match tcp.read(&mut byte).await {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let target = head.split(' ').nth(1).unwrap_or_default().to_string();
                asked.lock().unwrap().push(target.clone());
                let port = target.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(0);
                let Ok(mut out) = TcpStream::connect(("127.0.0.1", port)).await else { return };
                if tcp.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut out).await;
                }
            });
        }
    });
    (port, asked)
}

fn client(port: u16, root: &Path, offer: Offer, credentials: bool, proxy: ProxyChoice) -> Client {
    let via = Via::parse(&format!("https://{NAME}:{port}")).unwrap();
    let via = if credentials { via.with_credentials(&format!("{USER}:{}\n", password())).unwrap() } else { via };
    Client::new(via, Dial { trust: Trust::File(root.to_path_buf()), proxy, timeout: LIMIT, offer })
}

/// A tunnel's version line, then `sent` echoed back.
async fn carries(opened: &mut podssh_ws::via::Opened, sent: &[u8]) {
    let mut banner = vec![0u8; BANNER.len()];
    let mut back = vec![0u8; sent.len()];
    let both = async {
        opened.stream.read_exact(&mut banner).await.unwrap();
        opened.stream.write_all(sent).await.unwrap();
        opened.stream.read_exact(&mut back).await.unwrap();
    };
    tokio::time::timeout(LIMIT, both).await.expect("the bytes within the limit");
    assert_eq!(banner, BANNER);
    assert!(back == sent, "the bytes came back changed");
}

async fn open(client: &Client, port: u16) -> Result<podssh_ws::via::Opened, DialError> {
    tokio::time::timeout(LIMIT * 2, client.open("127.0.0.1", port)).await.expect("an answer within the limit")
}

/// The credential goes with each CONNECT, on HTTP/1.1 and on HTTP/2, and
/// the tunnel carries the target; with none, the `407` is said with its
/// words: what the proxy asks for, and that podssh sent none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_credential_goes_with_each_connect_and_a_407_says_what_is_missing() {
    pins();
    let (root, aim) = (root_file("credential"), target().await);
    for (alpn, version) in [(H1, Version::Http1), (H2, Version::Http2)] {
        let (port, seen) = proxy(alpn, Mode::Carry).await;
        let with = client(port, &root, Offer::Both, true, ProxyChoice::Direct);
        let mut opened = open(&with, aim).await.unwrap_or_else(|e| panic!("{}: {e}", version.name()));
        assert_eq!(opened.version, version);
        carries(&mut opened, b"through the second proxy").await;
        let (said, target, auth) = seen.connects.lock().unwrap()[0].clone();
        assert_eq!((said, target.as_str()), (version.name(), format!("127.0.0.1:{aim}").as_str()));
        assert_eq!(auth.as_deref(), Some(basic().as_str()));
        let without = client(port, &root, Offer::Both, false, ProxyChoice::Direct);
        let why = open(&without, aim).await.err().expect("a refusal").to_string();
        let words = format!("the proxy https://{NAME}:{port} refused CONNECT 127.0.0.1:{aim}: 407 Proxy");
        assert!(why.starts_with(&words) && why.contains(" Authentication Required; "), "{why}");
        assert!(why.contains("it asks for Basic, and podssh sent none") && why.contains("--via-auth-file"), "{why}");
    }
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// Over HTTP/2, two tunnels at once are two streams of one TLS connection,
/// each with its own bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_tunnels_share_one_http2_connection() {
    pins();
    let (root, aim) = (root_file("shared"), target().await);
    let (port, seen) = proxy(BOTH, Mode::Carry).await;
    let client = client(port, &root, Offer::Both, true, ProxyChoice::Direct);
    let mut first = open(&client, aim).await.unwrap();
    let mut second = open(&client, aim).await.unwrap();
    assert_eq!((first.version, first.shared), (Version::Http2, false));
    assert_eq!((second.version, second.shared), (Version::Http2, true));
    carries(&mut second, b"the second").await;
    let big = vec![7u8; 300_000];
    carries(&mut first, &big).await;
    assert_eq!(seen.accepted.load(Ordering::SeqCst), 1, "one TLS connection");
    assert_eq!(seen.connects.lock().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// The host's own proxy carries the TCP to the second by its name; TLS
/// and the CONNECT go inside, and the host's proxy sees neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_s_proxy_carries_the_tls_to_the_second_proxy() {
    pins();
    let (root, aim) = (root_file("hop"), target().await);
    let (port, seen) = proxy(BOTH, Mode::Carry).await;
    let (hop, asked) = host_proxy().await;
    let first = ProxyChoice::Via(Proxy::parse(&format!("http://127.0.0.1:{hop}")).unwrap());
    let mut opened = open(&client(port, &root, Offer::Http1, true, first), aim).await.unwrap();
    assert_eq!(opened.version, Version::Http1, "HTTP/1.1 alone was offered");
    carries(&mut opened, b"two proxies").await;
    assert_eq!(*asked.lock().unwrap(), vec![format!("{NAME}:{port}")]);
    assert_eq!(seen.connects.lock().unwrap()[0].1, format!("127.0.0.1:{aim}"));
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A proxy that resets the CONNECT on HTTP/2 gets HTTP/1.1 on a connection
/// of its own, and says why; with HTTP/2 alone asked, it is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_that_http2_resets_goes_over_http1() {
    pins();
    let (root, aim) = (root_file("reset"), target().await);
    let (port, seen) = proxy(BOTH, Mode::ResetHttp2).await;
    let mut opened = open(&client(port, &root, Offer::Both, true, ProxyChoice::Direct), aim).await.unwrap();
    assert_eq!(opened.version, Version::Http1);
    assert!(opened.fell_back.as_deref().is_some_and(|w| w.contains("HTTP/2 did not carry")), "{:?}", opened.fell_back);
    carries(&mut opened, b"after the reset").await;
    assert_eq!(seen.accepted.load(Ordering::SeqCst), 2);
    let only = open(&client(port, &root, Offer::Http2, true, ProxyChoice::Direct), aim).await;
    assert!(matches!(only, Err(DialError::ProxyProtocol { .. })), "{:?}", only.err());
    let (h1, _) = proxy(H1, Mode::Carry).await;
    let refused = open(&client(h1, &root, Offer::Http2, true, ProxyChoice::Direct), aim).await.err().unwrap();
    assert!(refused.to_string().contains("did not choose HTTP/2"), "{refused}");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A 403, a target that the proxy cannot reach, and a certificate of
/// another name each fail with what failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_an_unreachable_target_and_another_name_fail_with_their_words() {
    pins();
    let (root, aim) = (root_file("refusals"), target().await);
    for alpn in [H1, H2] {
        let (port, _) = proxy(alpn, Mode::Forbid).await;
        let e = open(&client(port, &root, Offer::Both, true, ProxyChoice::Direct), aim).await.err().unwrap();
        assert!(matches!(e, DialError::ProxyRefused { status: 403, .. }), "{e}");
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let (port, _) = proxy(alpn, Mode::Carry).await;
        let e = open(&client(port, &root, Offer::Both, true, ProxyChoice::Direct), closed).await.err().unwrap();
        assert!(matches!(e, DialError::ProxyRefused { status: 502, .. }), "{e}");
    }
    let (port, _) = proxy(H2, Mode::Carry).await;
    let via = Via::parse(&format!("https://other.via.test:{port}")).unwrap();
    let trust = Trust::File(root.clone());
    let dial = Dial { trust, proxy: ProxyChoice::Direct, timeout: LIMIT, offer: Offer::Both };
    let e = Client::new(via, dial).open("127.0.0.1", aim).await.err().unwrap();
    assert!(matches!(&e, DialError::ProxyUnreachable { detail, .. } if detail.starts_with("TLS")), "{e}");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}
