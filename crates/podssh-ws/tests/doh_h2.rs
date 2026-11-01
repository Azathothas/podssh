//! DNS over HTTPS over HTTP/2 (T-344), for a resolver that serves no
//! HTTP/1.1, as Quad9 answers a GET of HTTP/1.1 with `505` (2026-10-31). The
//! server is h2's own, which podssh did not write, behind TLS that offers
//! `h2`; its answer is the one that Quad9 sent (`tests/fixtures/doh/`).

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_ws::resolve::{h2 as doh_h2, wire};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const NAME: &str = "doh.test";
const LIMIT: Duration = Duration::from_secs(10);

fn quad9_a() -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/doh/quad9-a.bin")).unwrap()
}

/// A client configuration that trusts the test's root alone.
fn client(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    podssh_ws::tls::client_config(&podssh_ws::tls::TlsRoots {
        count: roots.len(),
        roots,
        source: "the test's own root".into(),
    })
    .unwrap()
}

/// What the server saw: the path and the `accept` that it was asked, once
/// it answered; then whether the client ended the connection within
/// [`LIMIT`] of the answer.
struct Served {
    asked: tokio::sync::oneshot::Receiver<(String, String)>,
    ended: tokio::task::JoinHandle<Option<bool>>,
    /// A read of the server's failed: the client tore its socket, with no
    /// GOAWAY before it.
    torn: Arc<AtomicBool>,
}

/// The server's TLS stream, which notes a read that fails. A client that
/// ends its connection sends GOAWAY, and the server stops there or reads the
/// end at close_notify; rustls gives an error for a socket closed without
/// one, and the socket gives one for a reset.
struct Watched<S> {
    inner: S,
    torn: Arc<AtomicBool>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Err(_))) {
            self.torn.store(true, Ordering::SeqCst);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A server for one connection that offers `alpn` and answers each GET
/// with `body`.
async fn server(alpn: Vec<Vec<u8>>, body: Vec<u8>) -> (u16, Arc<rustls::RootCertStore>, Served) {
    let (acceptor, roots) = cert::server_for(NAME).unwrap();
    let mut config = (**acceptor.config()).clone();
    config.alpn_protocols = alpn;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (said, asked) = tokio::sync::oneshot::channel();
    let torn = Arc::new(AtomicBool::new(false));
    let seen = torn.clone();
    let ended = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.ok()?;
        let tls = acceptor.accept(tcp).await.ok()?;
        let tls = Watched { inner: tls, torn: seen };
        let mut connection = h2::server::handshake(tls).await.ok()?;
        let (request, mut respond) = connection.accept().await?.ok()?;
        let asked = (
            request.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default(),
            request.headers().get("accept").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string(),
        );
        let response =
            http::Response::builder().status(200).header("content-type", "application/dns-message").body(()).ok()?;
        let mut send = respond.send_response(response, false).ok()?;
        send.send_data(body.into(), true).ok()?;
        let _ = said.send(asked);
        // The connection is driven until the client goes, which it does once
        // it has its answer; its own bound, so that no other wait races it.
        // An error ends it too: once the socket is gone, h2's server can give
        // the same error at each call (its own shutdown on a socket that the
        // client reset), and a loop on `is_some` spins on it to the bound.
        let gone = tokio::time::timeout(LIMIT, async { while let Some(Ok(_)) = connection.accept().await {} }).await;
        Some(gone.is_ok())
    });
    (port, Arc::new(roots), Served { asked, ended, torn })
}

/// Quad9's answer comes through h2's server whole, and decodes to its
/// addresses; the server was asked the path and the type of RFC 8484.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_comes_over_http2() {
    let answer = quad9_a();
    let (port, roots, served) = server(vec![b"h2".to_vec()], answer.clone()).await;
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let target = "/dns-query?dns=AAABAAABAAAAAAAAA3RjcANzc2gFcmVsYXkEYWphbQNkZXYAAAEAAQ";
    let got = tokio::time::timeout(
        LIMIT,
        doh_h2::get_over(&client((*roots).clone()), tcp, NAME, target, "application/dns-message", 64 * 1024),
    )
    .await
    .expect("in time")
    .expect("an answer");
    assert_eq!(got.status, 200);
    assert_eq!(got.body, answer, "the bytes as the server sent them");
    let ips = wire::addrs(&got.body, "tcp.ssh.relay.ajam.dev", 1).unwrap();
    assert_eq!(ips.len(), 2, "{ips:?}");
    let asked = tokio::time::timeout(LIMIT, served.asked).await.unwrap().expect("the server was asked");
    assert_eq!(asked, (target.to_string(), "application/dns-message".to_string()));
    // The server's own bound decides; this one only holds a server that hangs.
    let ended = tokio::time::timeout(LIMIT * 2, served.ended).await.expect("the server's bound").unwrap();
    assert_eq!(ended, Some(true), "the client left its HTTP/2 connection open {} s after its answer", LIMIT.as_secs());
    // Its end was HTTP/2's own: a socket torn instead reaches a server as an
    // error, a reset or an end with no close_notify, not as the end.
    assert!(!served.torn.load(Ordering::SeqCst), "the client tore its socket, with no GOAWAY");
}

/// A server that does not take `h2` is refused at TLS, before any request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_of_http1_alone_is_refused() {
    let (port, roots, served) = server(vec![b"http/1.1".to_vec()], quad9_a()).await;
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let got = tokio::time::timeout(
        LIMIT,
        doh_h2::get_over(&client((*roots).clone()), tcp, NAME, "/dns-query?dns=AA", "application/dns-message", 1024),
    )
    .await
    .expect("in time");
    assert!(got.is_err(), "{got:?}");
    assert_eq!(
        tokio::time::timeout(LIMIT, served.ended).await.unwrap().unwrap(),
        None,
        "no request reached the server"
    );
}

/// An answer over the bound is refused, as over HTTP/1.1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_over_the_bound_is_refused() {
    let (port, roots, _served) = server(vec![b"h2".to_vec()], vec![0u8; 4096]).await;
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let got = tokio::time::timeout(
        LIMIT,
        doh_h2::get_over(&client((*roots).clone()), tcp, NAME, "/dns-query?dns=AA", "application/dns-message", 1024),
    )
    .await
    .expect("in time");
    assert!(got.as_ref().is_err_and(|e| e.contains("over 1024 bytes")), "{got:?}");
}
