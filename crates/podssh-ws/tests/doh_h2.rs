//! DNS over HTTPS over HTTP/2 (T-344), for a resolver that serves no
//! HTTP/1.1, as Quad9 answers a GET of HTTP/1.1 with `505` (2026-10-31). The
//! server is h2's own, which podssh did not write, behind TLS that offers
//! `h2`; its answer is the one that Quad9 sent (`tests/fixtures/doh/`).

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::resolve::{h2 as doh_h2, wire};
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

/// A server for one connection that offers `alpn` and answers each GET
/// with `body`, giving back the path and the `accept` that it was asked.
async fn server(
    alpn: Vec<Vec<u8>>,
    body: Vec<u8>,
) -> (u16, Arc<rustls::RootCertStore>, tokio::task::JoinHandle<Option<(String, String)>>) {
    let (acceptor, roots) = cert::server_for(NAME).unwrap();
    let mut config = (**acceptor.config()).clone();
    config.alpn_protocols = alpn;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.ok()?;
        let tls = acceptor.accept(tcp).await.ok()?;
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
        // The connection is driven until the client goes.
        let _ = tokio::time::timeout(LIMIT, async { while connection.accept().await.is_some() {} }).await;
        Some(asked)
    });
    (port, Arc::new(roots), served)
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
    let asked = tokio::time::timeout(LIMIT, served).await.unwrap().unwrap().expect("the server was asked");
    assert_eq!(asked, (target.to_string(), "application/dns-message".to_string()));
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
    assert_eq!(tokio::time::timeout(LIMIT, served).await.unwrap().unwrap(), None, "no request reached the server");
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
