//! A `rustls::ClientConfig` that the caller supplies (T-066): podssh uses it
//! as it is, for the connection, and refuses one that offers ALPN. The
//! caller's configuration here is made with podssh's own provider, so the
//! tests need no C compiler; its only root is a test CA that the default
//! store does not hold.

use std::time::Duration;

use podssh_ws::dial::ProxyChoice;
use podssh_ws::tls::{self, TlsRoots, Trust};
use podssh_ws::WsError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const NAME: &str = "relay.test";
const TIMEOUT: Duration = Duration::from_secs(10);

/// A TLS server for `NAME` on loopback, which writes `hello` and closes; the
/// trust store of its test CA.
async fn server() -> (std::net::SocketAddr, rustls::RootCertStore, tokio::task::JoinHandle<()>) {
    let (acceptor, roots) = cert::server_for(NAME).expect("a test server");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("an address");
    let task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let _ = tls.write_all(b"hello").await;
                let _ = tls.shutdown().await;
            }
        }
    });
    (addr, roots, task)
}

fn callers_config(roots: rustls::RootCertStore) -> std::sync::Arc<rustls::ClientConfig> {
    let count = roots.len();
    tls::client_config(&TlsRoots { roots, source: "the caller's test CA".into(), count }).expect("a config")
}

async fn open(addr: std::net::SocketAddr, trust: &Trust) -> Result<String, String> {
    let mut stream =
        podssh_ws::client::open_tls(&addr.ip().to_string(), addr.port(), NAME, trust, &ProxyChoice::Direct, TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
    let mut got = String::new();
    stream.read_to_string(&mut got).await.map_err(|e| e.to_string())?;
    Ok(got)
}

#[tokio::test]
async fn a_callers_configuration_reaches_a_server_that_the_default_store_does_not_know() {
    let (addr, roots, task) = server().await;
    let trust = Trust::caller(callers_config(roots)).expect("no ALPN");
    assert_eq!(open(addr, &trust).await.expect("the caller's CA verifies the server"), "hello");
    task.await.unwrap();

    // The control: podssh's own store does not hold the test CA.
    let (addr, _, task) = server().await;
    let error = open(addr, &Trust::Default).await.expect_err("the default store does not know the test CA");
    assert!(error.contains("UnknownIssuer") || error.contains("issuer"), "{error}");
    task.await.unwrap();
}

#[test]
fn a_callers_configuration_that_offers_alpn_is_refused() {
    let (_, roots) = cert::server_for(NAME).expect("a test CA");
    let mut config = (*callers_config(roots)).clone();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    match Trust::caller(std::sync::Arc::new(config)) {
        Err(WsError::Config(why)) => assert!(why.contains("ALPN (h2, http/1.1)") && why.contains("HTTP/1.1"), "{why}"),
        other => panic!("a configuration with ALPN was accepted: {other:?}"),
    }
}

#[test]
fn a_callers_configuration_is_used_as_it_is() {
    let (_, roots) = cert::server_for(NAME).expect("a test CA");
    let config = callers_config(roots);
    let trust = Trust::caller(config.clone()).expect("no ALPN");
    assert!(std::sync::Arc::ptr_eq(&tls::config_for(&trust).unwrap(), &config), "the same configuration");
    assert!(tls::roots_for(&trust).is_err(), "podssh cannot list the caller's roots");
    assert_eq!(trust.clone(), trust, "a configuration equals itself");
}
