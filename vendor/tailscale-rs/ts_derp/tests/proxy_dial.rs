//! Increment 2 (E39): the DERP dial path routes through the proxy.
//!
//! `dial_server` takes a `ServerConnInfo`; under proxy the CONNECT authority
//! is its hostname, and `FixedAddr` is never consulted. The fake proxy below
//! records the authority: if the dial went direct, nothing connects to the
//! fake (unroutable hostname) and the dial fails — so this test is the plant
//! for the rewire, not just its proof.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ts_derp::dial::dial_server;
use ts_derp::ServerConnInfo;
use ts_http_util::proxy::{ProxyConfig, configure};

/// ⛔ **The rewire, as a test.** Remove the proxy branch in `dial_by_ipusage`
/// and this dials `relay.invalid` direct, which cannot resolve — the dial
/// fails, and the fake records zero CONNECTs.
#[tokio::test]
async fn dial_server_connects_by_hostname_through_the_proxy() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let authority = String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or("")
            .strip_prefix("CONNECT ")
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        seen_task.lock().unwrap().push(authority);
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
    });

    configure(Some(
        ProxyConfig::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
    ));
    struct ResetOnDrop;
    impl Drop for ResetOnDrop {
        fn drop(&mut self) {
            configure(None);
        }
    }
    let _reset = ResetOnDrop;

    // `.invalid` never resolves: success is only possible via the tunnel.
    let server = ServerConnInfo::default_from_url(
        &url::Url::parse("https://relay.invalid:443").unwrap(),
    )
    .unwrap();
    let stream = dial_server(&server).await.expect("dial via the fake proxy");
    assert!(stream.is_some());
    assert_eq!(*seen.lock().unwrap(), vec!["relay.invalid:443".to_string()]);
}
