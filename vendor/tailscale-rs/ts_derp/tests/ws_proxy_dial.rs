//! podssh's patch 0017: the DERP dial over WebSocket goes through the proxy.
//!
//! `ws::connect` opened TCP to the relay directly, with the system resolver
//! and no bound, so on a host whose only egress is a CONNECT proxy the node
//! never reached DERP. Now it asks the proxy to `CONNECT` the relay by name.
//! The fake proxy below records the authority: dialled directly, the
//! `.invalid` name cannot resolve, nothing reaches the fake, and this test
//! fails.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ts_http_util::proxy::{ProxyConfig, configure};

/// Resets the process proxy when the test returns, pass or fail.
struct ResetOnDrop;
impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        configure(None);
    }
}

#[tokio::test]
async fn ws_connect_dials_the_relay_by_name_through_the_proxy() {
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
        let first = String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        seen_task.lock().unwrap().push(first);
        // A tunnel that closes at once: the TLS handshake fails, after the
        // name went to the proxy.
        let _ = stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await;
    });

    configure(Some(
        ProxyConfig::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
    ));
    let _reset = ResetOnDrop;

    let result = ts_derp::ws::connect("relay.invalid", 443).await;
    assert!(result.is_err(), "the fake proxy's tunnel speaks no TLS");
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["CONNECT relay.invalid:443 HTTP/1.1".to_string()]
    );
}
