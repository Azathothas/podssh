//! The stand-ins of the tests of the iroh road: a relay server on the
//! loopback, under a name that only the stand-in proxy resolves, so that a
//! connection that does not go through the proxy finds no relay at all.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iroh::RelayUrl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The relay's name, which no resolver knows: `.test` is reserved.
pub const RELAY_NAME: &str = "relay.podssh.test";
pub const LIMIT: Duration = Duration::from_secs(60);

/// A relay server on the loopback, with no QUIC, and its URL under
/// [`RELAY_NAME`]. The relay stops when the server is dropped.
pub async fn relay() -> (RelayUrl, impl Sized) {
    let (_, url, server) = iroh::test_utils::run_relay_server_with(false).await.expect("a relay on the loopback");
    let port = url.port().expect("the relay's port");
    let named: RelayUrl = format!("https://{RELAY_NAME}:{port}").parse().expect("a relay URL");
    (named, server)
}

/// A stand-in CONNECT proxy, as a sandbox's: `CONNECT relay.podssh.test:PORT`
/// opens a tunnel to the relay on the loopback; anything else gets 403. The
/// count of tunnels.
pub async fn proxy(relay_port: u16) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let addr = listener.local_addr().unwrap();
    let tunnels = Arc::new(AtomicUsize::new(0));
    let counted = tunnels.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let counted = counted.clone();
            tokio::spawn(async move {
                let _ = tunnel(client, relay_port, &counted).await;
            });
        }
    });
    (addr, tunnels)
}

async fn tunnel(mut client: TcpStream, relay_port: u16, tunnels: &AtomicUsize) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        if client.read(&mut byte).await? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let line = head.lines().next().unwrap_or_default().to_string();
    if line != format!("CONNECT {RELAY_NAME}:{relay_port} HTTP/1.1") {
        client.write_all(b"HTTP/1.1 403 not on the egress allowlist\r\nContent-Length: 0\r\n\r\n").await?;
        return Ok(());
    }
    let mut relay = TcpStream::connect(("127.0.0.1", relay_port)).await?;
    tunnels.fetch_add(1, Ordering::SeqCst);
    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
    Ok(())
}
