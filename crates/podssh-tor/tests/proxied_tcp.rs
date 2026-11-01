//! The Tor road's TCP provider (T-353) against a stand-in proxy on the
//! loopback: each relay is asked of the proxy by its address, a refusal is
//! the connection's error, and the provider listens on nothing.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;

use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use podssh_tor::runtime::ProxiedTcp;
use podssh_ws::dial::ProxyChoice;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tor_rtcompat::{NetStreamProvider as _, TcpConnectOptions, TcpListenOptions};

/// A relay's address goes to the proxy as it is, an IP literal and its
/// port, and the bytes then pass both ways.
#[tokio::test]
async fn each_relay_is_asked_of_the_proxy_by_its_address() {
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = proxy.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
        let mut ping = [0u8; 4];
        s.read_exact(&mut ping).await.unwrap();
        s.write_all(b"pong").await.unwrap();
        (String::from_utf8(head).unwrap(), ping)
    });
    let choice = ProxyChoice::Via(podssh_ws::proxy::Proxy::parse(&format!("http://{at}")).unwrap());
    let tcp = ProxiedTcp::new(choice, Duration::from_secs(10));
    let relay: SocketAddr = "198.51.100.7:443".parse().unwrap();
    let mut stream = tcp.connect(&relay, &TcpConnectOptions::default()).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut answer = [0u8; 4];
    stream.read_exact(&mut answer).await.unwrap();
    let (head, ping) = server.await.unwrap();
    assert!(head.starts_with("CONNECT 198.51.100.7:443 HTTP/1.1\r\n"), "{head}");
    assert_eq!((&ping, &answer), (b"ping", b"pong"));
}

/// A refusal of the proxy is the connection's error, with its words.
#[tokio::test]
async fn a_refusal_of_the_proxy_is_an_error_of_the_connection() {
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = proxy.accept().await.unwrap();
        let mut buf = [0u8; 512];
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
    });
    let choice = ProxyChoice::Via(podssh_ws::proxy::Proxy::parse(&format!("http://{at}")).unwrap());
    let tcp = ProxiedTcp::new(choice, Duration::from_secs(10));
    let relay: SocketAddr = "198.51.100.7:9001".parse().unwrap();
    let err = tcp.connect(&relay, &TcpConnectOptions::default()).await.err().expect("a refusal");
    assert!(err.to_string().contains("403"), "{err}");
}

/// The road listens on nothing.
#[tokio::test]
async fn it_listens_on_nothing() {
    let tcp = ProxiedTcp::new(ProxyChoice::Direct, Duration::from_secs(1));
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let err = tcp.listen(&any, &TcpListenOptions::default()).await.err().expect("no listener");
    assert_eq!(err.kind(), ErrorKind::Unsupported);
}
