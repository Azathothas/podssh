//! A plain `ws://` session to the loopback (feature `plain-ws`, T-068): the
//! upgrade and data in both directions, against a listener that answers with
//! the bytes of `scripts/fake-relay.py`; and the refusal of each host that is
//! not the loopback, with no connection attempt.
#![cfg(feature = "plain-ws")]

use std::time::{Duration, Instant};

use podssh_ws::client::ConnectError;
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::plain::connect_loopback;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN: &str = "TESTONLYNOTACREDENTIAL";

/// One upgrade on 127.0.0.1: the 101 that `scripts/fake-relay.py` writes, a
/// binary frame `hello`, then the client's first frame, returned.
async fn relay() -> (u16, tokio::task::JoinHandle<(String, Frame)>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("an address").port();
    let task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.expect("accept");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tcp.read_exact(&mut byte).await.expect("a request");
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).expect("text");
        let key = head
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .expect("a key")
            .trim()
            .to_string();
        let accept = podssh_ws::handshake::accept_key(&key);
        let answer = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        tcp.write_all(answer.as_bytes()).await.unwrap();
        let hello = frame::encode(&Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: b"hello".to_vec() }, Role::Server, [0; 4]);
        tcp.write_all(&hello).await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if let Some((f, _)) = frame::decode(&buf, Role::Client).expect("a valid client frame") {
                return (head, f);
            }
            let n = tcp.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the client closed");
            buf.extend_from_slice(&chunk[..n]);
        }
    });
    (port, task)
}

#[tokio::test]
async fn a_plain_session_to_the_loopback_carries_data_both_ways() {
    let (port, relay) = relay().await;
    let session = connect_loopback("127.0.0.1", port, "/connect/example.org/22", TOKEN, TIMEOUT, Some(TIMEOUT))
        .await
        .expect("the upgrade");
    let got = session.read_frame().await.expect("a frame");
    assert_eq!((got.opcode, got.payload.as_slice()), (frame::OPCODE_BINARY, &b"hello"[..]));
    session.send_binary(b"ping").await.expect("a send");
    let (head, sent) = tokio::time::timeout(TIMEOUT, relay).await.expect("in time").unwrap();
    assert_eq!((sent.opcode, sent.payload.as_slice()), (frame::OPCODE_BINARY, &b"ping"[..]));
    assert!(head.starts_with("GET /connect/example.org/22 HTTP/1.1\r\n"), "{head}");
    assert!(head.contains(&format!("X-Relay-Token: {TOKEN}\r\n")), "the token travels in its header");
}

/// A host that is not the loopback is refused before any connection: the
/// address of 192.0.2.1 would take the whole timeout, and the refusal is at
/// once.
#[tokio::test]
async fn a_host_that_is_not_the_loopback_is_refused_with_no_connection() {
    for host in ["192.0.2.1", "example.org", "10.0.0.1", "[2001:db8::1]", "0.0.0.0", "localhost.example"] {
        let started = Instant::now();
        let error = connect_loopback(host, 443, "/connect/example.org/22", TOKEN, Duration::from_secs(30), None)
            .await
            .expect_err(host);
        assert!(matches!(&error, ConnectError::Config(why) if why.contains("only to the loopback")), "{host}: {error}");
        assert!(started.elapsed() < Duration::from_secs(1), "{host}: a connection was tried");
    }
}
