//! A stand-in of outline-ss-server's listener `websocket-stream` (T-493),
//! behind the test's TLS proxy as Caddy is in front of the real one: a
//! WebSocket on a secret path whose binary messages are the Shadowsocks
//! stream of TCP, as the Outline SDK's `gorillaConn` reads and writes them.
//! Another path gets 404, a path under `/forbidden` a 403 as a front that
//! refuses the upgrade answers; a text message ends the stream, as
//! `gorillaConn` refuses one, and so does a chunk that the key does not
//! open, as a server that cannot read a stream closes it. The real server
//! is the interop's (`scripts/interop-outline.sh`).

use std::sync::Arc;

use podssh_ws::shadowsocks::{self, Decoder, Encoder, Method, MAX_PAYLOAD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cloud_support::{self, Stream};

/// The stand-in's key and path.
#[derive(Debug, Clone)]
pub struct Outline {
    pub path: String,
    pub method: Method,
    pub password: String,
}

/// Each text message and each stream that a key did not open, counted.
#[derive(Debug, Default)]
pub struct Seen {
    pub streams: std::sync::atomic::AtomicUsize,
    pub texts: std::sync::atomic::AtomicUsize,
    pub unopened: std::sync::atomic::AtomicUsize,
}

/// Serve the upgrade of `head` on `stream`.
pub async fn serve(head: &str, mut stream: Stream, outline: &Outline, seen: Arc<Seen>) {
    use std::sync::atomic::Ordering::SeqCst;
    let path = head.split_whitespace().nth(1).unwrap_or_default().to_string();
    if path.starts_with("/forbidden") {
        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        return;
    }
    if path != outline.path {
        let answer = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
        let _ = stream.write_all(answer).await;
        return;
    }
    cloud_support::accept_upgrade(&mut stream, head, None).await;
    seen.streams.fetch_add(1, SeqCst);
    let session = Arc::new(podssh_ws::server::session(stream, Vec::new(), None));
    let master = shadowsocks::master_key(outline.password.as_bytes(), outline.method.key_len());
    let mut decoder = Decoder::new(outline.method, &master);
    // The target's address, from the first chunks of the stream.
    let mut plain = Vec::new();
    let (port, used) = loop {
        match next(&session, &mut decoder, &seen).await {
            Some(bytes) => plain.extend_from_slice(&bytes),
            None => return,
        }
        if let Some((_host, port, used)) = shadowsocks::parse_address(&plain) {
            break (port, used);
        }
    };
    let Ok(target) = TcpStream::connect(("127.0.0.1", port)).await else { return };
    let (mut from_target, mut to_target) = target.into_split();
    if to_target.write_all(&plain[used..]).await.is_err() {
        return;
    }
    let (down_session, method) = (session.clone(), outline.method);
    let down = tokio::spawn(async move {
        let mut encoder = Encoder::new(method, &master).unwrap();
        let mut buf = vec![0u8; MAX_PAYLOAD];
        while let Ok(n) = from_target.read(&mut buf).await {
            if n == 0 {
                break;
            }
            let mut out = Vec::new();
            encoder.seal(&buf[..n], &mut out).unwrap();
            if down_session.send_binary(&out).await.is_err() {
                return;
            }
        }
        let _ = down_session.send_close(1000, "").await;
    });
    while let Some(bytes) = next(&session, &mut decoder, &seen).await {
        if to_target.write_all(&bytes).await.is_err() {
            break;
        }
    }
    // The client's end of its bytes is the target's end of its input.
    let _ = to_target.shutdown().await;
    let _ = down.await;
}

/// The plaintext of the next binary messages, once a chunk opened; `None`
/// at the client's end, at a text message, or at a chunk that the key does
/// not open, each of which closes the WebSocket.
async fn next(session: &podssh_ws::RelaySession<Stream>, decoder: &mut Decoder, seen: &Seen) -> Option<Vec<u8>> {
    use std::sync::atomic::Ordering::SeqCst;
    loop {
        match decoder.chunk() {
            Ok(Some(bytes)) => return Some(bytes),
            Ok(None) => {}
            Err(_) => {
                seen.unopened.fetch_add(1, SeqCst);
                let _ = session.send_close(1000, "").await;
                return None;
            }
        }
        let frame = session.read_frame().await.ok()?;
        match frame.opcode {
            2 | 0 => decoder.feed(&frame.payload),
            1 => {
                seen.texts.fetch_add(1, SeqCst);
                let _ = session.send_close(1003, "binary messages only").await;
                return None;
            }
            8 => return None,
            _ => {}
        }
    }
}
