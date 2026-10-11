//! The bounds of the connection to the relay (T-201), each against a peer
//! that does not stop at it: what podssh reads, and how the read ends. Each
//! peer is in this process: an in-memory stream, or a listener on the
//! loopback for the proxy.

use std::time::Duration;

use podssh_ws::client::{self, ConnectError};
use podssh_ws::dial::{dial, DialError, HttpProxy, ProxyChoice};
use podssh_ws::frame::{self, Frame, Role, FORWARD_MAX_FRAME};
use podssh_ws::http;
use podssh_ws::session::{close_code_and_reason, RelaySession, MAX_MESSAGE};
use podssh_ws::SessionError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

/// How long each read may take.
const LIMIT: Duration = Duration::from_secs(30);
/// The bound of a response head: of the upgrade, of HTTP, of the proxy.
const HEAD: usize = 16 * 1024;
/// What a peer offers past a bound: far more than any bound here.
const ENDLESS: usize = 1 << 20;

/// Write `start`, then header lines and never the blank line, until the
/// reader goes or [`ENDLESS`] bytes went: the bytes written.
async fn endless_head<S: AsyncWrite + Unpin>(peer: &mut S, start: &[u8]) -> usize {
    let line = format!("X-Pad: {}\r\n", "a".repeat(100));
    let mut sent = 0;
    if peer.write_all(start).await.is_err() {
        return sent;
    }
    sent += start.len();
    while sent < ENDLESS {
        if peer.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        sent += line.len();
    }
    sent
}

/// Read the request's head, to its blank line.
async fn request_head<S: AsyncRead + Unpin>(peer: &mut S) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match peer.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
}

#[tokio::test]
async fn an_upgrade_head_that_never_ends_stops_at_16_kib() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let relay = tokio::spawn(async move {
        request_head(&mut peer).await;
        endless_head(&mut peer, b"HTTP/1.1 101 Switching Protocols\r\n").await
    });
    let upgrade = client::upgrade(client, "relay.test", "/connect/127.0.0.1/22", "token");
    match tokio::time::timeout(LIMIT, upgrade).await.expect("the upgrade ends") {
        Err(ConnectError::Upgrade(why)) => assert!(why.contains("within 16 KiB"), "{why}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
    // podssh read the bound and one read more; the stream held the rest.
    let sent = relay.await.unwrap();
    assert!(sent < HEAD + 8 * 1024, "the relay wrote {sent} bytes before podssh stopped reading");
}

#[tokio::test]
async fn an_http_head_that_never_ends_stops_at_16_kib() {
    let (mut client, mut peer) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move { endless_head(&mut peer, b"HTTP/1.1 200 OK\r\n").await });
    let read = http::read_response(&mut client, Vec::new(), 1024);
    let err = tokio::time::timeout(LIMIT, read).await.expect("the read ends").unwrap_err();
    assert!(err.to_string().contains("no end of the response headers within 16 KiB"), "{err}");
    drop(client);
    let sent = server.await.unwrap();
    assert!(sent < HEAD + 8 * 1024, "the server wrote {sent} bytes before podssh stopped reading");
}

/// A body of `max` bytes is read and one of `max + 1` is refused, in each of
/// the three framings of HTTP/1.1: a length, chunks, and the close.
#[tokio::test]
async fn a_body_past_its_bound_is_refused_in_each_framing() {
    const MAX: usize = 1000;
    let length = |n: usize| format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n{}", "b".repeat(n));
    let chunked = |n: usize| {
        let half = n / 2;
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{half:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            "b".repeat(half),
            n - half,
            "b".repeat(n - half)
        )
    };
    let until_close = |n: usize| format!("HTTP/1.1 200 OK\r\n\r\n{}", "b".repeat(n));
    let framings: [(&str, &dyn Fn(usize) -> String); 3] =
        [("a length", &length), ("chunks", &chunked), ("the close", &until_close)];
    for (framing, response) in framings {
        for (n, fits) in [(MAX, true), (MAX + 1, false)] {
            let (mut client, mut peer) = tokio::io::duplex(64 * 1024);
            let text = response(n);
            let server = tokio::spawn(async move {
                let _ = peer.write_all(text.as_bytes()).await;
                // The close ends the third framing.
                drop(peer);
            });
            let read = tokio::time::timeout(LIMIT, http::read_response(&mut client, Vec::new(), MAX)).await;
            server.await.unwrap();
            match (read.expect("the read ends"), fits) {
                (Ok(r), true) => assert_eq!(r.body.len(), MAX, "{framing}"),
                (Err(e), false) => assert!(e.to_string().contains("larger than allowed"), "{framing}: {e}"),
                (Ok(r), false) => panic!("{framing}: a body of {} bytes passed a bound of {MAX}", r.body.len()),
                (Err(e), true) => panic!("{framing}: a body of {MAX} bytes was refused: {e}"),
            }
        }
    }
}

#[tokio::test]
async fn a_proxy_answer_that_never_ends_stops_at_16_kib() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let proxy = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        request_head(&mut sock).await;
        endless_head(&mut sock, b"HTTP/1.1 200 Connection established\r\n").await
    });
    let via = HttpProxy::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let err = dial("relay.invalid", 443, &ProxyChoice::Via(via), LIMIT).await.unwrap_err();
    assert!(matches!(err, DialError::ProxyProtocol { .. }), "{err:?}");
    assert!(err.to_string().contains("no end of headers within 16384 bytes"), "{err}");
    proxy.abort();
}

/// A frame as the relay sends it: unmasked.
fn from_relay(opcode: u8, fin: bool, payload: Vec<u8>) -> Vec<u8> {
    frame::encode(&Frame { fin, opcode, payload }, Role::Server, [0; 4])
}

/// The next frame that podssh wrote.
async fn from_podssh(peer: &mut DuplexStream) -> Frame {
    let mut buf = Vec::new();
    loop {
        if let Some((f, _)) = frame::decode(&buf, Role::Client).expect("a valid frame from podssh") {
            return f;
        }
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(LIMIT, peer.read(&mut chunk)).await.expect("a frame from podssh").unwrap();
        assert!(n > 0, "podssh closed the stream with no Close");
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn session(stream: DuplexStream) -> RelaySession<DuplexStream> {
    RelaySession::new(stream, Vec::new(), None, Duration::from_secs(5))
}

/// A frame of the cap is read; a frame one byte longer ends the session by
/// its header alone, before a byte of its payload, with a Close 1002.
#[tokio::test]
async fn a_frame_past_the_forward_cap_ends_the_session_with_1002() {
    let (stream, mut peer) = tokio::io::duplex(64 * 1024);
    let s = session(stream);
    let at_cap = from_relay(frame::OPCODE_BINARY, true, vec![7; FORWARD_MAX_FRAME]);
    let writer = tokio::spawn(async move {
        peer.write_all(&at_cap).await.unwrap();
        peer
    });
    let got = tokio::time::timeout(LIMIT, s.read_frame()).await.expect("the frame").unwrap();
    assert_eq!(got.payload.len(), FORWARD_MAX_FRAME);
    let mut peer = writer.await.unwrap();

    let mut head = vec![0x80 | frame::OPCODE_BINARY, 127];
    head.extend_from_slice(&(FORWARD_MAX_FRAME as u64 + 1).to_be_bytes());
    peer.write_all(&head).await.unwrap();
    match tokio::time::timeout(LIMIT, s.read_frame()).await.expect("the read ends") {
        Err(SessionError::Protocol(why)) => assert!(why.contains("exceeds the forward cap of 262144"), "{why}"),
        other => panic!("{other:?}"),
    }
    let close = from_podssh(&mut peer).await;
    assert_eq!((close.opcode, close_code_and_reason(&close.payload).0), (frame::OPCODE_CLOSE, Some(1002)));
}

/// The relay's frames for one message of `fragments` frames of the cap and
/// then `tail` bytes, if any: the last frame ends the message.
fn fragmented(fragments: usize, tail: usize) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for i in 0..fragments {
        let opcode = if i == 0 { frame::OPCODE_BINARY } else { frame::OPCODE_CONTINUATION };
        let fin = tail == 0 && i + 1 == fragments;
        frames.push(from_relay(opcode, fin, vec![1; FORWARD_MAX_FRAME]));
    }
    if tail > 0 {
        frames.push(from_relay(frame::OPCODE_CONTINUATION, true, vec![2; tail]));
    }
    frames
}

/// A message of 16 MiB in fragments is read whole; with one byte more the
/// session ends with a Close 1009, and that byte never joins the message.
#[tokio::test]
async fn fragments_past_16_mib_end_the_session_with_1009() {
    let fragments = MAX_MESSAGE / FORWARD_MAX_FRAME;
    assert_eq!(fragments * FORWARD_MAX_FRAME, MAX_MESSAGE);
    let (stream, mut peer) = tokio::io::duplex(64 * 1024);
    let s = session(stream);
    let writer = tokio::spawn(async move {
        for f in fragmented(fragments, 0).into_iter().chain(fragmented(fragments, 1)) {
            peer.write_all(&f).await.unwrap();
        }
        peer
    });
    let whole = tokio::time::timeout(LIMIT, s.read_frame()).await.expect("the message").unwrap();
    assert_eq!(whole.payload.len(), MAX_MESSAGE);
    drop(whole);
    match tokio::time::timeout(LIMIT, s.read_frame()).await.expect("the read ends") {
        Err(SessionError::TooLarge(why)) => assert!(why.contains("exceeded 16777216 bytes"), "{why}"),
        other => panic!("{:?}", other.map(|f| f.payload.len())),
    }
    let mut peer = writer.await.unwrap();
    let close = from_podssh(&mut peer).await;
    assert_eq!((close.opcode, close_code_and_reason(&close.payload).0), (frame::OPCODE_CLOSE, Some(1009)));
}
