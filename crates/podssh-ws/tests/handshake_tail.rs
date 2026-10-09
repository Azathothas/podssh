//! **The bytes that arrive behind the `101`, and the Pong a Ping requires.**
//!
//! The relay dials the target *before* the upgrade, so the target's first
//! bytes can share a TCP segment with the response headers, and one `read` can
//! carry any number of frames. Both cases were once discarded: `read_response`
//! returned `Result<(), _>` and the reader kept its buffer in a local. A frame
//! parser that starts mid-frame decodes garbage forever after, and nothing in
//! the tree noticed — the bytes were already off the socket and there was no
//! second copy to compare against.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use podssh_ws::client::{next_event, read_frame_over, Event, DEFAULT_TIMEOUT};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::handshake::{self, accept_key, read_response};

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

fn response_for(key: &str) -> String {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(key)
    )
}

/// A server frame, unmasked, so it is exactly what the relay writes.
fn server_frame(payload: &[u8]) -> Vec<u8> {
    frame::encode(&Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: payload.to_vec() }, Role::Server, [0; 4])
}

/// **A stream whose reads are scripted, and which records its writes.** When
/// `tail` is set the reads are built from the request the caller wrote, because
/// the 101's `Sec-WebSocket-Accept` depends on a key this side generates and a
/// canned response cannot carry it.
struct Scripted {
    chunks: Vec<Vec<u8>>,
    written: Vec<u8>,
    tail: Option<Vec<u8>>,
}

impl Scripted {
    fn chunks(chunks: Vec<Vec<u8>>) -> Self {
        Self { chunks, written: Vec::new(), tail: None }
    }

    fn answering(tail: Vec<u8>) -> Self {
        Self { chunks: Vec::new(), written: Vec::new(), tail: Some(tail) }
    }

    fn key_from_request(&self) -> String {
        let text = String::from_utf8_lossy(&self.written).to_string();
        text.split("\r\n")
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .expect("the request carries the key")
            .to_string()
    }
}

impl AsyncRead for Scripted {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.chunks.is_empty() {
            if let Some(tail) = me.tail.take() {
                let mut chunk = response_for(&me.key_from_request()).into_bytes();
                chunk.extend_from_slice(&tail);
                me.chunks.push(chunk);
            }
        }
        if me.chunks.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let chunk = me.chunks.remove(0);
        buf.put_slice(&chunk);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Scripted {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().written.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ── the `101` and the first frame in one read ───────────────────────────────

#[tokio::test]
async fn a_frame_coalesced_with_the_101_is_returned_and_not_dropped() {
    let first = server_frame(b"first");
    let mut head = response_for(KEY).into_bytes();
    head.extend_from_slice(&first);
    let mut stream = Scripted::chunks(vec![head]);

    let tail = read_response(&mut stream, KEY).await.expect("a valid 101");

    assert_eq!(tail, first, "the frame behind the header terminator is the caller's");
    let (decoded, used) = frame::decode(&tail, Role::Server).expect("it is a whole frame").expect("and it is complete");
    assert_eq!(decoded.payload, b"first");
    assert_eq!(used, tail.len(), "nothing is left over here");
}

#[tokio::test]
async fn a_frame_split_across_reads_is_assembled_without_loss() {
    // The header arrives in two reads and the frame starts in the second,
    // which is the shape a small MTU produces.
    let text = response_for(KEY);
    let (one, two) = text.split_at(40);
    let mut second = two.as_bytes().to_vec();
    second.extend_from_slice(&server_frame(b"split"));
    let mut stream = Scripted::chunks(vec![one.as_bytes().to_vec(), second]);

    let tail = read_response(&mut stream, KEY).await.expect("a valid 101");

    assert_eq!(tail, server_frame(b"split"));
}

#[tokio::test]
async fn a_101_with_nothing_behind_it_yields_no_tail() {
    let mut stream = Scripted::chunks(vec![response_for(KEY).into_bytes()]);
    let tail = read_response(&mut stream, KEY).await.expect("a valid 101");
    assert!(tail.is_empty(), "an empty tail is not an error");
}

#[tokio::test]
async fn the_handshake_hands_the_tail_to_its_caller() {
    // The real entry point, with the real request: the tail has to survive
    // `handshake` as well as `read_response`, or `connect` has nothing to store.
    let mut stream = Scripted::answering(server_frame(b"behind"));
    let (_, tail) =
        handshake::handshake(&mut stream, "relay.example:443", "/connect/h/p", "tok").await.expect("a valid 101");
    assert_eq!(tail, server_frame(b"behind"));
}

// ── what the reader does with the buffer, and with a Ping ───────────────────

#[test]
fn the_buffer_keeps_the_frames_after_the_one_returned() {
    // Two complete frames in one buffer, the case a single `read` produces.
    // A reader that drains its buffer on return loses the second frame for
    // good — it was already off the socket.
    let mut buf = server_frame(b"one");
    buf.extend_from_slice(&server_frame(b"two"));

    let Some(Event::Frame(one)) = next_event(&mut buf).expect("a decodable frame") else {
        panic!("a binary frame is an Event::Frame");
    };
    assert_eq!(one.payload, b"one");
    assert_eq!(buf, server_frame(b"two"), "the second frame is still in the buffer");

    let Some(Event::Frame(two)) = next_event(&mut buf).expect("a decodable frame") else {
        panic!("a binary frame is an Event::Frame");
    };
    assert_eq!(two.payload, b"two");
    assert!(buf.is_empty());
    assert_eq!(next_event(&mut buf).expect("an empty buffer is not an error"), None);
}

#[test]
fn a_ping_becomes_a_pong_that_echoes_its_payload() {
    // RFC 6455 §5.5.2: an endpoint MUST answer a Ping with a Pong carrying
    // the same application data. A Ping surfaced as data would be read as
    // protocol bytes, and one surfaced as an error killed the session:
    // `TransportError::Unexpected` is `Retry::Never`.
    let ping = frame::encode(
        &Frame { fin: true, opcode: frame::OPCODE_PING, payload: b"keepalive".to_vec() },
        Role::Server,
        [0; 4],
    );
    let mut buf = ping;
    buf.extend_from_slice(&server_frame(b"after"));

    assert_eq!(next_event(&mut buf).expect("a decodable ping"), Some(Event::Pong(b"keepalive".to_vec())));
    let Some(Event::Frame(frame)) = next_event(&mut buf).expect("the data still follows") else {
        panic!("the frame after a Ping must still arrive");
    };
    assert_eq!(frame.payload, b"after");
}

// ── the Pong the loop actually writes ───────────────────────────────────────

/// **The Pong is a write, and a write is bytes.** `next_event` above stops
/// at the decision; this drives `read_frame_over`, the loop
/// `RelaySession::read_frame` runs, with a stream whose writes are recorded.
#[tokio::test]
async fn read_frame_answers_a_ping_with_a_masked_pong() {
    let mut bytes = frame::encode(
        &Frame { fin: true, opcode: frame::OPCODE_PING, payload: b"keepalive".to_vec() },
        Role::Server,
        [0; 4],
    );
    bytes.extend_from_slice(&server_frame(b"after"));
    let mut stream = Scripted::chunks(vec![bytes]);

    let mut pending = Vec::new();
    let mut close_received = false;
    let frame = read_frame_over(&mut stream, &mut pending, &mut close_received, DEFAULT_TIMEOUT)
        .await
        .expect("the data frame follows the Ping");
    assert_eq!(frame.payload, b"after");

    // `Role::Client` here is the mask check: the decoder refuses an unmasked
    // client frame, so a Pong written without §5.3's mask cannot pass.
    let (pong, used) = frame::decode(&stream.written, Role::Client)
        .expect("the recorded write is a well-formed client frame")
        .expect("and it is whole");
    assert_eq!(used, stream.written.len(), "the Pong is all that was written");
    assert_eq!(pong.opcode, frame::OPCODE_PONG);
    assert_eq!(pong.payload, b"keepalive", "§5.5.3: the payload comes back");
}

/// §5.5 caps a control frame at 125 bytes, so a 126-byte Ping is the
/// peer's violation and answering it would put podssh on the wrong side of
/// the same rule. The decoder refuses it: the read fails, and the only frame
/// written is a Close 1002 (§7.1.7), never a Pong.
#[tokio::test]
async fn read_frame_refuses_an_oversized_ping_with_a_close_1002() {
    let bytes =
        frame::encode(&Frame { fin: true, opcode: frame::OPCODE_PING, payload: vec![0x5a; 126] }, Role::Server, [0; 4]);
    let mut stream = Scripted::chunks(vec![bytes]);
    let mut pending = Vec::new();
    let mut close_received = false;
    let error = read_frame_over(&mut stream, &mut pending, &mut close_received, DEFAULT_TIMEOUT)
        .await
        .expect_err("a Ping of 126 bytes is refused");
    assert!(error.contains("RFC 6455 5.5"), "{error}");
    let (sent, used) = frame::decode(&stream.written, Role::Client).unwrap().expect("one frame was written");
    assert_eq!(used, stream.written.len(), "one frame only: {:02x?}", stream.written);
    assert_eq!(sent.opcode, frame::OPCODE_CLOSE);
    assert_eq!(sent.payload, 1002u16.to_be_bytes());
}

/// §5.5.2's MUST is excused once a Close has been received, so a later
/// Ping is not answered.
#[tokio::test]
async fn read_frame_does_not_answer_a_ping_after_a_close() {
    let mut bytes =
        frame::encode(&Frame { fin: true, opcode: frame::OPCODE_CLOSE, payload: Vec::new() }, Role::Server, [0; 4]);
    bytes.extend_from_slice(&frame::encode(
        &Frame { fin: true, opcode: frame::OPCODE_PING, payload: b"again".to_vec() },
        Role::Server,
        [0; 4],
    ));
    bytes.extend_from_slice(&server_frame(b"after"));
    let mut stream = Scripted::chunks(vec![bytes]);

    let mut pending = Vec::new();
    let mut close_received = false;
    let close = read_frame_over(&mut stream, &mut pending, &mut close_received, DEFAULT_TIMEOUT)
        .await
        .expect("the Close is returned to the caller");
    assert_eq!(close.opcode, frame::OPCODE_CLOSE);
    assert!(close_received, "the Close is the state the loop records");

    let frame = read_frame_over(&mut stream, &mut pending, &mut close_received, DEFAULT_TIMEOUT)
        .await
        .expect("the data frame still arrives");
    assert_eq!(frame.payload, b"after");
    assert!(stream.written.is_empty(), "a Ping after a Close may not be answered: {:02x?}", stream.written);
}
