//! RFC 6455 section 5.5 for received control frames: never fragmented, 125
//! bytes or less, and a Close of 0 bytes or of 2 and more. The frames are
//! bytes written from the RFC, not made by podssh's encoder. And section
//! 5.5.1 for sent ones: no data frame after this side's Close.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::frame::{self, decode, Frame, Role};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// A frame header from the server: no mask. `first` is FIN and the opcode.
fn header(first: u8, len: usize) -> Vec<u8> {
    match len {
        0..=125 => vec![first, len as u8],
        _ => vec![first, 126, (len >> 8) as u8, len as u8],
    }
}

fn whole(first: u8, len: usize) -> Vec<u8> {
    let mut bytes = header(first, len);
    bytes.extend(std::iter::repeat_n(b'x', len));
    bytes
}

const FIN: u8 = 0x80;

fn refused(bytes: &[u8]) {
    let error = decode(bytes, Role::Server).expect_err("accepted");
    assert!(error.to_string().contains("RFC 6455 5.5"), "{error}");
}

#[test]
fn a_ping_with_fin_clear_is_refused() {
    refused(&whole(frame::OPCODE_PING, 0));
}

#[test]
fn a_ping_of_126_bytes_is_refused_from_its_header() {
    refused(&whole(FIN | frame::OPCODE_PING, 126));
    // Nothing waits for 126 bytes that it will refuse.
    refused(&header(FIN | frame::OPCODE_PING, 126));
}

#[test]
fn a_close_of_126_bytes_is_refused() {
    refused(&whole(FIN | frame::OPCODE_CLOSE, 126));
}

#[test]
fn a_close_of_1_byte_is_refused() {
    refused(&[FIN | frame::OPCODE_CLOSE, 1, 0x03]);
}

#[test]
fn control_frames_of_0_and_125_bytes_are_accepted() {
    for opcode in [frame::OPCODE_PING, frame::OPCODE_PONG, frame::OPCODE_CLOSE] {
        for len in [0, 125] {
            let bytes = whole(FIN | opcode, len);
            let (got, used) = decode(&bytes, Role::Server).expect("valid").expect("whole");
            assert_eq!((got.opcode, got.payload.len(), used), (opcode, len, bytes.len()));
        }
    }
    let close = [FIN | frame::OPCODE_CLOSE, 2, 0x03, 0xe8];
    assert!(decode(&close, Role::Server).unwrap().is_some(), "a Close with a code alone");
}

async fn next_from_client(peer: &mut DuplexStream, buf: &mut Vec<u8>) -> Frame {
    loop {
        if let Some((f, used)) = decode(buf, Role::Client).expect("a valid client frame") {
            buf.drain(..used);
            return f;
        }
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut chunk))
            .await
            .expect("a client frame within 5 s")
            .unwrap();
        assert!(n > 0, "the client closed the stream");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A fragmented Ping gets no Pong: the read fails, and podssh fails the
/// connection with a Close 1002 (RFC 6455 section 7.1.7).
#[tokio::test]
async fn a_fragmented_ping_gets_no_pong_and_ends_the_read() {
    for bytes in [whole(frame::OPCODE_PING, 4), whole(FIN | frame::OPCODE_CLOSE, 126)] {
        let (client, mut peer) = tokio::io::duplex(64 * 1024);
        let session = Arc::new(RelaySession::new(client, Vec::new(), None, Duration::from_secs(5)));
        peer.write_all(&bytes).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), session.read_frame())
            .await
            .expect("the read ends")
            .expect_err("a forbidden control frame is an error");
        assert!(matches!(error, podssh_ws::SessionError::Protocol(_)), "{error:?}");
        assert!(error.to_string().contains("RFC 6455 5.5"), "{error}");
        let mut buf = Vec::new();
        let sent = next_from_client(&mut peer, &mut buf).await;
        assert_eq!(sent.opcode, frame::OPCODE_CLOSE, "a Pong or nothing was sent: {sent:?}");
        assert_eq!(close_code_and_reason(&sent.payload).0, Some(1002));
    }
}

/// A continuation with no message is a protocol error too: a Close 1002.
#[tokio::test]
async fn a_continuation_with_no_message_fails_the_connection_with_1002() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let session = Arc::new(RelaySession::new(client, Vec::new(), None, Duration::from_secs(5)));
    peer.write_all(&whole(FIN | frame::OPCODE_CONTINUATION, 3)).await.unwrap();
    assert!(session.read_frame().await.unwrap_err().to_string().contains("continuation"));
    let mut buf = Vec::new();
    let sent = next_from_client(&mut peer, &mut buf).await;
    assert_eq!((sent.opcode, close_code_and_reason(&sent.payload).0), (frame::OPCODE_CLOSE, Some(1002)));
}

/// RFC 6455 section 5.5.1: after its Close, an endpoint sends no data frame.
/// A send of data then fails, and the peer gets the Close alone.
#[tokio::test]
async fn no_data_frame_follows_this_sides_close() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let session = RelaySession::new(client, Vec::new(), None, Duration::from_secs(5));
    session.send_close(1000, "").await.unwrap();
    for sent in [session.send_binary(b"late").await, session.send_text("late").await] {
        let error = sent.expect_err("no data after the Close");
        assert!(matches!(error, podssh_ws::SessionError::Io { kind: std::io::ErrorKind::BrokenPipe, .. }), "{error:?}");
    }
    let mut buf = Vec::new();
    let first = next_from_client(&mut peer, &mut buf).await;
    assert_eq!((first.opcode, close_code_and_reason(&first.payload).0), (frame::OPCODE_CLOSE, Some(1000)));
    drop(session);
    let mut rest = Vec::new();
    peer.read_to_end(&mut rest).await.unwrap();
    assert!(buf.is_empty() && rest.is_empty(), "nothing after the Close");
}

/// The payload of a Close that the live relay sent (version 2026-10-03-r2),
/// captured on 2026-10-09 by `python scripts/capture-close.py`, a client of
/// the Python standard library: github.com:22 closed the connection after a
/// line that is not SSH. Bytes that podssh did not make.
const LIVE_CLOSE: &str = "03e874617267657420636c6f736564";

#[tokio::test]
async fn a_close_captured_from_the_live_relay_is_read_as_sent() {
    let payload: Vec<u8> =
        (0..LIVE_CLOSE.len()).step_by(2).map(|i| u8::from_str_radix(&LIVE_CLOSE[i..i + 2], 16).unwrap()).collect();
    assert_eq!(close_code_and_reason(&payload), (Some(1000), "target closed".to_string()));
    // Through a session too: the frame is read whole, and answered.
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let session = RelaySession::new(client, Vec::new(), None, Duration::from_secs(5));
    let mut bytes = vec![FIN | frame::OPCODE_CLOSE, payload.len() as u8];
    bytes.extend_from_slice(&payload);
    peer.write_all(&bytes).await.unwrap();
    let got = session.read_frame().await.expect("the Close");
    assert_eq!(
        (got.opcode, close_code_and_reason(&got.payload)),
        (frame::OPCODE_CLOSE, (Some(1000), "target closed".into()))
    );
}

/// A Close with no status code has none (callers read 1005, RFC 6455
/// section 7.1.5), and a reason loses its control characters before anyone
/// prints it.
#[test]
fn a_close_with_no_code_has_none_and_a_reason_loses_its_control_characters() {
    assert_eq!(close_code_and_reason(b""), (None, String::new()));
    let mut payload = 4000u16.to_be_bytes().to_vec();
    payload.extend_from_slice("bad\u{1b}[2J\u{7}news".as_bytes());
    assert_eq!(close_code_and_reason(&payload), (Some(4000), "bad[2Jnews".to_string()));
}
