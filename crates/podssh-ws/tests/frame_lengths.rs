//! RFC 6455 section 5.2 for received frames: "the minimal number of bytes
//! MUST be used to encode the length", so the 16-bit form holds 126 to 65535
//! and the 64-bit form 65536 and more. The frames are bytes written from the
//! RFC, not made by podssh's encoder, in both directions: the rule holds for a
//! server's frames and for a client's.

use std::time::Duration;

use podssh_ws::frame::{self, decode, Frame, Role, FORWARD_MAX_FRAME};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// FIN and the opcode of a binary frame.
const FIN_BINARY: u8 = 0x80 | frame::OPCODE_BINARY;

/// The masking key of RFC 6455 section 5.7's examples.
const KEY: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

/// The header of a binary frame of `len` bytes from `role`'s side, with the
/// length in the form that `marker` names: the mask bit and the key for a
/// client's frame, neither for a server's.
fn header(role: Role, marker: u8, len: u64) -> Vec<u8> {
    let mask = if role == Role::Client { 0x80 } else { 0x00 };
    let mut bytes = vec![FIN_BINARY, mask | marker];
    match marker {
        frame::LENGTH_16_MARKER => bytes.extend_from_slice(&u16::try_from(len).expect("a 16-bit length").to_be_bytes()),
        frame::LENGTH_64_MARKER => bytes.extend_from_slice(&len.to_be_bytes()),
        _ => panic!("{marker} is not a marker of a longer length"),
    }
    if role == Role::Client {
        bytes.extend_from_slice(&KEY);
    }
    bytes
}

/// The header and `len` bytes of payload.
fn whole(role: Role, marker: u8, len: u64) -> Vec<u8> {
    let mut bytes = header(role, marker, len);
    bytes.extend(std::iter::repeat_n(b'x', usize::try_from(len).expect("a length that fits")));
    bytes
}

/// The decoder refuses `bytes`, and names the rule.
fn refused(role: Role, bytes: &[u8]) {
    let error = decode(bytes, role).expect_err("a length that is not in the minimal form was accepted");
    let text = error.to_string();
    assert!(text.contains("RFC 6455 5.2") && text.contains("minimal"), "{role:?}: {text}");
}

/// The decoder reads the whole frame, and takes each of its bytes.
fn accepted(role: Role, marker: u8, len: u64) {
    let bytes = whole(role, marker, len);
    let (got, used) = decode(&bytes, role).expect("a length in the minimal form").expect("a whole frame");
    let want = (frame::OPCODE_BINARY, len, bytes.len());
    assert_eq!((got.opcode, got.payload.len() as u64, used), want, "{role:?} {len}");
}

/// The marker 126 with a length that the 7 bits hold: 125, and 1 and 0. Each
/// is refused from its header, so nothing waits for a payload that it will
/// refuse.
#[test]
fn a_16_bit_length_below_126_is_refused() {
    for role in [Role::Server, Role::Client] {
        for len in [125, 1, 0] {
            refused(role, &whole(role, frame::LENGTH_16_MARKER, len));
            refused(role, &header(role, frame::LENGTH_16_MARKER, len));
        }
    }
}

/// The marker 127 with a length that 16 bits or 7 hold: 65535, 126, 125 and 0.
#[test]
fn a_64_bit_length_below_65536_is_refused() {
    for role in [Role::Server, Role::Client] {
        for len in [65_535, 126, 125, 0] {
            refused(role, &whole(role, frame::LENGTH_64_MARKER, len));
            refused(role, &header(role, frame::LENGTH_64_MARKER, len));
        }
    }
}

/// The controls: the marker 126 with 126 and with 65535.
#[test]
fn the_16_bit_form_from_126_is_accepted() {
    for role in [Role::Server, Role::Client] {
        for len in [126, 65_535] {
            accepted(role, frame::LENGTH_16_MARKER, len);
        }
    }
}

/// The controls: the marker 127 with 65536, and with the relay's forward cap.
#[test]
fn the_64_bit_form_from_65536_is_accepted() {
    for role in [Role::Server, Role::Client] {
        for len in [65_536, FORWARD_MAX_FRAME as u64] {
            accepted(role, frame::LENGTH_64_MARKER, len);
        }
    }
}

/// The next frame that podssh wrote.
async fn from_client(peer: &mut DuplexStream, buf: &mut Vec<u8>) -> Frame {
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

/// From the relay, such a frame ends the read with an error, and podssh fails
/// the connection with a Close 1002, a protocol error (RFC 6455 sections 7.1.7
/// and 7.4.1). The same payload in the minimal form, sent first, is read.
#[tokio::test]
async fn a_length_not_in_the_minimal_form_fails_the_connection_with_1002() {
    for marker in [frame::LENGTH_16_MARKER, frame::LENGTH_64_MARKER] {
        let (client, mut peer) = tokio::io::duplex(64 * 1024);
        let session = RelaySession::new(client, Vec::new(), None, Duration::from_secs(5));
        let mut bytes = vec![FIN_BINARY, 5];
        bytes.extend_from_slice(b"hello");
        bytes.extend_from_slice(&header(Role::Server, marker, 5));
        bytes.extend_from_slice(b"hello");
        peer.write_all(&bytes).await.unwrap();
        let good = tokio::time::timeout(Duration::from_secs(5), session.read_frame())
            .await
            .expect("the first frame")
            .expect("a frame in the minimal form is read");
        assert_eq!(good.payload, b"hello");
        let error = tokio::time::timeout(Duration::from_secs(5), session.read_frame())
            .await
            .expect("the read ends")
            .expect_err("a length that is not in the minimal form is an error");
        assert!(matches!(error, podssh_ws::SessionError::Protocol(_)), "{marker}: {error:?}");
        assert!(error.to_string().contains("RFC 6455 5.2"), "{marker}: {error}");
        let mut buf = Vec::new();
        let sent = from_client(&mut peer, &mut buf).await;
        assert_eq!(
            (sent.opcode, close_code_and_reason(&sent.payload).0),
            (frame::OPCODE_CLOSE, Some(1002)),
            "{marker}"
        );
    }
}
