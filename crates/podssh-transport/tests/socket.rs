//! ⛔ **The socket seam: keepalive frames must not kill a session, and a
//! refused frame must not be counted as sent.**
//!
//! ⛔ The relay's published keepalive is a frame every 25 s, so a client that
//! treated every non-data opcode as an error would lose a healthy session on a
//! timer. RFC 6455 §5.5.2 makes the answer to a Ping a MUST, and §5.5.3 makes
//! the Pong a control frame: neither is data and neither is a failure.
//!
//! ⛔ **The counter is asserted here because it is a guard.** `sent_frames`
//! exists so a test can prove a refused frame never reached the wire; a fake
//! answers it honestly and a real socket returned a constant `0`, which turned
//! the guard into `0 == 0`.

use std::collections::VecDeque;

use podssh_transport::control::{self, CONTROL_MAX};
use podssh_transport::socket::{
    Leg, Socket, WireFrame, WsFrame, WsSession, WsSocket, OPCODE_BINARY, OPCODE_PING, OPCODE_PONG,
    OPCODE_TEXT,
};
use podssh_transport::transport::{LegShape, Limits};
use podssh_transport::{CodecError, SessionId, TransportError};

mod common;
use common::block_on;

/// ⛔ **A session that is a list of frames in and a list of frames out.**
/// Each write is recorded with its opcode, so a test sees the frame type that
/// reached the wire and not only how many frames did.
#[derive(Default)]
struct FakeSession {
    inbound: VecDeque<WsFrame>,
    sent: Vec<(u8, Vec<u8>)>,
    fail: Option<String>,
    /// The next write fails with this, as a dropped socket would.
    refuse: Option<String>,
}

impl FakeSession {
    fn with(frames: Vec<WsFrame>) -> Self {
        Self { inbound: frames.into(), ..Self::default() }
    }

    fn frame(opcode: u8, payload: &[u8]) -> WsFrame {
        WsFrame { opcode, payload: payload.to_vec() }
    }

    fn record(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        if let Some(detail) = self.refuse.take() {
            return Err(detail);
        }
        self.sent.push((opcode, payload.to_vec()));
        Ok(())
    }
}

impl WsSession for FakeSession {
    async fn send(&mut self, payload: &[u8]) -> Result<(), String> {
        self.record(OPCODE_BINARY, payload)
    }

    async fn send_pong(&mut self, payload: &[u8]) -> Result<(), String> {
        self.record(OPCODE_PONG, payload)
    }

    async fn send_text(&mut self, text: &str) -> Result<(), String> {
        self.record(OPCODE_TEXT, text.as_bytes())
    }

    async fn read(&mut self) -> Result<WsFrame, String> {
        if let Some(detail) = self.fail.take() {
            return Err(detail);
        }
        self.inbound.pop_front().ok_or_else(|| "the session ended".to_string())
    }
}

fn socket(frames: Vec<WsFrame>) -> WsSocket<FakeSession> {
    WsSocket::new(FakeSession::with(frames), Limits::reverse_node())
}

#[test]
fn a_ping_is_answered_with_its_own_payload_and_the_read_continues() {
    let mut socket = socket(vec![
        FakeSession::frame(OPCODE_PING, b"keepalive"),
        FakeSession::frame(OPCODE_BINARY, b"data"),
    ]);

    let frame = block_on(socket.recv()).expect("a Ping is not a failure");

    assert_eq!(frame, WireFrame::Binary(b"data".to_vec()));
    assert_eq!(socket.session().sent, vec![(OPCODE_PONG, b"keepalive".to_vec())]);
}

#[test]
fn a_pong_is_skipped_and_not_delivered_as_data() {
    let mut socket = socket(vec![
        FakeSession::frame(OPCODE_PONG, b""),
        FakeSession::frame(OPCODE_BINARY, b"payload"),
    ]);

    let frame = block_on(socket.recv()).expect("a Pong is not a failure");
    assert_eq!(frame, WireFrame::Binary(b"payload".to_vec()));
    assert!(socket.session().sent.is_empty(), "a Pong is never answered");
}

#[test]
fn a_text_frame_still_arrives_as_text_on_the_node_leg() {
    let mut socket = socket(vec![FakeSession::frame(OPCODE_TEXT, br#"{"type":"ready"}"#)]);
    let frame = block_on(socket.recv()).expect("the control channel is text");
    assert_eq!(frame, WireFrame::Text(br#"{"type":"ready"}"#.to_vec()));
}

#[test]
fn an_undefined_opcode_is_still_an_error() {
    // ⛔ The skip is for control frames, not for everything: an opcode that is
    // not defined is a protocol violation and must not be silently dropped.
    let mut socket = socket(vec![FakeSession::frame(0x3, b"")]);
    assert!(block_on(socket.recv()).is_err());
}

#[test]
fn sent_frames_counts_what_actually_went_out() {
    let mut socket = socket(vec![]);
    assert_eq!(socket.sent_frames(), 0);

    block_on(socket.send_binary(b"one")).expect("under the cap");
    assert_eq!(socket.sent_frames(), 1);

    // ⛔ **Refused, so not counted.** This is the whole reason the counter
    // exists: an over-cap frame must not reach the wire, and an error return
    // alone does not prove it did not.
    let over = vec![0u8; Limits::reverse_node().max_wire_frame + 1];
    assert!(block_on(socket.send_binary(&over)).is_err());
    assert_eq!(socket.sent_frames(), 1, "a refused frame is not a sent frame");

    block_on(socket.send_text(b"two")).expect("text is allowed on the node leg");
    assert_eq!(socket.sent_frames(), 2);
    assert_eq!(socket.session().sent.last(), Some(&(OPCODE_TEXT, b"two".to_vec())));
}

const ID: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

/// The relay reads a binary node frame as a 32-character session id and
/// closes `1003 bad multiplex id` when it is not hex, so a control message
/// sent as binary ends each session on the socket.
#[test]
fn a_control_frame_leaves_as_text() {
    let id = SessionId::parse(ID).expect("32 lowercase hex");
    let mut leg = Leg::new(socket(vec![]), LegShape::ReverseNode, Limits::reverse_node());
    let ready = control::ready(&id).expect("a ready frame");
    assert_eq!(
        String::from_utf8(ready.clone()).unwrap(),
        format!(r#"{{"type":"ready","id":"{}"}}"#, id.as_str())
    );

    block_on(leg.send_control(&ready)).expect("the node leg has a control channel");
    block_on(leg.send_data(Some(&id), b"payload")).expect("a data frame");

    let sent = &leg.socket().session().sent;
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0], (OPCODE_TEXT, ready), "control is a text frame");
    assert_eq!(sent[1].0, OPCODE_BINARY, "data is a binary frame");
    assert_eq!(&sent[1].1[..32], ID, "the id comes first");
    assert_eq!(&sent[1].1[32..], b"payload");
    assert_eq!(leg.sent_frames(), 2);
}

/// Refused before the wire, and not counted: text that is not UTF-8, and a
/// control over the 4 KiB cap. A frame at the cap leaves.
#[test]
fn a_text_frame_that_is_not_utf8_or_over_the_cap_never_leaves() {
    let mut socket = socket(vec![]);

    let err = block_on(socket.send_text(&[b'{', 0xff, b'}'])).unwrap_err();
    assert!(
        matches!(err, TransportError::Codec(CodecError::ControlNotUtf8 { valid_up_to: 1 })),
        "{err:?}"
    );
    let err = block_on(socket.send_text(&vec![b'x'; CONTROL_MAX + 1])).unwrap_err();
    assert!(
        matches!(err, TransportError::Codec(CodecError::ControlFrameTooLong { got, max })
            if got == CONTROL_MAX + 1 && max == CONTROL_MAX),
        "{err:?}"
    );
    assert_eq!(socket.sent_frames(), 0);
    assert!(socket.session().sent.is_empty(), "{:?}", socket.session().sent);

    block_on(socket.send_text(&vec![b'x'; CONTROL_MAX])).expect("4096 bytes is at the cap");
    assert_eq!(socket.session().sent, vec![(OPCODE_TEXT, vec![b'x'; CONTROL_MAX])]);
    assert_eq!(socket.sent_frames(), 1);
}

/// A write the session failed did not go out, so it is not counted.
#[test]
fn a_text_frame_the_session_failed_is_not_counted() {
    let mut socket = WsSocket::new(
        FakeSession { refuse: Some("the socket ended".into()), ..FakeSession::default() },
        Limits::reverse_node(),
    );
    let err = block_on(socket.send_text(br#"{"type":"close"}"#)).unwrap_err();
    assert!(matches!(err, TransportError::Unexpected(ref d) if d == "the socket ended"), "{err:?}");
    assert_eq!(socket.sent_frames(), 0);
    block_on(socket.send_text(br#"{"type":"close"}"#)).expect("the next write goes out");
    assert_eq!(socket.sent_frames(), 1);
}
