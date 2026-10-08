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
    Leg, Socket, WireFrame, WsFrame, WsSession, WsSocket, OPCODE_BINARY, OPCODE_CLOSE, OPCODE_PING,
    OPCODE_PONG, OPCODE_TEXT,
};
use podssh_transport::sessions::{
    OperatorState, SessionState, DATA_BEFORE_READY, INVALID_CONTROL_JSON, INVALID_SESSION_ID,
    UNKNOWN_CONTROL_TYPE, UNKNOWN_SESSION_ID, WAIT_FOR_READY,
};
use podssh_transport::transport::{Control, Inbound, LegShape, Limits};
use podssh_transport::adapt::SessionError;
use podssh_transport::{CodecError, Retry, SessionAction, SessionId, TransportError};

mod common;
use common::block_on;

/// ⛔ **A session that is a list of frames in and a list of frames out.**
/// Each write is recorded with its opcode, so a test sees the frame type that
/// reached the wire and not only how many frames did.
#[derive(Default)]
struct FakeSession {
    inbound: VecDeque<WsFrame>,
    sent: Vec<(u8, Vec<u8>)>,
    fail: Option<SessionError>,
    /// The next write fails with this, as a dropped socket would.
    refuse: Option<SessionError>,
}

impl FakeSession {
    fn with(frames: Vec<WsFrame>) -> Self {
        Self { inbound: frames.into(), ..Self::default() }
    }

    fn frame(opcode: u8, payload: &[u8]) -> WsFrame {
        WsFrame { opcode, payload: payload.to_vec() }
    }

    fn record(&mut self, opcode: u8, payload: &[u8]) -> Result<(), SessionError> {
        if let Some(detail) = self.refuse.take() {
            return Err(detail);
        }
        self.sent.push((opcode, payload.to_vec()));
        Ok(())
    }
}

impl WsSession for FakeSession {
    async fn send(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        self.record(OPCODE_BINARY, payload)
    }

    async fn send_pong(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        self.record(OPCODE_PONG, payload)
    }

    async fn send_text(&mut self, text: &str) -> Result<(), SessionError> {
        self.record(OPCODE_TEXT, text.as_bytes())
    }

    async fn read(&mut self) -> Result<WsFrame, SessionError> {
        if let Some(error) = self.fail.take() {
            return Err(error);
        }
        self.inbound.pop_front().ok_or_else(|| SessionError::ClosedWithoutClose("the session ended".to_string()))
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
    let mut leg = Leg::new(socket(vec![open(&id)]), LegShape::ReverseNode, Limits::reverse_node());
    block_on(leg.recv()).expect("the relay opens the session");
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
        FakeSession { refuse: Some(io("the socket ended")), ..FakeSession::default() },
        Limits::reverse_node(),
    );
    let err = block_on(socket.send_text(br#"{"type":"close"}"#)).unwrap_err();
    assert!(matches!(err, TransportError::Aborted { ref detail, .. } if detail == "the socket ended"), "{err:?}");
    assert_eq!(socket.sent_frames(), 0);
    block_on(socket.send_text(br#"{"type":"close"}"#)).expect("the next write goes out");
    assert_eq!(socket.sent_frames(), 1);
}

/// The payload of a Close that the live relay sent (version 2026-10-03-r2),
/// captured on 2026-10-09 by `python scripts/capture-close.py`, a client of
/// the Python standard library: github.com:22 closed the connection after a
/// line that is not SSH. Bytes that podssh did not make.
const LIVE_CLOSE: &str = "03e874617267657420636c6f736564";

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

fn close_frame(code: u16, reason: &str) -> WsFrame {
    let mut payload = code.to_be_bytes().to_vec();
    payload.extend_from_slice(reason.as_bytes());
    FakeSession::frame(OPCODE_CLOSE, &payload)
}

/// The code and the reason of a Close, as received.
fn close_of(error: &TransportError) -> (u16, String, bool) {
    match error {
        TransportError::Closed(close) => (close.code, close.reason.clone(), close.clean),
        other => panic!("not a Close: {other:?}"),
    }
}

/// The two `1001` reasons need opposite actions, so the reason must survive
/// the read: a new pair after `pair expired`, nothing after a stop.
#[test]
fn a_close_keeps_its_code_and_reason() {
    let mut socket = socket(vec![
        close_frame(1001, "pair expired"),
        FakeSession::frame(OPCODE_BINARY, b"after the close"),
    ]);
    let error = block_on(socket.recv()).unwrap_err();
    assert_eq!(close_of(&error), (1001, "pair expired".into(), true));
    assert_eq!(error.retry(), Retry::NewPair);
    assert!(error.to_string().contains("1001 pair expired"), "{error}");

    // After a Close, a read returns the same error and leaves the socket alone.
    let again = block_on(socket.recv()).unwrap_err();
    assert_eq!(close_of(&again), (1001, "pair expired".into(), true));
    assert_eq!(socket.session().inbound.len(), 1, "a frame after the Close was read");

    let mut socket = socket_with_close(close_frame(1001, "operator stopped reverse relay"));
    let error = block_on(socket.recv()).unwrap_err();
    assert_eq!(close_of(&error), (1001, "operator stopped reverse relay".into(), true));
    assert_eq!(error.retry(), Retry::Never);
}

fn socket_with_close(frame: WsFrame) -> WsSocket<FakeSession> {
    socket(vec![frame])
}

#[test]
fn a_close_captured_from_the_live_relay_is_read_as_sent() {
    let payload = from_hex(LIVE_CLOSE);
    let mut socket = socket_with_close(FakeSession::frame(OPCODE_CLOSE, &payload));
    let error = block_on(socket.recv()).unwrap_err();
    assert_eq!(close_of(&error), (1000, "target closed".into(), true));
    assert!(error.to_string().contains("1000 target closed"), "{error}");
}

/// RFC 6455 section 7.1.5: a Close with no status code is 1005. A reason is
/// printed with no control characters.
#[test]
fn a_close_with_no_code_is_1005_and_a_reason_loses_its_control_characters() {
    let mut socket = socket_with_close(FakeSession::frame(OPCODE_CLOSE, b""));
    assert_eq!(close_of(&block_on(socket.recv()).unwrap_err()), (1005, String::new(), true));

    let mut socket = socket_with_close(close_frame(4000, "bad\u{1b}[2J\u{7}news"));
    let error = block_on(socket.recv()).unwrap_err();
    assert_eq!(close_of(&error).1, "bad[2Jnews");
    assert!(!error.to_string().chars().any(char::is_control), "{error:?}");
}

/// A read error keeps its text, stays a reason to reconnect, and is returned
/// again with no second read.
#[test]
fn a_read_error_keeps_its_text() {
    let mut socket = WsSocket::new(
        FakeSession {
            inbound: vec![FakeSession::frame(OPCODE_BINARY, b"never read")].into(),
            fail: Some(io("tls: connection reset by peer")),
            ..FakeSession::default()
        },
        Limits::reverse_node(),
    );
    let error = block_on(socket.recv()).unwrap_err();
    assert!(
        matches!(&error, TransportError::Aborted { clean: false, detail } if detail == "tls: connection reset by peer"),
        "{error:?}"
    );
    assert_eq!(error.retry(), Retry::Reconnect);
    assert!(error.to_string().contains("tls: connection reset by peer"), "{error}");
    let again = block_on(socket.recv()).unwrap_err();
    assert!(matches!(&again, TransportError::Aborted { detail, .. } if detail == "tls: connection reset by peer"));
    assert_eq!(socket.session().inbound.len(), 1, "the socket was read after it failed");
}

/// A control frame as the relay sends it (spec lines 138-139).
fn control_frame(kind: &str, id: &SessionId) -> WsFrame {
    FakeSession::frame(OPCODE_TEXT, format!(r#"{{"type":"{kind}","id":"{}"}}"#, id.as_str()).as_bytes())
}

fn open(id: &SessionId) -> WsFrame {
    control_frame("open", id)
}

fn refusal_of(error: TransportError) -> podssh_transport::sessions::Refusal {
    match error {
        TransportError::Refused(refusal) => refusal,
        other => panic!("not a refusal: {other:?}"),
    }
}

fn node(frames: Vec<WsFrame>) -> Leg<WsSocket<FakeSession>> {
    Leg::new(socket(frames), LegShape::ReverseNode, Limits::reverse_node())
}

/// Data for a session goes out only between its `ready` and its `close`.
/// Before, the relay closes the whole node socket (`1003 data before ready`,
/// `1003 unknown session id`), which ends each session on it.
#[test]
fn node_data_before_ready_is_refused_and_not_sent() {
    let id = SessionId::parse(ID).unwrap();
    let mut leg = node(vec![open(&id), control_frame("close", &id)]);

    let error = block_on(leg.send_data(Some(&id), b"early")).unwrap_err();
    assert_eq!(refusal_of(error), UNKNOWN_SESSION_ID, "never opened");
    assert_eq!(leg.sent_frames(), 0);

    assert_eq!(block_on(leg.recv()).unwrap(), Inbound::Control(Control::Open { id }));
    assert_eq!(leg.sessions().state(&id), Some(SessionState::Opened));
    let error = block_on(leg.send_data(Some(&id), b"early")).unwrap_err();
    assert_eq!(error.session_action(), SessionAction::AnswerReadyFirst);
    assert!(error.to_string().contains("1003 data before ready"), "{error}");
    assert_eq!(refusal_of(error), DATA_BEFORE_READY);
    assert_eq!(leg.sent_frames(), 0, "a refused frame reached the wire");

    block_on(leg.send_control(&control::ready(&id).unwrap())).expect("ready for an open session");
    assert_eq!(leg.sessions().state(&id), Some(SessionState::Readied));
    block_on(leg.send_data(Some(&id), b"in time")).expect("data after ready");
    assert_eq!(leg.sent_frames(), 2);

    assert!(matches!(block_on(leg.recv()).unwrap(), Inbound::Control(Control::Close { .. })));
    assert_eq!(leg.sessions().state(&id), None, "a closed session is forgotten");
    let error = block_on(leg.send_data(Some(&id), b"late")).unwrap_err();
    assert_eq!(refusal_of(error), UNKNOWN_SESSION_ID);
    let error = block_on(leg.send_control(&control::ready(&id).unwrap())).unwrap_err();
    assert_eq!(refusal_of(error), UNKNOWN_SESSION_ID, "a ready for an old id");
    assert_eq!(leg.sent_frames(), 2);
    assert_eq!(leg.socket().session().sent.len(), 2);
}

/// One reader returns the control and the data of a node socket, mixed, in
/// the order they arrived. (The JSON follows the contract; T-079 records
/// frames from the live relay.)
#[test]
fn mixed_control_and_data_all_arrive_in_order() {
    let id = SessionId::parse(ID).unwrap();
    let mut data = ID.to_vec();
    data.extend_from_slice(b"SSH-2.0-OpenSSH_10.0\r\n");
    let mut leg = node(vec![
        open(&id),
        FakeSession::frame(OPCODE_BINARY, &data),
        FakeSession::frame(OPCODE_PING, b"keepalive"),
        control_frame("close", &id),
    ]);
    let mut got = Vec::new();
    for _ in 0..3 {
        got.push(block_on(leg.recv()).expect("a frame"));
    }
    assert_eq!(
        got,
        vec![
            Inbound::Control(Control::Open { id }),
            Inbound::Data { id: Some(id), payload: b"SSH-2.0-OpenSSH_10.0\r\n".to_vec() },
            Inbound::Control(Control::Close { id, reason: None }),
        ]
    );
    assert!(block_on(leg.recv()).is_err(), "the session ended");
}

/// The operator's data waits for the node's `ready` (`1008 wait for ready`)
/// and stops at its `reject`.
#[test]
fn operator_data_waits_for_ready_and_stops_after_reject() {
    let id = SessionId::parse(ID).unwrap();
    let reject = format!(r#"{{"type":"reject","id":"{}","reason":"connection refused"}}"#, id.as_str());
    let mut leg = Leg::new(
        socket(vec![control_frame("ready", &id), FakeSession::frame(OPCODE_TEXT, reject.as_bytes())]),
        LegShape::ReverseOperator,
        Limits::reverse_operator(),
    );
    let error = block_on(leg.send_data(None, b"early")).unwrap_err();
    assert_eq!(error.session_action(), SessionAction::WaitForReady);
    assert_eq!(refusal_of(error), WAIT_FOR_READY);
    assert_eq!(leg.sent_frames(), 0);

    assert_eq!(block_on(leg.recv()).unwrap(), Inbound::Control(Control::Ready { id }));
    assert_eq!(leg.operator_state(), OperatorState::Readied);
    block_on(leg.send_data(None, b"in time")).expect("data after ready");

    assert!(matches!(block_on(leg.recv()).unwrap(), Inbound::Control(Control::Reject { .. })));
    assert_eq!(leg.operator_state(), OperatorState::Closed);
    assert!(block_on(leg.send_data(None, b"late")).is_err());
    assert_eq!(leg.sent_frames(), 1);
}

/// A control frame that the relay would close the node socket for never
/// leaves: not JSON, an unknown type, an id that is not 32 lowercase hex.
#[test]
fn a_control_frame_the_relay_would_refuse_never_leaves() {
    let id = SessionId::parse(ID).unwrap();
    let mut leg = node(vec![open(&id)]);
    block_on(leg.recv()).unwrap();
    let cases: [(&[u8], _); 4] = [
        (b"ready", INVALID_CONTROL_JSON),
        (br#"{"type":"ping","id":"0123456789abcdef0123456789abcdef"}"#, UNKNOWN_CONTROL_TYPE),
        (br#"{"type":"ready","id":"0123456789ABCDEF0123456789abcdef"}"#, INVALID_SESSION_ID),
        (br#"{"type":"ready"}"#, INVALID_SESSION_ID),
    ];
    for (frame, expected) in cases {
        let error = block_on(leg.send_control(frame)).unwrap_err();
        assert_eq!(refusal_of(error), expected, "{}", String::from_utf8_lossy(frame));
    }
    assert_eq!(leg.sent_frames(), 0);
    assert_eq!(leg.sessions().state(&id), Some(SessionState::Opened), "a refusal changes nothing");
}

/// A socket error, as the session gives one.
fn io(text: &str) -> SessionError {
    SessionError::Io { kind: std::io::ErrorKind::ConnectionReset, text: text.into() }
}

/// Each class of a session's failure has its retry (T-069): a frame that RFC
/// 6455 forbids, or a message over the limit, is never retried; a link that
/// broke may be reconnected. The text is kept.
#[test]
fn each_class_of_a_session_failure_has_its_retry() {
    let cases = [
        (SessionError::Protocol("a continuation with no message".into()), Retry::Never),
        (SessionError::TooLarge("a fragmented message exceeded 16777216 bytes".into()), Retry::Never),
        (io("connection reset"), Retry::Reconnect),
        (SessionError::Idle("no data from the relay for 90s".into()), Retry::Reconnect),
        (SessionError::WriteStalled("sending to the relay stalled for 60s".into()), Retry::Reconnect),
        (SessionError::Dead("pings unanswered: the connection is dead".into()), Retry::Reconnect),
        (SessionError::ClosedWithoutClose("the relay closed the connection".into()), Retry::Reconnect),
    ];
    for (class, retry) in cases {
        let text = class.to_string();
        let mut socket =
            WsSocket::new(FakeSession { fail: Some(class.clone()), ..FakeSession::default() }, Limits::reverse_node());
        let error = block_on(socket.recv()).unwrap_err();
        assert_eq!(error.retry(), retry, "{class:?}");
        assert!(error.to_string().contains(&text), "{error}");
    }
}
