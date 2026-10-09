//! Four planted defects of the reverse legs, and the controls that show the
//! checks are not guards that refuse everything:
//!
//! | Plant | Defect | Expected |
//! | --- | --- | --- |
//! | A | a node frame with no id | the relay closes `1009` |
//! | B | an operator frame with an invented 32-byte prefix | it reaches the node as payload |
//! | C | an operator text frame | the relay closes `1003` |
//! | D | node data before `ready` | the relay closes `1003 data before ready` |
//!
//! The relay takes no inbound TCP, so a plant that needs its socket cannot
//! run here: each test models the relay from the row of its contract, and has
//! two arms. With `PODSSH_PLANT=<defect>` it takes the defective path and
//! fails, printing the close; unset, it takes the correct path and passes.
//!
//! ```sh
//! PODSSH_PLANT=no_id_prefix cargo test -p podssh-relay --features pair --test reverse_plants plant_no_id_prefix
//! cargo test -p podssh-relay --features pair --test reverse_plants plant_no_id_prefix   # the control
//! ```
#![cfg(feature = "pair")]

use podssh_relay::reverse::closes::{classify, Leg, Retry, SessionAction};
use podssh_relay::reverse::framing::legs::{decode_node_frame, encode_node_frame, encode_operator_frame};
use podssh_relay::reverse::framing::{
    CodecError, SessionId, NODE_FRAME_MAX_WIRE, NODE_PAYLOAD_MAX, OPERATOR_PAYLOAD_MAX, SESSION_ID_LEN,
};
use podssh_relay::reverse::sessions::{Sessions, DATA_BEFORE_READY};
use podssh_relay::reverse::RelayClose;

const ID_HEX: &str = "0123456789abcdef0123456789abcdef";

fn id() -> SessionId {
    SessionId::parse(ID_HEX.as_bytes()).expect("the test id is 32 lowercase hex")
}

/// Whether the named defect is planted. Unset, or a name that is no plant,
/// is the control: a typo plants nothing.
fn planted(name: &str) -> bool {
    std::env::var("PODSSH_PLANT").as_deref() == Ok(name)
}

/// Fail with the relay's own words: the close is what a reviewer needs.
fn closed_unexpectedly(close: RelayClose) {
    panic!(
        "relay closed {} {} (clean={}) — this line is the DEFECT arm, and it is \
         reached because the planted defect produced a close the buggy client \
         expected not to happen",
        close.code, close.reason, close.clean
    );
}

// The relay, as far as its contract says.

/// A node frame under 32 bytes, or over 65568, is `1009 bad multiplex frame`;
/// a prefix that is not hex is `1003 bad multiplex id`.
fn relay_accepts_node_frame(wire: &[u8]) -> Result<(), RelayClose> {
    if wire.len() < SESSION_ID_LEN || wire.len() > 65568 {
        return Err(RelayClose { code: 1009, reason: "bad multiplex frame".into(), clean: true });
    }
    if !wire[..SESSION_ID_LEN].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(RelayClose { code: 1003, reason: "bad multiplex id".into(), clean: true });
    }
    Ok(())
}

/// The operator sends binary frames only; a text frame closes it with `1003`.
fn relay_accepts_operator_frame(opcode: u8) -> Result<(), RelayClose> {
    if opcode != 0x2 {
        return Err(RelayClose { code: 1003, reason: "binary frames required".into(), clean: true });
    }
    Ok(())
}

/// Node data for a session that the node never readied.
struct NodeSessionState {
    readied: bool,
}

impl NodeSessionState {
    fn accept_data(&self) -> Result<(), RelayClose> {
        if !self.readied {
            return Err(RelayClose { code: 1003, reason: "data before ready".into(), clean: true });
        }
        Ok(())
    }
}

/// No `ready` within 15 s of `open`.
fn operator_wait_for_ready(elapsed_ms: u64) -> Result<(), RelayClose> {
    if elapsed_ms >= 15_000 {
        return Err(RelayClose { code: 1013, reason: "node open timeout".into(), clean: true });
    }
    Ok(())
}

// Plant A: a node frame with no id is 1009.

#[test]
fn plant_no_id_prefix() {
    let banner = b"SSH-2.0-podssh_0.1.0\r\n";
    if planted("no_id_prefix") {
        // The defect: the payload goes out alone.
        relay_accepts_node_frame(banner).unwrap_or_else(closed_unexpectedly);
    }
    // 22 bytes are under 32: `1009 bad multiplex frame`.
    let close = relay_accepts_node_frame(banner).expect_err("a bare node frame must be refused");
    assert_eq!(close.code, 1009);
    assert_eq!(close.reason, "bad multiplex frame");
    assert_eq!(classify(&close).row.expect("a published row").spec_line, 182);
    assert_eq!(classify(&close).retry, Retry::Never, "the next attempt sends the same bytes");

    // The control: the same payload, framed, is accepted. The one encoder of
    // node frames takes a `SessionId`, not an optional one, so the defect has
    // no way to the wire.
    let framed = encode_node_frame(&id(), banner).expect("a banner is under the cap");
    relay_accepts_node_frame(&framed).unwrap_or_else(closed_unexpectedly);
    assert_eq!(framed.len(), SESSION_ID_LEN + banner.len());
}

// Plant B: an id that an operator invents reaches the node as payload.

#[test]
fn plant_operator_invents_an_id() {
    // 32 `f`s, then the SSH version: what a client writes when it uses the
    // node's framing on the operator leg.
    let invented: &[u8] = b"ffffffffffffffffffffffffffffffff";
    let version: &[u8] = b"SSH-2.0-podssh_0.1.0";
    let defective = [invented, version].concat();

    // The relay takes it with no error, no close and no warning: it never reads
    // an id out of an operator frame, and puts the session's real id before it.
    relay_accepts_operator_frame(0x2).unwrap_or_else(closed_unexpectedly);
    let real_id: &[u8] = b"faa0afcc000000000000000000000000";
    assert_eq!(real_id.len(), 32, "an id is 32 ASCII hex characters");
    assert!(SessionId::parse(real_id).is_ok(), "and it must parse as one");
    let at_node = [real_id, defective.as_slice()].concat();
    assert_eq!(at_node.len(), 32 + 52);

    if planted("operator_prefix") {
        // The defect is silent: no close, no error, a well-formed frame. So the
        // plant asserts what a buggy client would see, which is wrong.
        assert!(
            at_node.len() == 52,
            "a client that subtracts 32 from the operator's inbound frame loses the \
             first 32 bytes: it sees \"{}\" + \" S\" where the version string \"{}\" \
             belongs, and SSH dies reading a banner that begins with a hex id",
            String::from_utf8_lossy(&at_node[32..43]),
            String::from_utf8_lossy(version)
        );
    }
    assert_eq!(
        &at_node[32..64],
        invented,
        "THE DEFECT IS VISIBLE HERE: the node reads the invented id as the first \
         32 bytes of session data, ahead of the SSH version string"
    );
    assert_eq!(&at_node[64..], version, "and the SSH version string arrives 32 bytes late, so the handshake dies reading garbage");

    // The control: the operator's frame is bare, and the node reads the version
    // right after the real id.
    let correct = encode_operator_frame(version).expect("20 bytes is far under the cap");
    assert_eq!(correct, version.to_vec(), "podssh writes no prefix at all");
    let at_node_correct = [real_id, correct.as_slice()].concat();
    assert_eq!(at_node_correct.len(), 32 + 20);
    assert_eq!(&at_node_correct[32..], version);
}

// Plant C: an operator text frame is 1003.

#[test]
fn plant_operator_text_frame() {
    if planted("operator_text") {
        // The defect: a text frame on the operator leg, for a heartbeat, a
        // goodbye or a log line.
        relay_accepts_operator_frame(0x1).unwrap_or_else(closed_unexpectedly);
    }
    let close = relay_accepts_operator_frame(0x1).expect_err("a text frame must be refused");
    assert_eq!(close.code, 1003);
    assert_eq!(close.reason, "binary frames required");
    assert_eq!(classify(&close).row.expect("a published row").observed_by, Leg::Operator);
    let classified = classify(&close);
    assert_eq!(classified.session, SessionAction::DoNotSendText);
    assert_eq!(classified.retry, Retry::Never, "never retry: the fault is the frame");
    // The control: binary is accepted.
    relay_accepts_operator_frame(0x2).unwrap_or_else(closed_unexpectedly);
}

// Plant D: node data before `ready` is `1003 data before ready`.

#[test]
fn plant_data_before_ready() {
    let version: &[u8] = b"SSH-2.0-podssh_0.1.0";
    if planted("data_before_ready") {
        // The defect: data for a session that was never readied.
        NodeSessionState { readied: false }.accept_data().unwrap_or_else(closed_unexpectedly);
    }
    // The frame is well formed; the fault is the order, which no codec sees.
    let frame = encode_node_frame(&id(), version).expect("the frame itself is well formed");
    relay_accepts_node_frame(&frame).unwrap_or_else(closed_unexpectedly);
    let close = NodeSessionState { readied: false }.accept_data().expect_err("data before ready must be refused");
    assert_eq!(close.code, 1003);
    assert_eq!(close.reason, "data before ready");
    assert_eq!(classify(&close).session, SessionAction::AnswerReadyFirst);
    assert_eq!(classify(&close).retry, Retry::Never, "a reconnection hides an ordering defect behind a loop");

    // The operator sees the same mistake as another code: it never got the
    // data, and what it sees is the relay's reaper at 15 s.
    let operator_side = operator_wait_for_ready(15_000).expect_err("reaped at 15 s");
    assert_eq!(operator_side.code, 1013);
    assert_eq!(operator_side.reason, "node open timeout");

    // The control: readied, and inside the operator's window.
    NodeSessionState { readied: true }.accept_data().unwrap_or_else(closed_unexpectedly);
    operator_wait_for_ready(14_999).unwrap_or_else(closed_unexpectedly);

    // The node's writer holds the same order: an opened session refuses data
    // with the relay's own words until it is readied.
    let mut sessions = Sessions::new();
    sessions.opened(id());
    let refused = sessions.may_send_data(&id()).expect_err("data before ready is refused");
    assert_eq!(refused, DATA_BEFORE_READY);
    let as_close = RelayClose { code: refused.code, reason: refused.reason.into(), clean: true };
    assert_eq!(classify(&as_close).session, SessionAction::AnswerReadyFirst);
    sessions.readied(id());
    assert!(sessions.may_send_data(&id()).is_ok());
}

// The caps are different numbers, which the plants did not blur.

#[test]
fn the_three_caps_are_three_different_numbers() {
    assert_eq!(NODE_FRAME_MAX_WIRE, 65568, "the id included");
    assert_eq!(NODE_PAYLOAD_MAX, 65536, "up to 64 KiB of bytes");
    assert_eq!(OPERATOR_PAYLOAD_MAX, 65536, "the payload alone");
    assert_eq!(NODE_FRAME_MAX_WIRE, SESSION_ID_LEN + NODE_PAYLOAD_MAX);
    assert!(encode_node_frame(&id(), &vec![b'x'; NODE_PAYLOAD_MAX]).is_ok(), "65536 beside an id");
    assert!(encode_node_frame(&id(), &vec![b'x'; NODE_PAYLOAD_MAX + 1]).is_err(), "65537 is not");
    assert!(encode_operator_frame(&vec![b'x'; OPERATOR_PAYLOAD_MAX]).is_ok(), "65536 bare");
    assert!(encode_operator_frame(&vec![b'x'; OPERATOR_PAYLOAD_MAX + 1]).is_err(), "65537 is not");
}

#[test]
fn a_codec_error_names_the_close_code_the_relay_would_answer_with() {
    let cases: Vec<CodecError> = vec![
        CodecError::FrameTooShort { got: 31 },
        CodecError::FrameTooLong { got: 65569, max: 65568 },
        CodecError::SessionIdLength { got: 31 },
        CodecError::SessionIdNotLowercaseHex { index: 0, byte: b'F' },
        CodecError::OperatorPayloadTooLong { got: 65537, max: 65536 },
        CodecError::ControlFrameTooLong { got: 4097, max: 4096 },
    ];
    for case in cases {
        let code = case.relay_close_code().expect("every codec error has a code");
        assert!(matches!(code, 1003 | 1009), "unexpected code {code} for {case:?}");
        assert!(!case.spec_row().is_empty(), "every codec error cites its row");
        assert!(case.to_string().contains("spec line"), "and says which: {case}");
    }
    let err = decode_node_frame(b"short").unwrap_err();
    assert_eq!(err.relay_close_code(), Some(1009));
    // Text that is not UTF-8 never leaves this side, so the relay's table has
    // no row for it: RFC 6455 is the source.
    let text = CodecError::ControlNotUtf8 { valid_up_to: 1 };
    assert_eq!(text.relay_close_code(), None);
    assert!(text.spec_row().starts_with("RFC 6455 section 8.1"), "{}", text.spec_row());
    assert!(text.to_string().contains("RFC 6455"), "{text}");
}
