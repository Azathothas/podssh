//! ⛔ **E02's four plants, and the controls that prove they are not guards that
//! refuse everything.**
//!
//! E02's `Prove` block names these four defects:
//!
//! | Plant | Defect | Expected |
//! | --- | --- | --- |
//! | A | a node frame with no id prefix | the relay closes `1009` |
//! | B | an operator frame with an invented 32-byte prefix | it arrives at the node as payload |
//! | C | an operator text frame | the relay closes `1003` |
//! | D | node data before `ready` | the relay closes `1003 data before ready` |
//!
//! ⛔ **How a plant is run here, and why.** ⛔ The relay accepts no inbound TCP —
//! **READ**, live spec line 222: *"no inbound TCP (inbound raw TCP to a Worker is
//! platform-impossible)"* — so a plant needing a real socket cannot run in this
//! repository at all. ⛔ Each test therefore has **two arms**: with
//! `PODSSH_PLANT=<defect>` set it takes the **defective** path and asserts what a
//! client carrying the bug would expect, which makes it **fail and print the
//! close code**; with the variable unset it takes the correct path and passes.
//! ⛔ **Both directions are in one file** so the control cannot be lost:
//!
//! ```sh
//! PODSSH_PLANT=no_id_prefix  cargo test -p podssh-transport --test plants plant_no_id_prefix
//! cargo test -p podssh-transport --test plants plant_no_id_prefix   # the control
//! ```
//!
//! ⛔ **The relay model is transcribed from the row it stands for**, with the spec
//! line named beside it, and ⛔ **it asserts the close CODE and REASON rather than
//! a paraphrase** — because a paraphrase is how a wrong number survives review.

use podssh_transport::closes::{classify, Leg, RelayClose};
use podssh_transport::framing::legs::{encode_node_frame, encode_operator_frame};
use podssh_transport::framing::{SessionId, SESSION_ID_LEN};
use podssh_transport::{Retry, SessionAction};

mod common;
use common::block_on;

/// ⛔ **Is the named defect switched on?** ⛔ An unset variable is the control, and
/// ⛔ **an unknown name is the control too** — a typo must not silently plant
/// something.
fn planted(name: &str) -> bool {
    std::env::var("PODSSH_PLANT").as_deref() == Ok(name)
}

/// ⛔ **Panic with the relay's own words.** ⛔ The close code is the thing a
/// reviewer needs, and `unwrap`'s message on a `RelayClose` would bury it under
/// the struct's `Debug`.
fn closed_unexpectedly(close: RelayClose) -> () {
    panic!(
        "relay closed {} {} (clean={}) — this line is the DEFECT arm, and it is \
         reached because the planted defect produced a close the buggy client \
         expected not to happen",
        close.code, close.reason, close.clean
    );
}

// ── the relay, as far as the protocol is published ──────────────────────────

/// ⛔ **Live spec line 182**, read with `sed -n '182p'` on 2026-10-05:
/// *"Node binary frame under 32 bytes or over 65568 (32-byte id plus 65536
/// payload). Always prefix the full id."*
fn relay_accepts_node_frame(wire: &[u8]) -> Result<(), RelayClose> {
    if wire.len() < SESSION_ID_LEN {
        return Err(RelayClose { code: 1009, reason: "bad multiplex frame".into(), clean: true });
    }
    if wire.len() > 65568 {
        return Err(RelayClose { code: 1009, reason: "bad multiplex frame".into(), clean: true });
    }
    if !wire[..SESSION_ID_LEN].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(RelayClose { code: 1003, reason: "bad multiplex id".into(), clean: true });
    }
    Ok(())
}

/// ⛔ **Live spec lines 143-145:** *"the operator receives text control frames and sends
/// binary data frames only — an operator text frame closes the socket `1003`."*
fn relay_accepts_operator_frame(opcode: u8) -> Result<(), RelayClose> {
    if opcode != 0x2 {
        return Err(RelayClose { code: 1003, reason: "binary frames required".into(), clean: true });
    }
    Ok(())
}

/// ⛔ **Live spec line 177:** *"Node data arrived for a session the node never
/// readied. Answer `open` with `ready` first."*
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

/// ⛔ **Live spec line 190:** *"No `ready` within 15 s of `open`."*
fn operator_wait_for_ready(elapsed_ms: u64) -> Result<(), RelayClose> {
    if elapsed_ms >= 15_000 {
        return Err(RelayClose { code: 1013, reason: "node open timeout".into(), clean: true });
    }
    Ok(())
}

// ── Plant A — a node frame with no id prefix → 1009 ────────────────────────

#[test]
fn plant_no_id_prefix() {
    let id = common::id();
    let banner = b"SSH-2.0-podssh_0.1.0\r\n";

    if planted("no_id_prefix") {
        // ⛔ **THE DEFECT: the payload goes out alone.** ⛔ A client that writes
        // this believes a bare node frame is acceptable.
        let bare = banner.to_vec();
        relay_accepts_node_frame(&bare).unwrap_or_else(closed_unexpectedly);
    }

    // ⛔ **THE CORRECT PATH.** The relay sees 19 bytes, which is *"under 32
    // bytes"*, and closes `1009 bad multiplex frame`.
    let bare = banner.to_vec();
    let close = relay_accepts_node_frame(&bare).expect_err("a bare node frame must be refused");
    assert_eq!(close.code, 1009, "⛔ spec line 182");
    assert_eq!(close.reason, "bad multiplex frame");
    assert_eq!(classify(&close).row.expect("a published row").spec_line, 182);
    assert_eq!(classify(&close).retry, Retry::Never, "⛔ the next attempt sends the same bytes");

    // ⛔ **CONTROL: the same payload, correctly framed, is accepted.**
    let framed = encode_node_frame(&id, banner).expect("a banner is under the cap");
    relay_accepts_node_frame(&framed).unwrap_or_else(closed_unexpectedly);
    assert_eq!(framed.len(), SESSION_ID_LEN + banner.len());

    // ⛔ **And podssh's own node leg refuses to build one**, so the defect cannot
    // reach the wire through this crate at all.
    let mut leg = podssh_transport::socket::Leg::new(
        podssh_transport::socket::FrameQueue::new(),
        podssh_transport::LegShape::ReverseNode,
        podssh_transport::Limits::reverse_node(),
    );
    let err = block_on(leg.send_data(None, banner)).expect_err("a node frame needs an id");
    assert!(err.to_string().contains("1009"), "the refusal names the code: {err}");
    assert_eq!(leg.sent_frames(), 0, "⛔ a refused frame must not reach the wire");
}

// ── Plant B — an invented operator prefix arrives as payload ───────────────

#[test]
fn plant_operator_invents_an_id() {
    // ⛔ 32 `f`s, then the SSH version string: what a client writes when it
    // reuses the reverse leg's framing on the forward one.
    let invented: &[u8] = b"ffffffffffffffffffffffffffffffff";
    let version: &[u8] = b"SSH-2.0-podssh_0.1.0";
    let defective = [invented, version].concat();

    // ⛔ **THE RELAY ACCEPTS IT. No error, no close, no warning.**
    // ⛔ **Live spec lines 146-151**: *"the relay never reads an id out of an
    // operator frame, treats the whole frame as payload, and prepends the
    // session's real id. An id an operator sends is rewritten, not honoured."*
    relay_accepts_operator_frame(0x2).unwrap_or_else(closed_unexpectedly);

    // ⛔ **What the node then receives: the invented id, as the first 32 bytes of
    // session data.** ⛔ For N operator bytes the node gets `32 + N`.
    let real_id: &[u8] = b"faa0afcc000000000000000000000000";
    assert_eq!(real_id.len(), 32, "⛔ spec line 140: 32 ASCII hex characters");
    assert!(SessionId::parse(real_id).is_ok(), "⛔ and it must parse as one");

    let at_node = [real_id, defective.as_slice()].concat();
    assert_eq!(at_node.len(), 32 + 52);

    if planted("operator_prefix") {
        // ⛔ **THE DEFECT, and it is the reason this plant exists.** ⛔ A buggy
        // client strips a 32-byte id off the relay's inbound frame before handing
        // the rest to the application — because that is what it writes on the
        // operator leg, and ⛔ **the first 32 bytes of every message the operator
        // receives are the SSH version string.** ⛔ **This defect is entirely
        // SILENT**: no close, no error, and the frame is a perfectly well-formed
        // binary frame. ⛔ So there is no relay answer for the plant to trip
        // over, and the plant asserts what a buggy client would produce — which
        // is wrong.
        assert!(
            at_node.len() == 52,
            "a client that subtracts 32 from the operator's inbound frame loses the \n             first 32 bytes: it sees \"{}\" + \" S\" where the version string \"{}\" \n             belongs, and SSH dies reading a banner that begins with a hex id",
            String::from_utf8_lossy(&at_node[32..43]),
            String::from_utf8_lossy(version)
        );
    }

    assert_eq!(
        &at_node[32..64],
        invented,
        "⛔ THE DEFECT IS VISIBLE HERE: the node reads the invented id as the first \
         32 bytes of session data, ahead of the SSH version string"
    );
    assert_eq!(
        &at_node[64..],
        version,
        "and the SSH version string arrives 32 bytes late, so the handshake dies \
         reading garbage"
    );

    // ⛔ **CONTROL: the operator's correct shape is bare**, and the node then reads
    // the version string at offset 32 with nothing in front of it.
    let correct = encode_operator_frame(version).expect("20 bytes is far under the cap");
    assert_eq!(correct, version.to_vec(), "⛔ podssh writes no prefix at all");
    let at_node_correct = [real_id, correct.as_slice()].concat();
    assert_eq!(at_node_correct.len(), 32 + 20);
    assert_eq!(&at_node_correct[32..], version);
}

// ── Plant C — an operator text frame → 1003 ─────────────────────────────────

#[test]
fn plant_operator_text_frame() {
    if planted("operator_text") {
        // ⛔ **THE DEFECT: a text frame goes out on the operator leg**, for a
        // heartbeat, a goodbye, or a log line.
        relay_accepts_operator_frame(0x1).unwrap_or_else(closed_unexpectedly);
    }

    // ⛔ **THE CORRECT PATH.** ⛔ Spec line 178 names the close and the reason.
    let close = relay_accepts_operator_frame(0x1).expect_err("a text frame must be refused");
    assert_eq!(close.code, 1003, "⛔ spec line 178, live lines 143-145");
    assert_eq!(close.reason, "binary frames required");
    assert_eq!(classify(&close).row.expect("a published row").observed_by, Leg::Operator);

    let classified = classify(&close);
    assert_eq!(classified.session, SessionAction::DoNotSendText);
    assert_eq!(classified.retry, Retry::Never, "⛔ never retry: the fault is the frame");

    // ⛔ **CONTROL: binary is accepted.**
    relay_accepts_operator_frame(0x2).unwrap_or_else(closed_unexpectedly);

    // ⛔ **And podssh's own operator leg refuses to send one**, which is the half
    // that is a guard rather than a model.
    let mut leg = podssh_transport::socket::Leg::new(
        podssh_transport::socket::FrameQueue::new(),
        podssh_transport::LegShape::ReverseOperator,
        podssh_transport::Limits::reverse_operator(),
    );
    let err = block_on(leg.send_control(br#"{"type":"ping"}"#))
        .expect_err("the operator leg must refuse a text frame");
    assert!(err.to_string().contains("1003"), "the refusal names the code: {err}");
    assert_eq!(leg.sent_frames(), 0, "⛔ a refused frame must not reach the wire");
}

#[test]
fn plant_forward_text_frame_is_refused_too() {
    // ⛔ **The forward path has no `hello`, no `open`, no `ready`, and no text
    // ⛔ **frame at all** — `01-relay-protocol.md:215-217`. ⛔ **A leg that
    // accepted a control frame would be a leg inventing a protocol**, and
    // ⛔ **READ**, live spec line 210: *"After `101`, **binary** frames carry
    // raw TCP bytes verbatim in both directions."*
    let mut leg = podssh_transport::socket::Leg::new(
        podssh_transport::socket::FrameQueue::new(),
        podssh_transport::LegShape::Forward,
        podssh_transport::Limits::forward(262_144),
    );
    assert!(leg.recv_control_is_absent(), "the forward leg has no control channel");
    assert!(block_on(leg.send_control(b"{}")).is_err());
    assert_eq!(leg.sent_frames(), 0);
}

// ── Plant D — node data before `ready` → 1003 data before ready ─────────────

#[test]
fn plant_data_before_ready() {
    let id = common::id();
    let version: &[u8] = b"SSH-2.0-podssh_0.1.0";

    if planted("data_before_ready") {
        // ⛔ **THE DEFECT: data goes out for a session that was never readied.**
        NodeSessionState { readied: false }.accept_data().unwrap_or_else(closed_unexpectedly);
    }

    // ⛔ **THE CORRECT PATH.** ⛔ The frame is perfectly well formed; the fault is
    // the ordering, and ⛔ that is why no codec check can catch it.
    let frame = encode_node_frame(&id, version).expect("the frame itself is well formed");
    relay_accepts_node_frame(&frame).unwrap_or_else(closed_unexpectedly);

    let close = NodeSessionState { readied: false }
        .accept_data()
        .expect_err("data before ready must be refused");
    assert_eq!(close.code, 1003, "⛔ spec line 177");
    assert_eq!(close.reason, "data before ready");
    assert_eq!(classify(&close).session, SessionAction::AnswerReadyFirst);
    assert_eq!(
        classify(&close).retry,
        Retry::Never,
        "⛔ reconnecting hides an ordering bug behind a retry loop"
    );

    // ⛔ **The operator's view of the same mistake is a DIFFERENT code.** ⛔ It
    // never received the data, so what it sees is the 15 s reaper — ⛔ spec line
    // 190, not line 177 — and a client that answered both with 1003 would be
    // wrong about which socket saw what.
    let operator_side = operator_wait_for_ready(15_000).expect_err("reaped at 15 s");
    assert_eq!(operator_side.code, 1013);
    assert_eq!(operator_side.reason, "node open timeout");

    // ⛔ **CONTROL: the same bytes with the session readied, and one millisecond
    // inside the operator's window.** One variable, two outcomes.
    NodeSessionState { readied: true }.accept_data().unwrap_or_else(closed_unexpectedly);
    operator_wait_for_ready(14_999).unwrap_or_else(closed_unexpectedly);

    // ⛔ **And podssh's node leg tracks readiness**, so the ordering is a value a
    // caller can read rather than a comment.
    let mut leg = podssh_transport::socket::Leg::new(
        podssh_transport::socket::FrameQueue::new(),
        podssh_transport::LegShape::ReverseNode,
        podssh_transport::Limits::reverse_node(),
    );
    assert!(!leg.is_ready(), "a fresh node leg has readied nothing");
    block_on(leg.send_data(Some(&id), version)).expect("the send itself is fine");
    leg.set_ready(true);
    assert!(leg.is_ready());
}

// ── the caps are three different numbers, and the plants did not blur them ──

#[test]
fn the_three_caps_are_three_different_numbers() {
    use podssh_transport::endpoint::FORWARD_MAX_FRAME_MEASURED;
    use podssh_transport::framing::{NODE_FRAME_MAX_WIRE, NODE_PAYLOAD_MAX, OPERATOR_PAYLOAD_MAX};

    assert_eq!(NODE_FRAME_MAX_WIRE, 65568, "⛔ spec line 182: id INCLUDED");
    assert_eq!(NODE_PAYLOAD_MAX, 65536, "⛔ spec line 140: up to 64 KiB of bytes");
    assert_eq!(OPERATOR_PAYLOAD_MAX, 65536, "⛔ spec line 184: PAYLOAD only");
    assert_eq!(FORWARD_MAX_FRAME_MEASURED, 262_144, "⛔ MEASURED from /relays.json");
    assert_eq!(NODE_FRAME_MAX_WIRE, SESSION_ID_LEN + NODE_PAYLOAD_MAX);

    let id = common::id();
    assert!(encode_node_frame(&id, &vec![b'x'; NODE_PAYLOAD_MAX]).is_ok(), "65536 beside an id");
    assert!(encode_node_frame(&id, &vec![b'x'; NODE_PAYLOAD_MAX + 1]).is_err(), "65537 is not");
    assert!(encode_operator_frame(&vec![b'x'; OPERATOR_PAYLOAD_MAX]).is_ok(), "65536 bare");
    assert!(encode_operator_frame(&vec![b'x'; OPERATOR_PAYLOAD_MAX + 1]).is_err(), "65537 is not");
    // ⛔ **The forward cap is a runtime value with no id in it**, so all 262144
    // bytes are payload.
    assert!(podssh_transport::framing::legs::encode_forward_frame(&vec![b'x'; 262_144], 262_144).is_ok());
    assert!(podssh_transport::framing::legs::encode_forward_frame(&vec![b'x'; 262_145], 262_144).is_err());
}

#[test]
fn a_codec_error_names_the_close_code_the_relay_would_answer_with() {
    use podssh_transport::framing::CodecError;
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
    let err = podssh_transport::framing::legs::decode_node_frame(b"short").unwrap_err();
    assert_eq!(err.relay_close_code(), Some(1009));
}