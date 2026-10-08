//! ⛔ **The byte-exact acceptance of E02.**
//!
//! Every assertion here compares **the exact bytes podssh would put on the wire**
//! against **the exact bytes the relay's published contract requires**. E02's
//! `Prove` block says why, and it says it about this file:
//!
//! > ⛔ **The framing tests must be byte-exact.** Assert the exact bytes on the
//! > wire for a node frame, an operator frame, and a forward frame. ⛔ **A test
//! > that only checks that "something was sent" cannot catch this class of bug**,
//! > because the failure is that the right bytes were sent in the wrong
//! > direction.
//!
//! ⛔ **These tests need no network and no credential**, which is not a
//! convenience: the relay accepts no inbound TCP (**READ**, live spec line 222:
//! *"no inbound TCP (inbound raw TCP to a Worker is platform-impossible)"*), so a
//! codec that could only be exercised through a socket would be a codec with no
//! test at all.

use podssh_transport::control;
use podssh_transport::framing::legs::{
    chunk_for_bare, chunk_for_node, decode_node_frame, encode_forward_frame, encode_node_frame,
    encode_operator_frame,
};
use podssh_transport::framing::{
    CodecError, SessionId, CONTROL_FRAME_MAX, NODE_FRAME_MAX_WIRE, NODE_PAYLOAD_MAX,
    OPERATOR_PAYLOAD_MAX, SESSION_ID_LEN,
};

mod common;
use common::{block_on, id, ID_HEX};

fn id_bytes() -> Vec<u8> {
    ID_HEX.as_bytes().to_vec()
}

// ── the node frame: id and payload, ONE frame ───────────────────────────────

#[test]
fn a_node_frame_is_the_id_then_the_payload_byte_for_byte() {
    // ⛔ **The SSH version banner**, the first bytes that ever cross this path.
    let banner: &[u8] = b"SSH-2.0-podssh_0.1.0\r\n";
    let frame = encode_node_frame(&id(), banner).expect("a banner is nowhere near the cap");

    // ⛔ **Byte-exact.** Asserted as two concrete literals, not as a length and
    // a prefix: a length-plus-prefix assertion passes when the payload is
    // reordered, and reordering an SSH banner is a silent corruption.
    let mut expected = id_bytes();
    expected.extend_from_slice(banner);
    assert_eq!(frame, expected, "the node frame is id || payload, in that order");
    assert_eq!(frame.len(), SESSION_ID_LEN + banner.len());
}

#[test]
fn a_node_frame_ends_in_exactly_the_payload_and_nothing_else() {
    let payload = b"\x00\x00\x00\x0cssh-userauth\0podssh";
    let frame = encode_node_frame(&id(), payload).unwrap();
    assert_eq!(
        &frame[SESSION_ID_LEN..],
        payload,
        "the relay strips the first 32 bytes and hands the operator everything \
         after them; anything appended would arrive as session data"
    );
    assert_eq!(&frame[..SESSION_ID_LEN], ID_HEX.as_bytes());
}

#[test]
fn a_node_frame_with_an_empty_payload_is_exactly_the_id() {
    let frame = encode_node_frame(&id(), b"").unwrap();
    assert_eq!(frame, id_bytes());
    assert_eq!(frame.len(), SESSION_ID_LEN, "spec line 182: under 32 bytes is 1009");
}

#[test]
fn decode_node_frame_round_trips_the_exact_bytes() {
    let payload: Vec<u8> = (0u8..=255).collect();
    let frame = encode_node_frame(&id(), &payload).unwrap();
    let (got_id, got_payload) = decode_node_frame(&frame).expect("a frame we just built");
    assert_eq!(got_id.as_bytes(), ID_HEX.as_bytes());
    assert_eq!(got_payload, payload.as_slice(), "payload survives byte for byte");
}

#[test]
fn a_node_frame_at_the_wire_cap_is_exactly_65568_bytes() {
    // ⛔ **READ**, live spec line 182: *"over 65568 (32-byte id plus 65536
    // payload)"*. ⛔ **65536 + 32 EQUALS 65568** — the earlier claim that it
    // overflowed does not compute, and `05-risk-and-open.md` R3 records it.
    let frame = encode_node_frame(&id(), &vec![b'x'; NODE_PAYLOAD_MAX]).unwrap();
    assert_eq!(frame.len(), NODE_FRAME_MAX_WIRE);
    assert_eq!(frame.len(), 65568);
    assert_eq!(32 + NODE_PAYLOAD_MAX, NODE_FRAME_MAX_WIRE);
}

#[test]
fn a_node_payload_one_byte_over_the_cap_is_refused_not_truncated() {
    // ⛔ **Refused, never truncated.** A silent truncation here drops the tail of
    // an SSH message and the session fails later with a protocol error that
    // names nothing useful.
    let err = encode_node_frame(&id(), &vec![b'x'; NODE_PAYLOAD_MAX + 1])
        .expect_err("one byte over the cap must be refused");
    match err {
        CodecError::FrameTooLong { got, max } => {
            assert_eq!(got, SESSION_ID_LEN + NODE_PAYLOAD_MAX + 1);
            assert_eq!(max, NODE_FRAME_MAX_WIRE);
        }
        other => panic!("the cap must answer with FrameTooLong, got {other:?}"),
    }
    assert_eq!(err.relay_close_code(), Some(1009), "spec line 182 is a 1009");
}

#[test]
fn a_frame_under_32_bytes_is_the_planted_defect_the_relay_closes_1009_on() {
    let err = decode_node_frame(&[b'a'; 31]).expect_err("31 bytes cannot carry an id");
    match err {
        CodecError::FrameTooShort { got } => assert_eq!(got, 31),
        other => panic!("a short frame must answer FrameTooShort, got {other:?}"),
    }
    assert_eq!(err.relay_close_code(), Some(1009));
    assert!(err.spec_row().contains("bad multiplex frame"), "{}", err.spec_row());
}

#[test]
fn a_frame_whose_prefix_is_not_hex_is_1003_not_1009() {
    // ⛔ **Two different faults, two different codes.** A 32-byte prefix of
    // non-hex is `1003 bad multiplex id` (spec line 176) — the length is right,
    // so it is not the `1009 bad multiplex frame` of spec line 182.
    let mut frame = vec![b'z'; SESSION_ID_LEN];
    frame.extend_from_slice(b"payload");
    let err = decode_node_frame(&frame).expect_err("'z' is not hex");
    assert_eq!(err.relay_close_code(), Some(1003));
    assert_eq!(err.spec_row(), "spec line 176 | 1003 | bad multiplex id | node");
}

#[test]
fn an_uppercase_id_is_refused_because_spec_lines_141_and_143_pin_lowercase() {
    let upper = "0123456789ABCDEF0123456789ABCDEF";
    let err = SessionId::parse(upper.as_bytes()).expect_err("uppercase is not lowercase hex");
    match err {
        CodecError::SessionIdNotLowercaseHex { index, byte } => {
            assert_eq!(index, 10, "the first uppercase character");
            assert_eq!(byte, b'A');
        }
        other => panic!("expected SessionIdNotLowercaseHex, got {other:?}"),
    }
    assert_eq!(err.relay_close_code(), Some(1003));
}

// ── the operator frame: bare, and the type has nowhere to put an id ─────────

#[test]
fn an_operator_frame_is_bare_payload_byte_for_byte() {
    let banner: &[u8] = b"SSH-2.0-podssh_0.1.0\r\n";
    let frame = encode_operator_frame(banner).expect("a banner is under the cap");
    assert_eq!(
        frame, banner,
        "the operator leg carries NO framing: spec lines 145-148, the relay \
         'treats the whole frame as payload'"
    );
    assert_eq!(frame.len(), banner.len());
}

#[test]
fn an_operator_frame_has_no_prefix_even_when_the_payload_is_32_bytes_of_hex() {
    // ⛔ **The adversarial case, and the one a length assertion cannot catch.**
    // A payload that is itself 32 hex characters is indistinguishable from a
    // prefix by length alone; only a byte-exact comparison tells them apart, and
    // the relay cannot tell them apart either — which is the hazard.
    let looks_like_an_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let frame = encode_operator_frame(looks_like_an_id.as_bytes()).unwrap();
    assert_eq!(frame, looks_like_an_id.as_bytes());
    assert_eq!(frame.len(), 32, "32 bytes, and NOT an id: nothing was prepended");
    assert_eq!(frame.iter().filter(|b| **b == b'a').count(), 32);
}

#[test]
fn an_operator_payload_at_the_cap_is_accepted_and_one_byte_over_is_1009() {
    // ⛔ **READ**, live spec line 184: *"One operator frame exceeded 65536
    // payload bytes."* ⛔ **This is the OPERATOR cap and not the node one**, and
    // the two are the same number for different reasons — which is why they are
    // two constants and one of the two tests asserts each.
    assert_eq!(encode_operator_frame(&vec![b'x'; OPERATOR_PAYLOAD_MAX]).unwrap().len(), 65536);

    let err = encode_operator_frame(&vec![b'x'; OPERATOR_PAYLOAD_MAX + 1])
        .expect_err("65537 is over the operator cap");
    match err {
        CodecError::OperatorPayloadTooLong { got, max } => {
            assert_eq!(got, 65537);
            assert_eq!(max, 65536);
        }
        other => panic!("expected OperatorPayloadTooLong, got {other:?}"),
    }
    assert_eq!(err.relay_close_code(), Some(1009));
    assert_eq!(err.spec_row(), "spec line 184 | 1009 | frame byte cap | operator");
}

// ── the forward frame: bare, and no id, and a cap that is read not compiled ─

#[test]
fn a_forward_frame_is_bare_payload_byte_for_byte() {
    let banner: &[u8] = b"SSH-2.0-OpenSSH_9.6\r\n";
    let frame = encode_forward_frame(banner, podssh_transport::endpoint::FORWARD_MAX_FRAME_MEASURED)
        .unwrap();
    assert_eq!(frame, banner, "no id, no framing, no subprotocol wrapper");
}

#[test]
fn the_forward_cap_is_a_value_not_a_constant() {
    // ⛔ **There is no `hello` frame on the forward path**, so nothing on the
    // wire can tell a client the cap and a compiled constant is a number nothing
    // could correct. ⛔ The test proves the cap is an input: a caller passing a
    // smaller value gets a smaller cap.
    assert!(encode_forward_frame(&[b'x'; 1024], 1024).is_ok());
    assert!(encode_forward_frame(&[b'x'; 1025], 1024).is_err());
}

// ── chunking: each chunk repeats the full id ────────────────────────────────

#[test]
fn a_node_chunk_repeats_the_full_id_on_every_frame() {
    // ⛔ **The relay strips exactly one 32-byte prefix PER FRAME** — READ,
    // `dropssh` `src/serve.c:387-391`. A second chunk without an id is
    // `1009 bad multiplex frame`, so this asserts the prefix is on *each*.
    let payload = vec![b'y'; NODE_PAYLOAD_MAX * 2];
    let frames = chunk_for_node(&id(), &payload).expect("2x the payload is 2 frames");
    assert_eq!(frames.len(), 2);
    for (index, frame) in frames.iter().enumerate() {
        assert_eq!(frame.len(), NODE_FRAME_MAX_WIRE, "frame {index} is full");
        assert_eq!(&frame[..SESSION_ID_LEN], ID_HEX.as_bytes(), "frame {index} carries the id");
        let (got, body) = decode_node_frame(frame).expect("frame {index} decodes");
        assert_eq!(got.as_bytes(), ID_HEX.as_bytes());
        assert_eq!(body.len(), NODE_PAYLOAD_MAX);
    }
    // ⛔ And the payloads reassemble to what went in, in order.
    let joined: Vec<u8> = frames.iter().flat_map(|f| f[SESSION_ID_LEN..].to_vec()).collect();
    assert_eq!(joined, payload);
}

#[test]
fn an_empty_node_stream_still_emits_one_id_only_frame() {
    // ⛔ **A zero-length frame is legal on the node leg** because it is 32 bytes
    // long — spec line 182 closes *"under 32 bytes"*, and 32 is not under 32.
    let frames = chunk_for_node(&id(), b"").unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0], id_bytes());
}

#[test]
fn bare_chunking_splits_on_size_and_never_on_a_boundary() {
    let payload: Vec<u8> = (0..70000u32).map(|n| n as u8).collect();
    let frames = chunk_for_bare(&payload, OPERATOR_PAYLOAD_MAX).unwrap();
    assert_eq!(frames.len(), 2);
    let joined: Vec<u8> = frames.concat();
    assert_eq!(joined, payload, "chunking is lossless");
    for frame in &frames {
        assert!(frame.len() <= OPERATOR_PAYLOAD_MAX);
    }
}

// ── the control channel: JSON text, byte-exact ─────────────────────────────

#[test]
fn a_ready_control_frame_is_exactly_this_json() {
    let bytes = control::ready(&id()).expect("a ready is far under 4 KiB");
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        r#"{"type":"ready","id":"0123456789abcdef0123456789abcdef"}"#,
        "⛔ byte-exact: the control frame is a contract too, and a key order or \
         a missing field is a frame the relay parses differently"
    );
}

#[test]
fn a_close_control_frame_omits_an_absent_reason() {
    let bytes = control::close(&id(), None).unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        r#"{"type":"close","id":"0123456789abcdef0123456789abcdef"}"#
    );
    let with_reason = control::close(&id(), Some("target refused")).unwrap();
    assert_eq!(
        std::str::from_utf8(&with_reason).unwrap(),
        r#"{"type":"close","id":"0123456789abcdef0123456789abcdef","reason":"target refused"}"#
    );
}

#[test]
fn a_control_frame_over_4_kib_is_refused_with_the_control_cap() {
    // ⛔ **4 KiB is the CONTROL cap** (spec line 181) and ⛔ **not** the 123-byte
    // close-reason cap (spec line 192). They are different bounds and
    // `reverse-node.md:53-57` records the conflation as a correction.
    //
    // A `reject` keeps the node's whole reason (spec line 192: the relay cuts
    // only the reason of its own Close, and "the `reject` text frame preserves
    // the full reason"): 200 bytes go out whole. A reason of kilobytes is cut
    // until the frame fits the control cap, so the builder never makes a frame
    // that the relay closes with `1009`.
    let long = "r".repeat(200);
    let built = control::reject(&id(), &long).expect("200 bytes fit");
    assert!(String::from_utf8(built).unwrap().contains(&long), "the whole reason");
    let huge = "é".repeat(CONTROL_FRAME_MAX);
    for built in [control::reject(&id(), &huge).expect("cut to fit"), control::close(&id(), Some(&huge)).expect("cut to fit")] {
        assert!(built.len() <= CONTROL_FRAME_MAX, "{} bytes", built.len());
        assert!(std::str::from_utf8(&built).is_ok(), "no code point was split");
    }
    // The cut for display still binds on 100 characters for ASCII.
    let text = control::truncate_reason(&"r".repeat(CONTROL_FRAME_MAX));
    assert_eq!(text.len(), 100, "⛔ 100 chars of ASCII is 100 bytes, under the 123 bound");
    assert_eq!(control::CONTROL_MAX, CONTROL_FRAME_MAX, "one number, two names");

    // ⛔ **And the cap IS enforced when a frame really is over it**, proved
    // through `Leg::send_control`, which checks the bound on the bytes it is
    // handed.
    let mut leg = podssh_transport::socket::Leg::new(
        podssh_transport::socket::FrameQueue::new(),
        podssh_transport::LegShape::ReverseNode,
        podssh_transport::Limits::reverse_node(),
    );
    let oversize = vec![b'x'; CONTROL_FRAME_MAX + 1];
    let err = block_on(leg.send_control(&oversize)).expect_err("4097 is over the cap");
    assert!(
        err.to_string().contains("over the 4096 cap"),
        "expected the control cap, got {err}"
    );
    assert_eq!(leg.sent_frames(), 0, "⛔ a refused frame must not reach the wire");
}

#[test]
fn a_reason_is_truncated_on_a_character_boundary_and_on_both_bounds() {
    // ⛔ **READ**, live spec line 192: *"limited to 100 chars and 123 UTF-8
    // bytes without splitting a code point"*. Both bounds, and a byte index
    // that lands mid-character would produce invalid UTF-8 — the one thing that
    // sentence is careful about.
    let multi = "é".repeat(100); // 2 bytes each = 200 bytes, 100 chars
    let cut = control::truncate_reason(&multi);
    assert!(cut.len() <= 123);
    assert!(cut.chars().count() <= 100);
    assert!(std::str::from_utf8(cut.as_bytes()).is_ok(), "no code point was split");

    let ascii = "x".repeat(300); // 300 bytes, 300 chars: the CHAR bound binds
    let cut = control::truncate_reason(&ascii);
    assert_eq!(cut.len(), 100, "the 100-char bound binds before the byte bound");

    let short = "connection refused";
    assert_eq!(control::truncate_reason(short), short, "a short reason is untouched");
}

#[test]
fn control_frames_round_trip_through_the_parser() {
    let open = br#"{"type":"open","id":"0123456789abcdef0123456789abcdef"}"#;
    match control::parse_inbound(open).expect("an open parses") {
        control::NodeInbound::Open { id } => {
            assert_eq!(id, ID_HEX);
        }
        other => panic!("expected Open, got {other:?}"),
    }
    let reject = br#"{"type":"reject","id":"0123456789abcdef0123456789abcdef","reason":"nope"}"#;
    match control::parse_operator_control(reject).expect("a reject parses") {
        control::NodeOutbound::Reject { id, reason } => {
            assert_eq!(id, ID_HEX);
            assert_eq!(reason, "nope");
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn an_unknown_control_type_is_parsed_rather_than_dropped() {
    // ⛔ **Spec line 175 answers `1003 unknown control type`,** so a message with a
    // type podssh does not model is a *fault to report*, not a frame to discard.
    // A frame that vanished would look like a relay that stopped talking.
    let bytes = br#"{"type":"future","id":"0123456789abcdef0123456789abcdef"}"#;
    match control::parse_inbound(bytes).expect("serde must not error on an unknown type") {
        control::NodeInbound::Unknown => {}
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn a_hello_with_fields_podssh_does_not_model_still_parses() {
    // ⛔ **`01-relay-protocol.md:501-506` records that the relay deletes prose
    // between versions.** A client that errors on an added field is a client that
    // turns a rewording into an outage, and this is the direction that fails.
    let bytes = br#"{"type":"hello","version":1,"maxSessions":64,"maxFrameBytes":65536,"future":7}"#;
    match control::parse_inbound(bytes).expect("an extra field must not fail the parse") {
        control::NodeInbound::Hello(hello) => {
            assert_eq!(hello.max_sessions, Some(64));
            assert_eq!(hello.max_frame_bytes, Some(65536));
            assert_eq!(hello.extra.get("future"), Some(&serde_json::json!(7)));
        }
        other => panic!("expected Hello, got {other:?}"),
    }
}

#[test]
fn limits_apply_whatever_hello_says_and_clamp_it_to_the_published_wire_maximum() {
    let mut limits = control::NodeLimits::conservative();
    let hello = control::Hello {
        max_sessions: Some(64),
        max_frame_bytes: Some(65536),
        ..Default::default()
    };
    limits.apply(&hello);
    assert_eq!(limits.max_sessions, 64);
    assert_eq!(limits.max_frame_bytes, 65536);

    // ⛔ **A `hello` claiming more than the published cap is clamped down**, not
    // obeyed: the relay's table is the contract and a `hello` is a hint read off
    // the wire.
    let greedy = control::Hello {
        max_frame_bytes: Some(1 << 20),
        ..Default::default()
    };
    limits.apply(&greedy);
    assert_eq!(limits.max_frame_bytes, NODE_PAYLOAD_MAX as u64, "clamped to the payload cap");

    // ⛔ **A zero is refused outright** rather than accepted as "send nothing".
    let zero = control::Hello { max_sessions: Some(0), max_frame_bytes: Some(0), ..Default::default() };
    limits.apply(&zero);
    assert_eq!(limits.max_sessions, 64, "zero does not become the limit");
    assert_eq!(limits.max_frame_bytes, NODE_PAYLOAD_MAX as u64, "clamped to the payload cap");
}