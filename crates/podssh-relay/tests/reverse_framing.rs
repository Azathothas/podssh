//! The framing of the reverse legs, byte for byte: each assertion compares the
//! bytes that podssh would put on the wire with the bytes that the relay's
//! contract requires. A test that checks only that something was sent misses
//! the right bytes sent the wrong way. No network: the relay takes no inbound
//! TCP, so a codec tested only through a socket would have no test at all.
#![cfg(feature = "pair")]

use podssh_relay::reverse::control;
use podssh_relay::reverse::framing::legs::{
    chunk_for_bare, chunk_for_node, decode_node_frame, encode_node_frame, encode_operator_frame,
};
use podssh_relay::reverse::framing::{
    CodecError, SessionId, CONTROL_FRAME_MAX, NODE_FRAME_MAX_WIRE, NODE_PAYLOAD_MAX, OPERATOR_PAYLOAD_MAX,
    SESSION_ID_LEN,
};

/// A session id written out: a repeated digit is the shape of a mistake, and
/// would hide one.
const ID_HEX: &str = "0123456789abcdef0123456789abcdef";

fn id() -> SessionId {
    SessionId::parse(ID_HEX.as_bytes()).expect("the test id is 32 lowercase hex")
}

fn id_bytes() -> Vec<u8> {
    ID_HEX.as_bytes().to_vec()
}

// The node frame: the id and the payload, in one frame.

#[test]
fn a_node_frame_is_the_id_then_the_payload_byte_for_byte() {
    // The SSH banner: the first bytes that cross this path.
    let banner: &[u8] = b"SSH-2.0-podssh_0.1.0\r\n";
    let frame = encode_node_frame(&id(), banner).expect("a banner is nowhere near the cap");
    // Two literals, not a length and a prefix, which pass for a payload in
    // the wrong order.
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
    assert_eq!(frame.len(), SESSION_ID_LEN, "under 32 bytes is 1009; 32 is not under 32");
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
    // The 32-byte id and 65536 bytes of payload: 65568 exactly, no overflow.
    let frame = encode_node_frame(&id(), &vec![b'x'; NODE_PAYLOAD_MAX]).unwrap();
    assert_eq!(frame.len(), NODE_FRAME_MAX_WIRE);
    assert_eq!(frame.len(), 65568);
    assert_eq!(32 + NODE_PAYLOAD_MAX, NODE_FRAME_MAX_WIRE);
}

#[test]
fn a_node_payload_one_byte_over_the_cap_is_refused_not_truncated() {
    // Refused, never cut: a cut drops the tail of an SSH message, and the
    // session fails later with an error that names nothing useful.
    let err = encode_node_frame(&id(), &vec![b'x'; NODE_PAYLOAD_MAX + 1]).expect_err("one byte over the cap must be refused");
    match err {
        CodecError::FrameTooLong { got, max } => {
            assert_eq!(got, SESSION_ID_LEN + NODE_PAYLOAD_MAX + 1);
            assert_eq!(max, NODE_FRAME_MAX_WIRE);
        }
        other => panic!("the cap must answer with FrameTooLong, got {other:?}"),
    }
    assert_eq!(err.relay_close_code(), Some(1009), "the relay closes it with 1009");
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
    // Two faults, two codes: 32 bytes of a prefix that is not hex have the
    // right length, so they are `1003 bad multiplex id`, not `1009`.
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

// The operator frame: bare payload, with no place for an id.

#[test]
fn an_operator_frame_is_bare_payload_byte_for_byte() {
    let banner: &[u8] = b"SSH-2.0-podssh_0.1.0\r\n";
    let frame = encode_operator_frame(banner).expect("a banner is under the cap");
    assert_eq!(frame, banner, "the operator leg carries no framing: the relay treats the whole frame as payload");
    assert_eq!(frame.len(), banner.len());
}

#[test]
fn an_operator_frame_has_no_prefix_even_when_the_payload_is_32_bytes_of_hex() {
    // A payload of 32 hex characters looks like a prefix by its length; only
    // the bytes tell them apart, and the relay cannot tell them apart either.
    let looks_like_an_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let frame = encode_operator_frame(looks_like_an_id.as_bytes()).unwrap();
    assert_eq!(frame, looks_like_an_id.as_bytes());
    assert_eq!(frame.len(), 32, "32 bytes, and NOT an id: nothing was prepended");
    assert_eq!(frame.iter().filter(|b| **b == b'a').count(), 32);
}

#[test]
fn an_operator_payload_at_the_cap_is_accepted_and_one_byte_over_is_1009() {
    // The operator's cap, not the node's: one number for two reasons.
    assert_eq!(encode_operator_frame(&vec![b'x'; OPERATOR_PAYLOAD_MAX]).unwrap().len(), 65536);
    let err = encode_operator_frame(&vec![b'x'; OPERATOR_PAYLOAD_MAX + 1]).expect_err("65537 is over the operator cap");
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

// Chunks: each one with the whole id.

#[test]
fn a_node_chunk_repeats_the_full_id_on_every_frame() {
    // The relay strips one prefix from each frame: a chunk with no id is
    // `1009 bad multiplex frame`, so each frame is checked.
    let payload = vec![b'y'; NODE_PAYLOAD_MAX * 2];
    let frames = chunk_for_node(&id(), &payload).expect("2x the payload is 2 frames");
    assert_eq!(frames.len(), 2);
    for (index, frame) in frames.iter().enumerate() {
        assert_eq!(frame.len(), NODE_FRAME_MAX_WIRE, "frame {index} is full");
        assert_eq!(&frame[..SESSION_ID_LEN], ID_HEX.as_bytes(), "frame {index} carries the id");
        let (got, body) = decode_node_frame(frame).expect("each frame decodes");
        assert_eq!(got.as_bytes(), ID_HEX.as_bytes());
        assert_eq!(body.len(), NODE_PAYLOAD_MAX);
    }
    let joined: Vec<u8> = frames.iter().flat_map(|f| f[SESSION_ID_LEN..].to_vec()).collect();
    assert_eq!(joined, payload, "the payloads come back in order");
}

#[test]
fn an_empty_node_stream_still_emits_one_id_only_frame() {
    // Legal on the node leg: 32 bytes long, and the relay closes under 32.
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

// The control channel: JSON text, byte for byte.

#[test]
fn a_ready_control_frame_is_exactly_this_json() {
    let bytes = control::ready(&id()).expect("a ready is far under 4 KiB");
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        r#"{"type":"ready","id":"0123456789abcdef0123456789abcdef"}"#,
        "a control frame is a contract too: a key order or a missing field is a frame the relay reads differently"
    );
}

#[test]
fn a_close_control_frame_omits_an_absent_reason() {
    let bytes = control::close(&id(), None).unwrap();
    assert_eq!(std::str::from_utf8(&bytes).unwrap(), r#"{"type":"close","id":"0123456789abcdef0123456789abcdef"}"#);
    let with_reason = control::close(&id(), Some("target refused")).unwrap();
    assert_eq!(
        std::str::from_utf8(&with_reason).unwrap(),
        r#"{"type":"close","id":"0123456789abcdef0123456789abcdef","reason":"target refused"}"#
    );
}

#[test]
fn a_control_frame_over_4_kib_is_refused_with_the_control_cap() {
    // 4 KiB is the control cap, not the cut of a Close's reason. A `reject`
    // keeps the node's whole reason, as the relay forwards it whole: 200 bytes
    // go out whole. A reason of kilobytes is cut until the frame fits, so the
    // builder never makes a frame that the relay closes with `1009`.
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
    assert_eq!(text.len(), 100, "100 characters of ASCII are 100 bytes, under the 123 bound");
    assert_eq!(control::CONTROL_MAX, CONTROL_FRAME_MAX, "one number, two names");
    // And the cap holds for a frame that is over it.
    let oversize = control::NodeOutbound::Reject { id: ID_HEX.into(), reason: "x".repeat(CONTROL_FRAME_MAX) };
    let err = control::encode(&oversize).expect_err("over the cap");
    assert!(err.to_string().contains("over the 4096 cap"), "expected the control cap, got {err}");
}

#[test]
fn a_reason_is_truncated_on_a_character_boundary_and_on_both_bounds() {
    // The relay's cut: 100 characters and 123 bytes, without splitting a
    // character, which would make the text invalid UTF-8.
    let multi = "é".repeat(100); // 2 bytes each: 200 bytes, 100 characters
    let cut = control::truncate_reason(&multi);
    assert!(cut.len() <= 123);
    assert!(cut.chars().count() <= 100);
    assert!(std::str::from_utf8(cut.as_bytes()).is_ok(), "no code point was split");

    let ascii = "x".repeat(300); // 300 bytes and characters: the character bound binds
    let cut = control::truncate_reason(&ascii);
    assert_eq!(cut.len(), 100, "the 100-char bound binds before the byte bound");

    let short = "connection refused";
    assert_eq!(control::truncate_reason(short), short, "a short reason is untouched");
}

#[test]
fn control_frames_round_trip_through_the_parser() {
    let open = br#"{"type":"open","id":"0123456789abcdef0123456789abcdef"}"#;
    match control::parse_inbound(open).expect("an open parses") {
        control::NodeInbound::Open { id } => assert_eq!(id, ID_HEX),
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
    // The relay answers an unknown type with `1003 unknown control type`: a
    // fault to report, not a frame to discard; a frame that vanished would look
    // like a relay that stopped talking.
    let bytes = br#"{"type":"future","id":"0123456789abcdef0123456789abcdef"}"#;
    match control::parse_inbound(bytes).expect("serde must not error on an unknown type") {
        control::NodeInbound::Unknown => {}
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn a_hello_with_fields_podssh_does_not_model_still_parses() {
    // A client that fails on an added field turns a new version into an outage.
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
    let hello = control::Hello { max_sessions: Some(64), max_frame_bytes: Some(65536), ..Default::default() };
    limits.apply(&hello);
    assert_eq!(limits.max_sessions, 64);
    assert_eq!(limits.max_frame_bytes, 65536);
    // More than the published cap is clamped, not obeyed: the table is the
    // contract, and `hello` a hint.
    let greedy = control::Hello { max_frame_bytes: Some(1 << 20), ..Default::default() };
    limits.apply(&greedy);
    assert_eq!(limits.max_frame_bytes, NODE_PAYLOAD_MAX as u64, "clamped to the payload cap");
    // A zero is ignored, not read as "send nothing".
    let zero = control::Hello { max_sessions: Some(0), max_frame_bytes: Some(0), ..Default::default() };
    limits.apply(&zero);
    assert_eq!(limits.max_sessions, 64, "zero does not become the limit");
    assert_eq!(limits.max_frame_bytes, NODE_PAYLOAD_MAX as u64, "clamped to the payload cap");
}
