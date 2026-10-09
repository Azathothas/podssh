//! **RFC 6455, byte-exact, and E03's three plants as tests.**
//!
//! **The plants here are tests, not comments.** E03's `Prove` block requires
//! each of them to be *seen to fail*, and a plant described in prose is a
//! plant nobody runs. Each one asserts **which** check fired, so a defect that
//! reddened the suite for an unrelated reason cannot pass a plant that only
//! looked at the outcome.
//!
//! **Byte-exact means byte-exact.** An assertion that only checks "something
//! was sent" cannot catch the one bug this layer exists to prevent: the right
//! bytes in the wrong direction, or unmasked where RFC 6455 §5.3 requires a
//! mask.

use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::handshake;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── masking: RFC 6455 §5.3 ──────────────────────────────────────────────────

/// **The mask is `i % 4`, applied to the payload only.** This vector is the
/// one from §5.7's worked framing, so an implementation that applied the key
/// to the header, or with a different stride, produces different bytes and
/// fails here.
#[test]
fn the_mask_is_applied_with_a_four_byte_stride() {
    let key = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut data = b"Hello".to_vec();
    frame::apply_mask(&mut data, key);
    assert_eq!(hex(&data), "7f9f4d51 58".replace(' ', ""));
    frame::apply_mask(&mut data, key);
    assert_eq!(data, b"Hello", "the mask must be its own inverse");
}

#[test]
fn masking_is_its_own_inverse_at_every_length() {
    // **Starts at 1.** A zero-length payload masked with any key is still
    // zero-length, so "the bytes changed" cannot be asserted at 0 and a test
    // that tries is asserting nothing.
    for len in 1..64usize {
        let key = [0xABu8, 0xCD, 0xEF, 0x01];
        let original: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
        let mut data = original.clone();
        frame::apply_mask(&mut data, key);
        assert_ne!(data, original, "the mask did nothing at length {len}");
        frame::apply_mask(&mut data, key);
        assert_eq!(data, original, "round-trip failed at length {len}");
    }
}

/// **Every client frame carries the mask bit.** RFC 6455 §5.1 sets bit 0x80
/// of the second byte for a masked frame; §5.3 says a client MUST mask.
#[test]
fn every_encoded_client_frame_is_masked() {
    for len in [0usize, 1, 125, 126, 127, 200, 65_535, 65_536] {
        let payload = vec![0x5Au8; len];
        let encoded = frame::encode(
            &Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: payload.clone() },
            Role::Client,
            [1, 2, 3, 4],
        );
        assert_eq!(encoded[1] & 0x80, 0x80, "the mask bit is clear at length {len}");
        // **The payload on the wire must not be the payload**, or the mask
        // bit was set without transforming anything. Skipped at length 0,
        // where masking changes nothing and the assertion would be vacuous.
        if len > 0 {
            let header = 2 + header_extra(encoded[1] & 0x7f) + 4;
            assert_ne!(&encoded[header..], payload.as_slice(), "unmasked at length {len}");
        }
    }
}

/// **The other direction is equally a MUST-NOT.** RFC 6455 §5.1: a
/// server-to-client frame MUST NOT be masked. A client that accepted a masked
/// server frame would be reading bytes the relay never sent.
#[test]
fn a_server_frame_is_never_masked() {
    let payload = b"the relay copies bytes".to_vec();
    let encoded = frame::encode(
        &Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: payload.clone() },
        Role::Server,
        // A key is passed and must be IGNORED, or a caller could produce a
        // masked server frame by supplying one.
        [0xFF, 0xFF, 0xFF, 0xFF],
    );
    assert_eq!(encoded[1] & 0x80, 0, "a server frame was masked");
    assert_eq!(&encoded[2..], payload.as_slice(), "a server payload was masked");
}

/// **The three length encodings, at their boundaries.** 125 is the last
/// 7-bit length, 126 is the first 16-bit one, and 65536 is the first 64-bit
/// one. Getting a boundary wrong truncates or over-reads by exactly one frame.
#[test]
fn the_three_length_encodings_appear_at_their_boundaries() {
    // Payload sizes only, and the second and third numbers this tuple used
    // to carry were never read — the expected marker and the expected header
    // size are DERIVED below from `len`, which is the stronger assertion. An
    // unused field in a table reads as an unfinished edit.
    let cases: &[usize] = &[125, 126, 65_535, 65_536];
    for len in cases {
        let encoded = frame::encode(
            &Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: vec![0u8; *len] },
            Role::Client,
            [0, 0, 0, 0],
        );
        let marker = encoded[1] & 0x7f;
        let expected = match len {
            n if *n < 126 => *n as u8,
            n if *n <= u16::MAX as usize => frame::LENGTH_16_MARKER,
            _ => frame::LENGTH_64_MARKER,
        };
        assert_eq!(marker, expected, "wrong length marker at {len}");
        assert_eq!(encoded.len(), len + 2 + 4 + header_extra(expected));
    }
}

fn header_extra(marker: u8) -> usize {
    match marker {
        frame::LENGTH_16_MARKER => 2,
        frame::LENGTH_64_MARKER => 8,
        _ => 0,
    }
}

// ── decode ──────────────────────────────────────────────────────────────────

#[test]
fn a_decoded_frame_is_the_frame_that_was_encoded() {
    let original =
        Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: b"\x00\x00\x00\x15SSH-2.0-podssh".to_vec() };
    // **Client to client**: encoded masked, decoded with the same role. This
    // is the path podssh's own frames take, and it is the one that proves the
    // mask is reversible.
    let encoded = frame::encode(&original, Role::Client, [0xDE, 0xAD, 0xBE, 0xEF]);
    let (decoded, used) = frame::decode(&encoded, Role::Client).expect("decode").expect("a frame");
    assert_eq!(decoded, original);
    assert_eq!(used, encoded.len());

    // And the relay's direction: a server frame round-trips unmasked.
    let from_server = frame::encode(&original, Role::Server, [0, 0, 0, 0]);
    let (back, used) = frame::decode(&from_server, Role::Server).expect("decode").expect("a frame");
    assert_eq!(back, original);
    assert_eq!(used, from_server.len());
}

#[test]
fn a_short_buffer_is_incomplete_not_an_error() {
    let encoded = frame::encode(
        &Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: vec![1, 2, 3, 4, 5] },
        Role::Client,
        [9, 8, 7, 6],
    );
    // **Every prefix shorter than a whole frame is `Ok(None)`.** A stream
    // arrives in pieces, and a decoder that errored on a partial frame would
    // break every read.
    for cut in 0..encoded.len() {
        assert_eq!(
            frame::decode(&encoded[..cut], Role::Client),
            Ok(None),
            "a {cut}-byte prefix was not reported as incomplete"
        );
    }
    assert!(frame::decode(&encoded, Role::Client).expect("decode").is_some());
}

// ── PLANT 3: an unparseable frame mid-stream ────────────────────────────────

/// **E03's third plant: an unparseable frame must produce a clean error, not
/// a panic.**
///
/// The frame below has a reserved bit set (`0x40` in the first byte) with no
/// extension negotiated. A decoder that ignored RSV bits would hand a
/// compressed payload to the SSH layer as if it were raw bytes — and that is
/// exactly what E02's byte-exact framing tests exist to catch one layer up.
#[test]
fn plant_unparseable_frame_mid_stream_is_a_clean_error_not_a_panic() {
    let mut stream = vec![0x82u8, 0x80, 1, 2, 3, 4, 0]; // 0x42 => RSV1 set
    stream[0] = 0xC2; // FIN + RSV1 + binary

    let result = frame::decode(&stream, Role::Server);
    match result {
        Err(podssh_ws::WsError::Frame(why)) => {
            assert!(why.contains("reserved"), "the error must name the actual fault, got: {why}");
        }
        other => panic!("a reserved bit must be an error, got {other:?}"),
    }
}

/// **The same frame arriving *after* a good one is still an error, and the
/// good one is still delivered first.** This is the "mid-stream" half of the
/// plant: a decoder that dropped the whole buffer on a bad frame would lose a
/// valid message, and one that panicked would lose the session.
#[test]
fn plant_an_unparseable_frame_after_a_good_one_keeps_the_good_one() {
    let good = frame::encode(
        &Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: b"first".to_vec() },
        Role::Server,
        [1, 1, 1, 1],
    );
    let mut stream = good.clone();
    // A frame with RSV1 set, appended after a valid one.
    stream.extend_from_slice(&[0xC2, 0x80, 0, 0, 0, 0, 0x7F]);

    let (first, used) = frame::decode(&stream, Role::Server).expect("decode").expect("a frame");
    assert_eq!(first.payload, b"first");
    let rest = &stream[used..];
    assert!(frame::decode(rest, Role::Server).is_err(), "the malformed second frame was accepted");
}

#[test]
fn an_undefined_opcode_is_an_error() {
    // 0x3 is reserved and undefined in RFC 6455 §5.2.
    let err = frame::decode(&[0x83, 0x00], Role::Server).expect_err("opcode 0x3 is undefined");
    assert!(format!("{err}").contains("opcode"), "got {err}");
}

/// **Direction is enforced.** A client-to-server frame MUST be masked
/// (RFC 6455 §5.3) and a server-to-client frame MUST NOT be (§5.1). These two
/// tests are the wire-level form of E03's masking requirement: the encoder
/// sets the bit, and the decoder refuses a frame that is wrong for its
/// direction.
#[test]
fn an_unmasked_client_to_server_frame_is_rejected() {
    let unmasked = [0x82u8, 0x03, b'a', b'b', b'c'];
    let err = frame::decode(&unmasked, Role::Client).expect_err("an unmasked client frame");
    assert!(format!("{err}").contains("not masked"), "got {err}");
}

#[test]
fn a_masked_server_to_client_frame_is_rejected() {
    let masked = [0x82u8, 0x83, 1, 2, 3, 4, 0];
    let err = frame::decode(&masked, Role::Server).expect_err("a masked server frame");
    assert!(format!("{err}").contains("masked"), "got {err}");
}

/// **A frame claiming more than the relay's forward cap is refused before
/// anything is allocated.** The cap is 262144, re-measured from `/relays.json`
/// on 2026-10-02; a 64-bit length of 2^32 would otherwise become a
/// four-gigabyte `Vec::with_capacity`.
#[test]
fn a_frame_beyond_the_forward_cap_is_refused() {
    let mut header = vec![0x82u8, 0x80 | frame::LENGTH_64_MARKER];
    header.extend_from_slice(&(u32::MAX as u64).to_be_bytes());
    header.extend_from_slice(&[0, 0, 0, 0]);
    let err = frame::decode(&header, Role::Client).expect_err("a 4 GiB frame");
    assert!(format!("{err}").contains("forward cap"), "got {err}");
}

// ── the opening handshake ───────────────────────────────────────────────────

/// **RFC 6455 §1.3's worked example, byte for byte.** The key and the
/// accept value are the ones the RFC prints, which is the only check of this
/// that is not a round-trip with itself.
#[test]
fn the_accept_value_matches_rfc6455_section_1_3() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    assert_eq!(handshake::accept_key(key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

/// **The SHA-1 under `accept_key`, against FIPS 180-1's published values.**
/// RFC 6455 is the one place a modern client is *required* to compute SHA-1,
/// so the function is written here and asserted rather than pulled in.
#[test]
fn the_sha1_used_for_the_accept_value_is_correct() {
    assert_eq!(hex(&handshake::sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(hex(&handshake::sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    // **A message that crosses the 64-byte block boundary**, which is where
    // a padding bug hides.
    assert_eq!(
        hex(&handshake::sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
}

/// **The token is a header and the request has no query string.** Spec line
/// 61: *"URLs can appear in logs"*.
#[test]
fn the_token_travels_in_a_header_and_never_in_the_url() {
    let request = String::from_utf8(handshake::build_request(
        "tcp.ssh.relay.ajam.dev:443",
        "/v1/connect/railway",
        "tok-abc123",
        "dGhlIHNhbXBsZSBub25jZQ==",
    ))
    .expect("the request is ASCII");

    let request_line = request.lines().next().expect("a request line");
    assert_eq!(request_line, "GET /v1/connect/railway HTTP/1.1");
    assert!(!request_line.contains('?'), "the request line carries a query string: {request_line}");
    assert!(!request_line.contains("tok-abc123"), "the token is in the request line");
    assert!(request.contains("X-Relay-Token: tok-abc123\r\n"), "the token is not in the X-Relay-Token header");
    assert!(request.ends_with("\r\n\r\n"), "no header terminator");
    assert!(request.contains("Sec-WebSocket-Version: 13\r\n"));
    assert!(request.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
    assert!(request.contains("Upgrade: websocket\r\n"));
    assert!(request.contains("Connection: Upgrade\r\n"));
}

/// **No subprotocol is offered.** Spec line 172 says "no subprotocol", and
/// `Sec-WebSocket-Protocol` is *absent* rather than empty: the two are
/// different on the wire and a relay that compares strings sees them
/// differently.
#[test]
fn no_subprotocol_is_offered() {
    let request = String::from_utf8(handshake::build_request("h:443", "/x", "t", "k")).unwrap();
    assert!(!request.to_ascii_lowercase().contains("sec-websocket-protocol"), "a subprotocol was offered:\n{request}");
}

/// **The configuration refuses a path with a query string**, so there is no
/// code path by which a token could reach a URL.
#[test]
fn a_path_with_a_query_string_is_refused() {
    let config = podssh_ws::WsClientConfig {
        endpoint: podssh_ws::Endpoint {
            host: "relay.example".into(),
            port: 443,
            path: "/v1/connect/railway?token=SECRET".into(),
        },
        trust: podssh_ws::Trust::File("/nonexistent/podssh-ca.pem".into()),
        server_name: "relay.example".into(),
        timeout: std::time::Duration::from_secs(1),
        idle_timeout: None,
        proxy: podssh_ws::ProxyChoice::Direct,
    };
    let err = config.validate().expect_err("a query string must be refused");
    assert!(err.contains("query string"), "got {err}");
    // And the message must not echo the secret back.
    assert!(!err.contains("SECRET"), "the error leaked the token: {err}");
}

#[test]
fn a_valid_configuration_passes_validation() {
    let config = podssh_ws::WsClientConfig {
        endpoint: podssh_ws::Endpoint { host: "relay.example".into(), port: 443, path: "/v1/connect/railway".into() },
        trust: podssh_ws::Trust::Default,
        server_name: "relay.example".into(),
        timeout: std::time::Duration::from_secs(20),
        idle_timeout: None,
        proxy: podssh_ws::ProxyChoice::Direct,
    };
    config.validate().expect("a well-formed configuration");
}

// ── response checking ───────────────────────────────────────────────────────

#[test]
fn a_correct_101_response_is_accepted() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let head = "HTTP/1.1 101 Switching Protocols\r\n\
                Upgrade: websocket\r\n\
                Connection: Upgrade\r\n\
                Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    handshake::check_response(head, key).expect("a well-formed 101");
}

/// **The accept value is checked, not merely present.** Any cache can echo
/// a header; only the computed value proves a server read the request.
#[test]
fn a_101_with_the_wrong_accept_value_is_rejected() {
    let head = "HTTP/1.1 101 Switching Protocols\r\n\
                Upgrade: websocket\r\n\
                Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
    let err = handshake::check_response(head, "dGhlIHNhbXBsZSBub25jZQ==").expect_err("a wrong accept value");
    assert!(format!("{err}").contains("Sec-WebSocket-Accept"), "got {err}");
}

#[test]
fn a_101_without_the_upgrade_header_is_rejected() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let head =
        format!("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {}\r\n\r\n", handshake::accept_key(key));
    assert!(handshake::check_response(&head, key).is_err());
}

/// **The `426` and `403` distinction survives.** E03's `Decision` records
/// that a verifier measured `426` for a valid token with no upgrade and `403`
/// for no token — so authentication is checked before the upgrade and the two
/// failures are distinguishable. That is only true if the status is reported
/// rather than collapsed into "upgrade failed".
#[test]
fn the_status_code_survives_into_the_error() {
    for (status, label) in [(403u16, "403"), (426, "426")] {
        let head = format!("HTTP/1.1 {status} Forbidden\r\nContent-Length: 0\r\n\r\n");
        let err = handshake::check_response(&head, "k").expect_err("a non-101 status");
        match err {
            podssh_ws::WsError::Upgrade { status: got, .. } => assert_eq!(got, status),
            other => panic!("expected an upgrade error carrying {label}, got {other:?}"),
        }
    }
}

/// The relay's connect knobs are the one exception: `-4`/`-6` add
/// `?family=`, and `?dial=lazy`, `?path=` and `?precheck=` are documented
/// knobs. None can carry a secret; anything else is still refused.
#[test]
fn only_the_relays_connect_knobs_may_ride_in_the_path() {
    let config = |path: &str| podssh_ws::WsClientConfig {
        endpoint: podssh_ws::Endpoint { host: "relay.example".into(), port: 443, path: path.into() },
        trust: podssh_ws::Trust::File("/nonexistent/podssh-ca.pem".into()),
        server_name: "relay.example".into(),
        timeout: std::time::Duration::from_secs(1),
        idle_timeout: None,
        proxy: podssh_ws::ProxyChoice::Direct,
    };
    for ok in [
        "/connect/h/22?family=4",
        "/connect/h/22?family=6",
        "/connect/h/22?dial=lazy&precheck=0",
        "/connect/h/22?path=vpc",
    ] {
        assert!(config(ok).validate().is_ok(), "{ok} must be accepted");
    }
    for bad in [
        "/connect/h/22?family=5",
        "/connect/h/22?family=4&token=SECRET",
        "/connect/h/22?",
        "/connect/h/22?precheck=12345678",
        "/connect/h/22?dial=eager",
    ] {
        let err = config(bad).validate().expect_err(bad);
        assert!(!err.contains("SECRET"), "the error leaked a value: {err}");
    }
}
