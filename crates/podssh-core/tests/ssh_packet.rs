//! Task 1 tests: the packet codec is byte-exact and the banner parser refuses
//! what it must. Every assertion is on bytes — a framing test that checks
//! "something decoded" cannot catch a misframed stream.

use podssh_core::ssh::packet::{Decoder, MsgId, PacketError, encode_packet};
use podssh_core::ssh::version::{OUR_VERSION, our_banner, parse_version};

#[test]
fn encode_is_byte_exact_and_aligned() {
    // payload 5 + 1 length byte + padding: 4+1+5=10, next multiple of 8 is
    // 16, so padding 6 and packet_length 12. Hand-computed, not asserted
    // from the function's own output.
    let out = encode_packet(b"hello", 8);
    assert_eq!(out.len(), 16);
    assert_eq!(&out[0..4], &[0, 0, 0, 12]);
    assert_eq!(out[4], 6);
    assert_eq!(&out[5..10], b"hello");
}

#[test]
fn encode_respects_a_larger_block_size() {
    // payload 5, block 16: padding = 16 - ((4+1+5) % 16) = 6, legal, so
    // total 16 with packet_length 12 — hand-computed.
    let out = encode_packet(b"hello", 16);
    assert_eq!(out.len(), 16);
    assert_eq!(&out[0..4], &[0, 0, 0, 12]);
    assert_eq!(out[4], 6);
}

#[test]
fn encode_grows_padding_when_the_minimum_is_short() {
    // payload 6, block 8: 4+1+6=11, next multiple of 8 is 16, padding 5 —
    // legal (>= 4). payload 7: 4+1+7=12, next multiple 16, padding 4 —
    // exactly the minimum. payload 8: 4+1+8=13, next multiple 16, padding
    // 3 — ILLEGAL, so one more block: padding 11, total 24.
    let exact = encode_packet(b"1234567", 8);
    assert_eq!(exact[4], 4);
    let grown = encode_packet(b"12345678", 8);
    assert_eq!(grown[4], 11);
    assert_eq!(grown.len(), 24);
}

#[test]
fn decode_round_trips_split_at_every_offset() {
    // ⛔ The reassembly proof's shape: a frame boundary can land anywhere,
    // so the split is tried at every byte offset, not one lucky one.
    let wire = encode_packet(&[20, 1, 2, 3], 8);
    for at in 0..wire.len() {
        let mut d = Decoder::new();
        let first = d.push(&wire[..at], 8).unwrap();
        assert!(first.is_empty(), "offset {at}: a half packet produced {first:?}");
        let rest = d.push(&wire[at..], 8).unwrap();
        assert_eq!(rest.len(), 1, "offset {at}");
        assert_eq!(rest[0].payload, vec![20, 1, 2, 3]);
        assert_eq!(d.pending_len(), 0);
    }
}

#[test]
fn decode_emits_each_packet_once() {
    let a = encode_packet(b"aaa", 8);
    let b = encode_packet(b"bb", 8);
    let mut wire = Vec::new();
    wire.extend_from_slice(&a);
    wire.extend_from_slice(&b);
    let mut d = Decoder::new();
    let packets = d.push(&wire, 8).unwrap();
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].payload, b"aaa");
    assert_eq!(packets[1].payload, b"bb");
}

#[test]
fn decode_refuses_short_padding_and_drops_the_stream() {
    // padding_length 0: the payload end under-reports and bytes would leak
    // past the MAC — refused, and the buffer is cleared, not re-synced.
    let mut wire = encode_packet(b"hello", 8);
    wire[4] = 0;
    let mut d = Decoder::new();
    let err = d.push(&wire, 8).unwrap_err();
    assert_eq!(
        err,
        PacketError::BadPadding { padding_length: 0, packet_length: 12 }
    );
    assert_eq!(d.pending_len(), 0);
}

#[test]
fn decode_refuses_misalignment() {
    let mut wire = encode_packet(b"hello", 8);
    // Corrupt the length field: total no longer a multiple of 8. One extra
    // byte is appended so the decoder has the full 17-byte frame to judge —
    // without it this would read as NeedMore, which is a different fact.
    wire[3] += 1;
    wire.push(0);
    let mut d = Decoder::new();
    let err = d.push(&wire, 8).unwrap_err();
    assert!(matches!(err, PacketError::BadAlignment { .. }), "got {err}");
}

#[test]
fn decode_refuses_an_absurd_length() {
    let wire = [0xFFu8, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0];
    let mut d = Decoder::new();
    let err = d.push(&wire, 8).unwrap_err();
    assert!(matches!(err, PacketError::LengthTooLarge { .. }), "got {err}");
    assert_eq!(d.pending_len(), 0);
}

#[test]
fn message_ids_name_the_transport_layer() {
    assert_eq!(MsgId::of(20), Some(MsgId::KexInit));
    assert_eq!(MsgId::of(21), Some(MsgId::NewKeys));
    assert_eq!(MsgId::of(5), Some(MsgId::ServiceRequest));
    assert_eq!(MsgId::of(94), None);
}

#[test]
fn our_banner_is_crlf_terminated() {
    let banner = our_banner();
    assert!(banner.starts_with(OUR_VERSION.as_bytes()));
    assert!(banner.ends_with(b"\r\n"));
}

#[test]
fn version_parses_an_openssh_banner() {
    let (v, used) = parse_version(b"SSH-2.0-OpenSSH_10.3\r\n").unwrap();
    assert_eq!(v.proto, "2.0");
    assert_eq!(v.raw, "SSH-2.0-OpenSSH_10.3");
    assert_eq!(used, 22);
}

#[test]
fn version_accepts_the_dual_stack_marker() {
    // RFC 4253 §4.2: 1.99 speaks 2.0. Refusing it refuses working servers.
    let (v, _) = parse_version(b"SSH-1.99-dropbear\r\n").unwrap();
    assert_eq!(v.proto, "1.99");
}

#[test]
fn version_refuses_ssh1() {
    let err = parse_version(b"SSH-1.5-1.2.27\r\n").unwrap_err();
    assert!(matches!(err, podssh_core::ssh::version::VersionError::UnsupportedProtocol { .. }));
}

#[test]
fn version_waits_for_the_terminator() {
    let err = parse_version(b"SSH-2.0-partial").unwrap_err();
    assert!(matches!(err, podssh_core::ssh::version::VersionError::NeedMore { .. }));
}

#[test]
fn version_refuses_non_ssh_lines() {
    let err = parse_version(b"HTTP/1.1 200 OK\r\n").unwrap_err();
    assert!(matches!(err, podssh_core::ssh::version::VersionError::NotSsh { .. }));
}
