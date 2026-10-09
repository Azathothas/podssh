//! The records of the resumable layer against vectors written by hand from
//! the table of `docs/design.md` (section 5), not made by the encoder: each
//! vector decodes to the record built here field by field, and the encoder
//! gives the vector back. Then the offsets: an overlap is dropped, and
//! nothing after a gap is ever delivered (T-151).

use podssh_relay::session::decode::DecodeError;
use podssh_relay::session::link::{Event, Link, LinkError};
use podssh_relay::session::record::MAX_DATA;
use podssh_relay::session::{
    Acceptance, Decoder, Hello, Inbound, Nonce, OffsetError, Opening, Outbound, Proof, Record, RefuseCode, Role,
    SessionId,
};

/// Hex with spaces and line breaks between the fields.
fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(digits.len() % 2, 0, "an odd count of hex digits");
    digits.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
}

fn run_of(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start + i as u8).collect()
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

/// RFC 7748, section 6.1: the public keys of Alice and Bob.
const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const FAR_PROOF: &str = "3faedde01956c848d852d53cc0af0586490e10aa662ffd36dc4fcbb428fc88eb";
const CLIENT_PROOF: &str = "44f2167e46064b4dbb88c717034770a0cbef195b22489be9ff70e235297b0958";

/// Each vector, and the record that it is.
fn vectors() -> Vec<(&'static str, Vec<u8>, Record)> {
    let magic = "70 6f 64 73 73 68 2d 73 65 73 73 69 6f 6e"; // "podssh-session"
    vec![
        (
            "GREETING of a node",
            hex(&format!(
                "01 00000048 {magic} 01 02
                 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 02 09 7265706c61792e7631 0c 6865617274626561742e7631"
            )),
            Record::Greeting(Hello {
                version: 1,
                role: Role::NODE,
                nonce: Nonce(array(&run_of(0x00, 32))),
                features: vec!["replay.v1".into(), "heartbeat.v1".into()],
            }),
        ),
        (
            "OPEN of a new session",
            hex(&format!(
                "02 00000052 {magic} 01 01
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 00 {ALICE_PUBLIC} 00"
            )),
            Record::Open {
                hello: Hello {
                    version: 1,
                    role: Role::CLIENT,
                    nonce: Nonce(array(&run_of(0x20, 32))),
                    features: vec![],
                },
                opening: Opening::New { public: array(&hex(ALICE_PUBLIC)) },
            },
        ),
        (
            "OPEN of a resume",
            hex(&format!(
                "02 0000004c {magic} 01 01
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 01 404142434445464748494a4b4c4d4e4f 01 09 7265706c61792e7631"
            )),
            Record::Open {
                hello: Hello {
                    version: 1,
                    role: Role::CLIENT,
                    nonce: Nonce(array(&run_of(0xa0, 32))),
                    features: vec!["replay.v1".into()],
                },
                opening: Opening::Resume { id: SessionId(array(&run_of(0x40, 16))) },
            },
        ),
        (
            "ACCEPT of a new session",
            hex(&format!("03 00000031 00 404142434445464748494a4b4c4d4e4f {BOB_PUBLIC}")),
            Record::Accept(Acceptance::New {
                id: SessionId(array(&run_of(0x40, 16))),
                public: array(&hex(BOB_PUBLIC)),
            }),
        ),
        (
            "ACCEPT of a resume",
            hex(&format!("03 00000029 01 00000000000007d0 {FAR_PROOF}")),
            Record::Accept(Acceptance::Resume { offset: 2000, proof: Proof(array(&hex(FAR_PROOF))) }),
        ),
        (
            "PROOF",
            hex(&format!("04 00000028 00000000000003e8 {CLIENT_PROOF}")),
            Record::Proof { offset: 1000, proof: Proof(array(&hex(CLIENT_PROOF))) },
        ),
        (
            "REFUSE of an unknown session",
            hex("05 00000015 01 6e6f2073756368207365737369 6f6e2068657265"),
            Record::Refuse { code: RefuseCode::UNKNOWN_SESSION, reason: "no such session here".into() },
        ),
        (
            "DATA",
            hex("06 0000000d 0102030405060708 68656c6c6f"),
            Record::Data { offset: 0x0102_0304_0506_0708, bytes: b"hello".to_vec() },
        ),
        ("DATA with no bytes", hex("06 00000008 0000000000000000"), Record::Data { offset: 0, bytes: vec![] }),
        ("ACK", hex("07 00000008 0000000000010000"), Record::Ack { offset: 65536 }),
        ("PING", hex("08 00000008 deadbeef00000001"), Record::Ping { value: 0xdead_beef_0000_0001 }),
        (
            "PONG",
            hex("09 00000010 deadbeef00000001 000000000000002a"),
            Record::Pong { value: 0xdead_beef_0000_0001, offset: 42 },
        ),
        ("CLOSE", hex("0a 00000003 627965"), Record::Close { reason: "bye".into() }),
        ("CLOSE with no reason", hex("0a 00000000"), Record::Close { reason: String::new() }),
    ]
}

#[test]
fn each_vector_decodes_to_its_record() {
    for (name, bytes, record) in vectors() {
        let mut decoder = Decoder::new();
        decoder.push(&bytes);
        assert_eq!(decoder.next(), Ok(Some(record)), "{name}");
        assert_eq!(decoder.next(), Ok(None), "{name}: a byte left over");
        assert_eq!(decoder.buffered(), 0, "{name}");
    }
}

#[test]
fn the_encoder_gives_each_vector_back() {
    for (name, bytes, record) in vectors() {
        assert_eq!(record.to_bytes().unwrap(), bytes, "{name}");
    }
}

/// The relay can split and join frames: the same records come out of the
/// bytes in one piece and one byte at a time.
#[test]
fn frames_mean_nothing() {
    let all: Vec<u8> = vectors().into_iter().flat_map(|(_, bytes, _)| bytes).collect();
    let records: Vec<Record> = vectors().into_iter().map(|(_, _, record)| record).collect();

    let mut whole = Decoder::new();
    whole.push(&all);
    let mut out = Vec::new();
    while let Some(record) = whole.next().unwrap() {
        out.push(record);
    }
    assert_eq!(out, records);

    let mut bytewise = Decoder::new();
    let mut out = Vec::new();
    for byte in &all {
        bytewise.push(std::slice::from_ref(byte));
        while let Some(record) = bytewise.next().unwrap() {
            out.push(record);
        }
    }
    assert_eq!(out, records);
}

/// The largest body is 65536 bytes: a `DATA` of [`MAX_DATA`] bytes.
#[test]
fn the_largest_record_decodes_and_one_more_byte_does_not() {
    let mut bytes = hex("06 00010000 0000000000000000");
    bytes.extend(std::iter::repeat_n(0x5a, MAX_DATA));
    let mut decoder = Decoder::new();
    decoder.push(&bytes);
    match decoder.next() {
        Ok(Some(Record::Data { offset: 0, bytes })) => assert_eq!(bytes.len(), MAX_DATA),
        other => panic!("{other:?}"),
    }

    let mut decoder = Decoder::new();
    decoder.push(&hex("06 00010001"));
    assert_eq!(decoder.next(), Err(DecodeError::TooLong(65537)));

    let too_big = Record::Data { offset: 0, bytes: vec![0; MAX_DATA + 1] };
    assert!(too_big.to_bytes().is_err());
}

fn error_of(bytes: &[u8]) -> DecodeError {
    let mut decoder = Decoder::new();
    decoder.push(bytes);
    match decoder.next() {
        Err(e) => e,
        other => panic!("decoded {other:?}"),
    }
}

fn malformed(bytes: &[u8]) -> &'static str {
    match error_of(bytes) {
        DecodeError::Malformed { why, .. } => why,
        other => panic!("{other:?}"),
    }
}

/// A server with no layer sends its version line: the first byte refuses
/// it, with no wait for a body that never comes.
#[test]
fn a_type_that_the_table_does_not_have_is_refused_at_its_first_byte() {
    assert_eq!(error_of(b"SSH-2.0-OpenSSH_9.6\r\n"), DecodeError::UnknownType(b'S'));
    assert_eq!(error_of(&[0x00]), DecodeError::UnknownType(0));
    assert_eq!(error_of(&[0x0b]), DecodeError::UnknownType(0x0b));
}

#[test]
fn bodies_that_are_not_their_record_are_refused() {
    let nonce = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    // A magic of one wrong letter.
    assert_eq!(
        malformed(&hex(&format!("01 00000031 706f64737368 2d 7365737369 6f6f 01 02 {nonce} 00"))),
        "no podssh-session magic"
    );
    // 17 feature names.
    let magic = "706f647373682d73657373696f6e";
    assert_eq!(malformed(&hex(&format!("01 00000031 {magic} 01 02 {nonce} 11"))), "more than 16 feature names");
    // A capital letter, and an empty name.
    assert_eq!(
        malformed(&hex(&format!("01 00000033 {magic} 01 02 {nonce} 01 01 41"))),
        "a feature name out of its alphabet or length"
    );
    assert_eq!(
        malformed(&hex(&format!("01 00000032 {magic} 01 02 {nonce} 01 00"))),
        "a feature name out of its alphabet or length"
    );
    // An `OPEN` that is neither new nor a resume.
    assert_eq!(
        malformed(&hex(&format!("02 00000031 {magic} 01 01 {nonce} 02"))),
        "neither a new session (0) nor a resume (1)"
    );
    // A reason that is not UTF-8, and one over 1024 bytes.
    assert_eq!(malformed(&hex("05 00000002 01 ff")), "a reason that is not UTF-8");
    let mut long = hex("0a 00000401");
    long.extend(std::iter::repeat_n(b'x', 1025));
    assert_eq!(malformed(&long), "a reason over 1024 bytes");
    // An offset of 7 bytes, and one of 9.
    assert_eq!(malformed(&hex("07 00000007 00000000000000")), "the body ends early");
    assert_eq!(malformed(&hex("07 00000009 000000000000000000")), "bytes after the end of the body");
}

/// After an error the decoder gives that error again: no byte after it is
/// read as a record.
#[test]
fn a_decoder_reads_nothing_after_an_error() {
    let mut decoder = Decoder::new();
    decoder.push(&hex("07 00000009 000000000000000000"));
    let error = decoder.next().unwrap_err();
    decoder.push(&hex("07 00000008 0000000000000001"));
    assert_eq!(decoder.next(), Err(error));
}

#[test]
fn an_overlap_is_dropped_and_old_bytes_are_ignored() {
    let mut inbound = Inbound::new(0);
    assert_eq!(inbound.accept(0, b"abc"), Ok(&b"abc"[..]));
    assert_eq!(inbound.accept(1, b"bcd"), Ok(&b"d"[..]));
    assert_eq!(inbound.accept(0, b"ab"), Ok(&b""[..]));
    assert_eq!(inbound.accept(4, b""), Ok(&b""[..]));
    assert_eq!(inbound.received(), 4);
}

#[test]
fn a_gap_delivers_nothing_and_the_offset_stays() {
    let mut inbound = Inbound::new(0);
    assert_eq!(inbound.accept(0, b"abcd"), Ok(&b"abcd"[..]));
    assert_eq!(inbound.accept(6, b"gh"), Err(OffsetError::Gap { expected: 4, got: 6 }));
    assert_eq!(inbound.received(), 4);
    // A resume sends from the received offset, and the bytes follow on.
    assert_eq!(inbound.accept(4, b"efgh"), Ok(&b"efgh"[..]));
    assert_eq!(inbound.received(), 8);
    assert_eq!(inbound.accept(u64::MAX, b"x"), Err(OffsetError::Overflow { offset: u64::MAX, len: 1 }));
}

/// The rule of the layer: once a link shows a gap, nothing more comes from
/// it, not even the bytes that would fill the gap. Those come on a new link.
#[test]
fn a_link_delivers_nothing_after_a_gap() {
    let mut link = Link::new(0, 0);
    let data = |offset: u64, bytes: &[u8]| Record::Data { offset, bytes: bytes.to_vec() };
    assert_eq!(link.on_record(data(0, b"abc")), Ok(Event::Deliver(b"abc".to_vec())));
    let gap = LinkError::Offset(OffsetError::Gap { expected: 3, got: 5 });
    assert_eq!(link.on_record(data(5, b"fgh")), Err(gap.clone()));
    assert_eq!(link.on_record(data(3, b"de")), Err(gap.clone()));
    assert_eq!(link.on_record(data(5, b"fgh")), Err(gap));
    assert_eq!(link.received(), 3);
}

#[test]
fn the_sender_numbers_its_bytes_and_takes_acknowledgements() {
    let mut outbound = Outbound::new(0);
    assert_eq!(outbound.take(5), Ok(0));
    assert_eq!(outbound.take(3), Ok(5));
    assert_eq!(outbound.sent(), 8);
    assert_eq!(outbound.acknowledge(4), Ok(()));
    assert_eq!(outbound.acknowledge(2), Ok(()));
    assert_eq!(outbound.acknowledged(), 4);
    assert_eq!(outbound.acknowledge(9), Err(OffsetError::Ahead { sent: 8, acknowledged: 9 }));
}

#[test]
fn a_link_answers_a_ping_and_refuses_an_acknowledgement_of_bytes_never_sent() {
    let mut link = Link::new(7, 0);
    assert_eq!(link.on_record(Record::Ping { value: 9 }), Ok(Event::Reply(Record::Pong { value: 9, offset: 7 })));
    assert_eq!(
        link.on_record(Record::Pong { value: 9, offset: 1 }),
        Err(LinkError::Offset(OffsetError::Ahead { sent: 0, acknowledged: 1 }))
    );
}

#[test]
fn a_link_cuts_its_bytes_into_records_of_at_most_max_data() {
    let mut link = Link::new(0, 100);
    let bytes: Vec<u8> = (0..(MAX_DATA * 2 + 10)).map(|i| i as u8).collect();
    let mut out = Vec::new();
    link.send(&bytes, &mut out).unwrap();
    let mut decoder = Decoder::new();
    decoder.push(&out);
    let mut offsets = Vec::new();
    let mut joined = Vec::new();
    while let Some(record) = decoder.next().unwrap() {
        let Record::Data { offset, bytes } = record else { panic!("{record:?}") };
        offsets.push((offset, bytes.len()));
        joined.extend(bytes);
    }
    assert_eq!(offsets, vec![(100, MAX_DATA), (100 + MAX_DATA as u64, MAX_DATA), (100 + 2 * MAX_DATA as u64, 10)]);
    assert_eq!(joined, bytes);
    assert_eq!(link.sent(), 100 + bytes.len() as u64);
}

#[test]
fn a_record_of_the_handshake_ends_a_link_past_it() {
    let mut link = Link::new(0, 0);
    let proof = Record::Proof { offset: 0, proof: Proof([0; 32]) };
    assert_eq!(link.on_record(proof), Err(LinkError::Unexpected("PROOF")));
    let mut link = Link::new(0, 0);
    let refuse = Record::Refuse { code: RefuseCode::NOT_KEPT, reason: "offset 5 is gone".into() };
    assert!(matches!(link.on_record(refuse), Err(LinkError::Refused { code: RefuseCode::NOT_KEPT, .. })));
}

/// A message never shows a proof or the bytes of the session.
#[test]
fn debug_hides_proofs_and_data() {
    let proof = Record::Proof { offset: 1, proof: Proof(array(&hex(CLIENT_PROOF))) };
    assert!(!format!("{proof:?}").contains("44f2"), "{proof:?}");
    let data = Record::Data { offset: 0, bytes: b"secret bytes".to_vec() };
    assert_eq!(format!("{data:?}"), "Data { offset: 0, len: 12 }");
}
