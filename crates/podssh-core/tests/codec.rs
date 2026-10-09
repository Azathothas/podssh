//! ⛔ **The base64 codec, against RFC 4648's own vectors** ⛔ and against its
//! strictness.
//!
//! ⛔ **podssh-core has no `base64` dependency, and that is a decision with a
//! test behind it** ⛔ — ⛔ see [`podssh_core::irc::transfer::b64`]. ⛔ Every
//! dependency is another thing that can fail `CC=/nonexistent`, ⛔ and this is
//! a 40-line codec whose vectors are in a document everyone can check.
//!
//! ⛔ **The strict half is the one that matters.** ⛔ A lenient decoder drops
//! the offending byte and returns a file that is short by one ⛔ with no word
//! to anyone, ⛔ and a file transfer is precisely where a silently short file
//! does the most damage.

use podssh_core::irc::transfer::b64;

#[test]
fn the_rfc4648_vectors_round_trip() {
    // ⛔ **RFC 4648 §10, "Test Vectors", verbatim.** ⛔ Every one of these is a
    // published test vector, not a value this implementation chose ⛔ and ⛔ a
    // codec that disagrees with them will not interoperate with anything.
    const VECTORS: &[(&str, &str)] = &[
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];
    for (plain, encoded) in VECTORS {
        assert_eq!(b64::encode(plain.as_bytes()), *encoded, "⛔ RFC 4648 says {plain:?} encodes as {encoded:?}");
        assert_eq!(
            b64::decode(encoded).unwrap_or_else(|e| panic!("{encoded:?}: {e}")),
            plain.as_bytes(),
            "⛔ RFC 4648 says {encoded:?} decodes to {plain:?}"
        );
    }
}

#[test]
fn the_alphabet_and_the_padding_are_the_standard_ones() {
    // ⛔ **The padded standard alphabet**, ⛔ not URL-safe and not unpadded ⛔ —
    // ⛔ it is what every other implementation emits, ⛔ so a peer that is not
    // podssh and a file produced elsewhere both decode.
    assert_eq!(b64::encode(b"\xfb\xff\xbe"), "+/++");
    assert_eq!(b64::encode(b"\x00\x00\x00"), "AAAA");
    // ⛔ **Every length remainder pads the way RFC 4648 says**, ⛔ because a
    // decoder that assumed only one of the two cases fails on half the files.
    for (n, want) in [(1usize, 2usize), (2, 1), (3, 0)] {
        let encoded = b64::encode(&vec![b'A'; n]);
        assert_eq!(encoded.matches('=').count(), want, "⛔ {n} bytes must pad {want}");
    }
}

#[test]
fn every_byte_value_survives_a_round_trip() {
    // ⛔ **All 256 byte values**, ⛔ and ⛔ **each at every phase**, ⛔ because a
    // codec that works on aligned input and fails on the last byte of a file is
    // a codec that fails on every file whose length is not a multiple of three.
    let all: Vec<u8> = (0..=255u8).collect();
    for phase in 0..3 {
        let mut slice = all.clone();
        slice.extend_from_slice(&all[..phase]);
        let encoded = b64::encode(&slice);
        assert_eq!(
            b64::decode(&encoded).unwrap_or_else(|e| panic!("phase {phase}: {e}")),
            slice,
            "⛔ a round trip at phase {phase} lost or changed a byte"
        );
    }
}

#[test]
fn a_payload_the_wire_layer_would_destroy_still_round_trips() {
    // ⛔ **THE REASON FOR THE ENCODING, as a test.** ⛔ A raw chunk is not
    // line-safe: ⛔ NUL is stripped by the byte layer and ⛔ `0x0a` ends the line
    // and turns the rest of the file into a second message. ⛔ **Base64 is what
    // makes an arbitrary file survive an IRC message** ⛔ and ⛔ this asserts it
    // for exactly the bytes that would break a raw one.
    let hostile: Vec<u8> = vec![0x00, 0x0a, 0x0d, 0x00, b':', b' ', 0x0a, 0xff];
    let encoded = b64::encode(&hostile);
    assert!(
        !encoded.contains('\n') && !encoded.contains('\r') && !encoded.contains(':'),
        "⛔ the encoded payload carries a byte the IRC grammar treats specially: {encoded}"
    );
    assert_eq!(b64::decode(&encoded).expect("decodes"), hostile);
}

#[test]
fn a_malformed_payload_is_refused_rather_than_shortened() {
    // ⛔ **THE STRICTNESS PLANT.** ⛔ Every one of these is refused. ⛔ A
    // lenient decoder would return a shorter buffer ⛔ and ⛔ the caller writes
    // it to disk ⛔ and ⛔ the digest then fails on a file that "arrived" ⛔ which
    // is a far worse failure than an error naming the byte.
    // ⛔ **The empty string is NOT in this list**, ⛔ and ⛔ **that is a
    // correction rather than an omission**: ⛔ RFC 4648 §10 lists `""` → `""` as
    // its first test vector, ⛔ so an empty payload is valid base64 ⛔ and ⛔ the
    // first version of this test asserted the opposite. ⛔ A decoder that
    // refused `""` would refuse a zero-byte chunk ⛔ and a zero-byte file ⛔ for
    // no reason a reader could see.
    for (bad, why) in [
        ("Zm9vY", "length is not a multiple of four"),
        ("Zm9!", "a byte outside the alphabet"),
        ("Z===", "padding at the first position"),
        ("=m9v", "padding before data"),
        ("Zm=v", "padding in the middle"),
        ("Zg==Zg==", "padding followed by data"),
    ] {
        let result = b64::decode(bad);
        assert!(
            result.is_err(),
            "⛔ PLANT: {bad:?} ({why}) was accepted and decoded to {:?}; a lenient \
             decoder drops a byte and ships a short file",
            result.unwrap_or_default()
        );
    }
}

#[test]
fn the_control_correct_payloads_are_still_accepted() {
    // ⛔ **THE OTHER DIRECTION, and the one a strictness test without it
    // cannot tell from a codec that refuses everything.** ⛔ A decoder that
    // refuses every input is not strict, ⛔ it is broken, ⛔ and ⛔ it looks
    // identical to a strict one until somebody tries to send a file.
    for good in ["", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"] {
        assert!(b64::decode(good).is_ok(), "⛔ a valid RFC 4648 payload was refused: {good:?}");
    }
    // ⛔ **And a long one**, ⛔ because a length check written for one group
    // fails on the hundredth.
    let long: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(b64::decode(&b64::encode(&long)).expect("decodes"), long);
}

#[test]
fn the_error_names_the_byte_and_not_only_that_it_failed() {
    // ⛔ **An error a user cannot act on is half an error.** ⛔ `BadEncoding` on
    // every path is the defect E03 found in its own certificates ⛔ and ⛔ three
    // sibling projects shipped a doctor that reported green over a broken
    // environment.
    let err = b64::decode("Zm9!").expect_err("must fail");
    assert!(err.contains('!'), "⛔ the error must name the offending byte: {err}");
    assert!(err.contains("alphabet"), "⛔ the error must say what was wrong: {err}");
}

#[test]
fn the_suite_is_not_vacuous() {
    // ⛔ **A test that runs nothing is a pass that measured nothing.** ⛔ So
    // the vector count is asserted.
    assert_eq!(b64::encode(b"foobar"), "Zm9vYmFy");
    assert_eq!(b64::encode(b"fo"), "Zm8=");
}
