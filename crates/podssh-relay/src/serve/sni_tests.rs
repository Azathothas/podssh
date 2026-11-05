//! The tests of the reader of a ClientHello (T-649), on captured bytes: the
//! record of RFC 8448's first ClientHello (section 3, "complete record (201
//! octets)"), whose name is `server`, and RFC 9001's (appendix A.2, its CRYPTO
//! frame's ClientHello, put in a record of TLS), whose name is `example.com`
//! and whose ALPN is `alpn`. Their variants put an extension first among the
//! hello's own, with the three lengths that hold it moved.

use super::*;

/// RFC 8448, section 3: a ClientHello for `server`, with no ALPN.
const RFC_8448: &str = concat!(
    "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece70000061301",
    "13031302010000910000000b0009000006736572766572ff01000100000a00140012001d001700180019010001010102",
    "0103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529a",
    "af2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00",
    "020101001c00024001",
);
/// Where the extensions' length of [`RFC_8448`] is.
const RFC_8448_EXTENSIONS: usize = 54;

/// RFC 9001, appendix A.2: a ClientHello for `example.com` that offers the
/// ALPN `alpn`, behind the head of a record of 241 bytes.
const RFC_9001: &str = concat!(
    "16030100f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c0000041301",
    "1302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d001700180010000700",
    "0504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1c",
    "e15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001",
    "003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e515708",
    "06048000ffff",
);

fn unhex(text: &str) -> Vec<u8> {
    let digits = text.as_bytes();
    digits.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
}

/// `record`, a ClientHello whose extensions' length is at `at`, with
/// `extension` first among them: the record's, the message's and the
/// extensions' lengths each grow by its size.
fn with_extension(record: &[u8], at: usize, extension: &[u8]) -> Vec<u8> {
    let add = extension.len();
    let mut out = record[..at + 2].to_vec();
    out.extend_from_slice(extension);
    out.extend_from_slice(&record[at + 2..]);
    let record_len = usize::from(u16::from_be_bytes([out[3], out[4]])) + add;
    out[3..5].copy_from_slice(&u16::try_from(record_len).unwrap().to_be_bytes());
    let message = ((usize::from(out[6]) << 16) | (usize::from(out[7]) << 8) | usize::from(out[8])) + add;
    out[6..9].copy_from_slice(&u32::try_from(message).unwrap().to_be_bytes()[1..]);
    let extensions = usize::from(u16::from_be_bytes([out[at], out[at + 1]])) + add;
    out[at..at + 2].copy_from_slice(&u16::try_from(extensions).unwrap().to_be_bytes());
    out
}

/// An ALPN extension that offers `protocols`, in order.
fn alpn(protocols: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for protocol in protocols {
        list.push(u8::try_from(protocol.len()).unwrap());
        list.extend_from_slice(protocol);
    }
    let mut data = u16::try_from(list.len()).unwrap().to_be_bytes().to_vec();
    data.extend_from_slice(&list);
    let mut extension = vec![0x00, 0x10];
    extension.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    extension.extend_from_slice(&data);
    extension
}

fn hello(name: &str, acme: bool) -> Read {
    Read::Hello(Hello { name: Some(name.to_string()), acme })
}

/// T-649: the name of each captured hello, as its client wrote it; RFC
/// 9001's ALPN is no CA's validation.
#[test]
fn the_names_of_captured_client_hellos_are_read() {
    assert_eq!(read(&unhex(RFC_8448)), hello("server", false));
    assert_eq!(read(&unhex(RFC_9001)), hello("example.com", false));
    // A byte after the record is the next record's: the hello is read.
    let mut after = unhex(RFC_8448);
    after.push(0x17);
    assert_eq!(read(&after), hello("server", false));
    // The case as written: the table of published names folds it.
    let mut upper = unhex(RFC_8448);
    let at = upper.windows(6).position(|w| w == b"server").expect("the name in RFC 8448's hello");
    upper[at..at + 6].copy_from_slice(b"SERVER");
    assert_eq!(read(&upper), hello("SERVER", false));
}

/// T-649: `acme-tls/1` alone is a CA's validation; beside another protocol,
/// or in an empty list, it is not.
#[test]
fn a_hello_that_offers_acme_tls_alone_is_a_ca_s_validation() {
    let record = unhex(RFC_8448);
    let acme = with_extension(&record, RFC_8448_EXTENSIONS, &alpn(&[ACME_TLS_1]));
    assert_eq!(read(&acme), hello("server", true));
    let beside = with_extension(&record, RFC_8448_EXTENSIONS, &alpn(&[&b"h2"[..], ACME_TLS_1]));
    assert_eq!(read(&beside), hello("server", false));
    let empty = with_extension(&record, RFC_8448_EXTENSIONS, &alpn(&[]));
    assert_eq!(read(&empty), hello("server", false));
}

/// T-649: each part of a record waits for more; a record past TLS's bound
/// of 16 KiB, and a hello longer than its record, are none at once.
#[test]
fn a_record_cut_short_waits_and_one_too_long_is_none() {
    let record = unhex(RFC_8448);
    for cut in 0..record.len() {
        assert_eq!(read(&record[..cut]), Read::More, "the first {cut} bytes");
    }
    let mut long = record.clone();
    long[3..5].copy_from_slice(&u16::try_from(MOST - 5 + 1).unwrap().to_be_bytes());
    assert_eq!(read(&long), Read::Not, "a record of 16 KiB and one byte");
    // The largest record waits for its bytes.
    let mut largest = record.clone();
    largest[3..5].copy_from_slice(&u16::try_from(MOST - 5).unwrap().to_be_bytes());
    assert_eq!(read(&largest), Read::More, "a record of 16 KiB");
    // The handshake says one byte more than its record holds: a hello in
    // two records, which the reader does not join.
    let mut two = record.clone();
    two[8] += 1;
    assert_eq!(read(&two), Read::Not);
    let mut empty = record;
    empty[3..5].copy_from_slice(&[0, 0]);
    assert_eq!(read(&empty), Read::Not, "a record of no bytes");
}

/// T-649: what is no record of TLS's handshake is none at its first byte
/// that says so.
#[test]
fn what_is_no_handshake_is_none_at_once() {
    // HTTP, SSH, a record of TLS's data, a version of no TLS, and a zero.
    let others = [&b"GET / HTTP/1.1\r\n"[..], b"SSH-2.0-OpenSSH_9.6\r\n", b"\x17\x03\x03\x00\x10", b"\x16\x02", b"\0"];
    for other in others {
        assert_eq!(read(other), Read::Not, "{other:?}");
    }
    // A handshake that is no ClientHello: a ServerHello's type.
    let mut server = unhex(RFC_8448);
    server[5] = 0x02;
    assert_eq!(read(&server), Read::Not);
}

/// T-649: a second server_name or ALPN, and a name that no DNS name is,
/// are none: a guess could send the visitor to another node.
#[test]
fn a_second_name_or_a_name_out_of_shape_is_none() {
    let record = unhex(RFC_8448);
    // `other.org` before the hello's own `server`.
    let other = unhex("0000000e000c0000096f746865722e6f7267");
    assert_eq!(read(&with_extension(&record, RFC_8448_EXTENSIONS, &other)), Read::Not);
    let acme = alpn(&[ACME_TLS_1]);
    let twice = with_extension(&with_extension(&record, RFC_8448_EXTENSIONS, &acme), RFC_8448_EXTENSIONS, &acme);
    assert_eq!(read(&twice), Read::Not);
    for odd in [&b"ser ve"[..], b"ser\0ve", b"ser/ve", b"s\xc3\xa9rve"] {
        let mut bytes = record.clone();
        let at = bytes.windows(6).position(|w| w == b"server").unwrap();
        // Six bytes each, so that no length moves.
        bytes[at..at + 6].copy_from_slice(odd);
        assert_eq!(read(&bytes), Read::Not, "{odd:?}");
    }
}
