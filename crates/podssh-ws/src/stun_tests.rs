//! The tests of STUN's codec (T-641): RFC 5769's test vectors, bytes that
//! the RFC's authors' software wrote, read field by field; the writer held to
//! the same bytes; and each form that is no message refused before a byte
//! past it is read.

use super::*;

/// RFC 5769, 2.1: a request with SOFTWARE, PRIORITY, ICE-CONTROLLED,
/// USERNAME, MESSAGE-INTEGRITY and FINGERPRINT.
const REQUEST: &str = "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74\
                       002400046e0001ff80290008932ff9b151263b36000600096576746a3a6836765920202000080014\
                       9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf";

/// RFC 5769, 2.2: a response that names 192.0.2.1 port 32853.
const RESPONSE_V4: &str = "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220\
                           002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7\
                           80280004c07d4c96";

/// RFC 5769, 2.3: a response that names 2001:db8:1234:5678:11:2233:4455:6677
/// port 32853.
const RESPONSE_V6: &str = "010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220\
                           002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf1\
                           1784c97c8292c275bfe3ed4180280004c8fb0b4c";

/// The transaction's id of each vector.
const ID: TransactionId = [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
}

/// Each vector reads, with each attribute in its order and without its
/// padding; MESSAGE-INTEGRITY and FINGERPRINT are carried, not checked, as
/// the probe of a NAT sends no credential.
#[test]
fn rfc_5769_s_vectors_read_field_by_field() {
    let bytes = hex(REQUEST);
    let request = parse(&bytes).unwrap();
    assert_eq!((request.kind, request.id), (BINDING_REQUEST, ID));
    let kinds: Vec<u16> = request.attributes.iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, [SOFTWARE, 0x0024, 0x8029, 0x0006, 0x0008, 0x8028]);
    assert_eq!(request.attribute(SOFTWARE), Some(&b"STUN test client"[..]));
    assert_eq!(request.attribute(0x0006), Some(&b"evtj:h6vY"[..]), "USERNAME, its 3 bytes of padding left out");
    assert_eq!(request.mapped(), None, "a request names no address");

    let bytes = hex(RESPONSE_V4);
    let v4 = parse(&bytes).unwrap();
    assert_eq!((v4.kind, v4.id), (BINDING_SUCCESS, ID));
    assert_eq!(v4.attribute(SOFTWARE), Some(&b"test vector"[..]));
    assert_eq!(v4.mapped(), Some(Ok("192.0.2.1:32853".parse().unwrap())));
    assert_eq!(v4.attributes.len(), 4);

    let bytes = hex(RESPONSE_V6);
    let v6 = parse(&bytes).unwrap();
    assert_eq!(v6.mapped(), Some(Ok("[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse().unwrap())));
}

/// The writer gives the vectors' own bytes for their addresses, and what it
/// writes reads back.
#[test]
fn the_writer_gives_the_vectors_bytes_and_reads_back() {
    let v4: SocketAddr = "192.0.2.1:32853".parse().unwrap();
    assert_eq!(write_address(v4, Some(&ID)), hex("0001a147e112a643"));
    let v6: SocketAddr = "[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse().unwrap();
    assert_eq!(write_address(v6, Some(&ID)), hex("0002a1470113a9faa5d3f179bc25f4b5bed2b9d9"));
    assert_eq!(write_address(v4, None), hex("00018055c0000201"), "plain: the port and the address as they are");
    for addr in [v4, v6] {
        let bytes = binding_success(&ID, addr);
        assert_eq!(bytes.len() % 4, 0);
        let answer = parse(&bytes).unwrap();
        assert_eq!((answer.kind, answer.id, answer.mapped()), (BINDING_SUCCESS, ID, Some(Ok(addr))));
    }
    let request = binding_request(&ID);
    assert_eq!(request[..8], hex("000100002112a442")[..]);
    let read = parse(&request).unwrap();
    assert_eq!((read.kind, read.id, read.attributes.len()), (BINDING_REQUEST, ID, 0));
}

/// XOR-MAPPED-ADDRESS wins over the plain one; the plain one alone is an
/// older server's answer and is read; neither is no address.
#[test]
fn the_xored_address_wins_and_the_plain_one_is_a_fallback() {
    let seen: SocketAddr = "198.51.100.7:40000".parse().unwrap();
    let other: SocketAddr = "203.0.113.9:9".parse().unwrap();
    let (xored, plain) = (write_address(seen, Some(&ID)), write_address(other, None));
    let pair = [(MAPPED_ADDRESS, plain.as_slice()), (XOR_MAPPED_ADDRESS, xored.as_slice())];
    let both = message(BINDING_SUCCESS, &ID, &pair);
    assert_eq!(parse(&both).unwrap().mapped(), Some(Ok(seen)));
    let old = message(BINDING_SUCCESS, &ID, &[(MAPPED_ADDRESS, plain.as_slice())]);
    assert_eq!(parse(&old).unwrap().mapped(), Some(Ok(other)));
    let none = message(BINDING_SUCCESS, &ID, &[(SOFTWARE, b"stand-in".as_slice())]);
    assert_eq!(parse(&none).unwrap().mapped(), None);
    // A family that is neither, and an address of the wrong length.
    let odd = message(BINDING_SUCCESS, &ID, &[(XOR_MAPPED_ADDRESS, [0u8, 3, 0, 1, 1, 2, 3, 4].as_slice())]);
    assert!(parse(&odd).unwrap().mapped().unwrap().unwrap_err().contains("family 3"));
    let short = message(BINDING_SUCCESS, &ID, &[(XOR_MAPPED_ADDRESS, [0u8, 1, 0, 1, 1, 2, 3].as_slice())]);
    assert!(parse(&short).unwrap().mapped().unwrap().unwrap_err().contains("3 bytes for the family 1"));
}

/// An error response's code and reason (RFC 8489, 14.8).
#[test]
fn an_error_response_gives_its_code_and_reason() {
    let value = [[0u8, 0, 4, 20].as_slice(), b"Unknown Attribute".as_slice()].concat();
    let bytes = message(BINDING_ERROR, &ID, &[(ERROR_CODE, value.as_slice())]);
    let read = parse(&bytes).unwrap();
    assert_eq!(read.kind, BINDING_ERROR);
    assert_eq!(read.error(), Some(Ok((420, "Unknown Attribute".to_string()))));
    let bad = message(BINDING_ERROR, &ID, &[(ERROR_CODE, [0u8, 0, 7, 0].as_slice())]);
    assert!(parse(&bad).unwrap().error().unwrap().is_err(), "class 7 is no class");
}

/// Each form that is no message is refused with why, and no length is
/// trusted past the datagram: a QUIC packet, a datagram cut short, a length
/// that is not the datagram's, an attribute that runs past the end.
#[test]
fn what_is_no_message_is_refused_before_a_byte_past_it_is_read() {
    let good = hex(RESPONSE_V4);
    assert!(parse(&good[..19]).unwrap_err().contains("fewer than a header's 20"));
    let mut quic = good.clone();
    quic[0] = 0xc0;
    assert!(parse(&quic).unwrap_err().contains("first two bits"));
    let mut cookie = good.clone();
    cookie[4] ^= 1;
    assert!(parse(&cookie).unwrap_err().contains("no magic cookie"));
    // The length says 4 more than the datagram holds, then 2 more.
    let mut long = good.clone();
    long[3] += 4;
    assert!(parse(&long).unwrap_err().contains("a length of 64 for 60 bytes"), "{:?}", parse(&long));
    let mut odd = good.clone();
    odd[3] += 2;
    assert!(parse(&odd).unwrap_err().contains("not a multiple of 4"));
    // The datagram cut after the header and 4 bytes of an attribute.
    assert!(parse(&good[..good.len() - 4]).is_err());
    // An attribute whose length runs past the message: SOFTWARE says 255.
    let mut past = good.clone();
    past[23] = 0xff;
    assert!(parse(&past).unwrap_err().contains("0x8022 says 255 bytes, past the message"));
    // 3 bytes after a header that says 4.
    let mut header_cut = binding_request(&ID).to_vec();
    header_cut[3] = 4;
    header_cut.extend_from_slice(&[0x80, 0x22, 0x00]);
    assert!(parse(&header_cut).unwrap_err().contains("a length of 4 for 3 bytes"));
    // An attribute of no bytes is one, and a value of 2 bytes takes 2 of
    // padding that are not part of it.
    let empty = message(BINDING_SUCCESS, &ID, &[(SOFTWARE, b"".as_slice()), (0x8023, b"ab".as_slice())]);
    assert_eq!(empty.len(), HEADER + 4 + 8);
    assert_eq!(parse(&empty).unwrap().attributes, vec![(SOFTWARE, &b""[..]), (0x8023, &b"ab"[..])]);
}
