//! The reader of HTTPS records against answers captured from Cloudflare's and
//! Google's resolvers on 2026-11-05 (04:10 UTC, through the fetch service of
//! web.pkgforge.dev), for `crypto.cloudflare.com`, a name of Cloudflare's that
//! publishes `ech`: the JSON form of each, and Cloudflare's wire form. The two
//! forms were captured apart, so their agreeing is a check of the reader, not
//! of a test's own bytes.

use super::*;

const NAME: &str = "crypto.cloudflare.com";

/// `GET https://cloudflare-dns.com/dns-query?name=crypto.cloudflare.com&type=HTTPS`
/// with `Accept: application/dns-json`, as it came.
const CLOUDFLARE_JSON: &str = r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,"Question":[{"name":"crypto.cloudflare.com","type":65}],"Answer":[{"name":"crypto.cloudflare.com","type":65,"TTL":300,"data":"1 . alpn=h2 ipv4hint=104.18.6.137,104.18.7.137 ech=AEX+DQBB4gAgACB0aiFCZ6Z30w1eAG3xQ9fJ8/o1688ZHKfPMd+umC5kGwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= ipv6hint=2606:4700::6812:689,2606:4700::6812:789"}]}"#;

/// `GET https://dns.google/resolve?name=crypto.cloudflare.com&type=HTTPS`, as
/// it came.
const GOOGLE_JSON: &str = r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,"Question":[{"name":"crypto.cloudflare.com.","type":65}],"Answer":[{"name":"crypto.cloudflare.com.","type":65,"TTL":300,"data":"1 . alpn=h2 ipv4hint=104.18.6.137,104.18.7.137 ech=AEX+DQBB4gAgACB0aiFCZ6Z30w1eAG3xQ9fJ8/o1688ZHKfPMd+umC5kGwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= ipv6hint=2606:4700::6812:689,2606:4700::6812:789"}],"Comment":"Response from 162.159.1.33."}"#;

/// RFC 8484's GET to `cloudflare-dns.com` of the question of type 65 for
/// the name, with `Accept: application/dns-message`: 184 bytes, as they came.
#[rustfmt::skip]
const CLOUDFLARE_WIRE: [u8; 184] = [
    0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x63, 0x72, 0x79,
    0x70, 0x74, 0x6f, 0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x03, 0x63,
    0x6f, 0x6d, 0x00, 0x00, 0x41, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x01,
    0x2c, 0x00, 0x85, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, 0x68, 0x32, 0x00, 0x04, 0x00,
    0x08, 0x68, 0x12, 0x06, 0x89, 0x68, 0x12, 0x07, 0x89, 0x00, 0x05, 0x00, 0x47, 0x00, 0x45, 0xfe,
    0x0d, 0x00, 0x41, 0xe2, 0x00, 0x20, 0x00, 0x20, 0x74, 0x6a, 0x21, 0x42, 0x67, 0xa6, 0x77, 0xd3,
    0x0d, 0x5e, 0x00, 0x6d, 0xf1, 0x43, 0xd7, 0xc9, 0xf3, 0xfa, 0x35, 0xeb, 0xcf, 0x19, 0x1c, 0xa7,
    0xcf, 0x31, 0xdf, 0xae, 0x98, 0x2e, 0x64, 0x1b, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x12,
    0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65, 0x63, 0x68, 0x2e, 0x63,
    0x6f, 0x6d, 0x00, 0x00, 0x00, 0x06, 0x00, 0x20, 0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x68, 0x12, 0x06, 0x89, 0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x68, 0x12, 0x07, 0x89,
];

/// Where the record's data is in the wire answer: after the header, the
/// question and the record's fixed fields, 133 bytes to the end.
const RDATA: std::ops::Range<usize> = 51..184;

/// Where the `ech` parameter starts in the record's data: after the
/// priority, the root as target, `alpn` and `ipv4hint`.
const ECH_AT: usize = 22;

/// The ECHConfigList that the three answers carry: version 0xfe0d, config
/// 0xe2, X25519, HKDF-SHA256 with AES-128-GCM, public name
/// `cloudflare-ech.com`.
const LIST: &str = "0045fe0d0041e200200020746a214267a677d30d5e006df143d7c9f3fa35ebcf191ca7cf31dfae982e641b\
                    0004000100010012636c6f7564666c6172652d6563682e636f6d0000";

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn published() -> Option<Published> {
    Some(Published { list: unhex(LIST), ttl: Some(300) })
}

#[test]
fn both_resolvers_json_answers_give_the_list_and_its_ttl() {
    assert_eq!(from_json(CLOUDFLARE_JSON.as_bytes()), Ok(published()));
    assert_eq!(from_json(GOOGLE_JSON.as_bytes()), Ok(published()));
}

/// The wire form, captured apart, gives the same list and TTL; the question
/// is checked as for the addresses (case and a final dot aside).
#[test]
fn the_wire_answer_gives_the_same_list_and_ttl() {
    assert_eq!(from_wire(&CLOUDFLARE_WIRE, NAME), Ok(published()));
    assert_eq!(from_wire(&CLOUDFLARE_WIRE, "Crypto.Cloudflare.com."), Ok(published()));
    assert!(from_wire(&CLOUDFLARE_WIRE, "other.example").unwrap_err().contains("another question"));
    assert_eq!(from_rdata(&CLOUDFLARE_WIRE[RDATA]), Ok(Some((1, unhex(LIST)))));
}

/// rustls takes the list with podssh's own HPKE suites, and with none it
/// finds no config that it can use: the suites are the ones that matter.
#[test]
fn rustls_takes_the_list_with_podssh_s_suites() {
    let bytes = || rustls_pki_types::EchConfigListBytes::from(unhex(LIST));
    assert!(rustls::client::EchConfig::new(bytes(), crate::crypto::hpke::SUITES).is_ok());
    match rustls::client::EchConfig::new(bytes(), &[]) {
        Err(rustls::Error::InvalidEncryptedClientHello(rustls::EncryptedClientHelloError::NoCompatibleConfig)) => {}
        other => panic!("no suite should find no config: {:?}", other.map(|_| "a config")),
    }
}

/// A parameter with no bytes is no list, in each form, and not an error.
#[test]
fn a_parameter_with_no_bytes_is_no_list() {
    assert_eq!(from_rdata(&[0, 1, 0, 0, 5, 0, 0]), Ok(None));
    assert_eq!(from_text("1 . ech="), Ok(None));
    assert_eq!(from_text("1 . alpn=h2 ech=\"\""), Ok(None));
    let json = r#"{"Status":0,"Answer":[{"type":65,"TTL":60,"data":"1 . ech="}]}"#;
    assert_eq!(from_json(json.as_bytes()), Ok(None));
}

/// A record cut short is an error that says so, never a list and never a
/// panic: each cut of the wire answer, each cut inside the `ech` parameter's
/// data, and a list in base64 cut short.
#[test]
fn a_record_cut_short_is_an_error_that_says_so() {
    for cut in 0..CLOUDFLARE_WIRE.len() {
        assert!(from_wire(&CLOUDFLARE_WIRE[..cut], NAME).is_err(), "the answer cut at {cut}");
    }
    let rdata = &CLOUDFLARE_WIRE[RDATA];
    for cut in ECH_AT + 1..ECH_AT + 4 + 71 {
        assert_eq!(from_rdata(&rdata[..cut]), Err(CUT.to_string()), "the record cut at {cut}");
    }
    // The base64 of the list's first 12 bytes: its length says 69.
    assert_eq!(from_text("1 . ech=AEX+DQBB4gAgACB0"), Err(LIST_CUT.to_string()));
    // A config whose length runs past the list.
    let mut list = unhex(LIST);
    list[5] += 1;
    assert_eq!(check_list(&list), Err(LIST_CUT.to_string()));
    assert_eq!(check_list(&[0, 0]), Err(LIST_CUT.to_string()), "an empty list");
}

/// An alias holds no parameter; an answer with no record, and no answer,
/// give none; the resolver's own status is an error, NXDOMAIN by name.
#[test]
fn an_alias_or_no_record_gives_no_list_and_a_status_is_said() {
    assert_eq!(from_text("0 svc.example."), Ok(None));
    assert_eq!(from_rdata(&[0, 0, 3, b's', b'v', b'c', 0]), Ok(None));
    assert_eq!(from_json(br#"{"Status":0,"Answer":[]}"#), Ok(None));
    assert_eq!(from_json(br#"{"Status":0}"#), Ok(None));
    // A record of another type, a CNAME before the record, is passed over.
    let cname = r#"{"Status":0,"Answer":[{"type":5,"TTL":60,"data":"crypto.cloudflare.com."}]}"#;
    assert_eq!(from_json(cname.as_bytes()), Ok(None));
    assert_eq!(from_json(br#"{"Status":3}"#), Err(NXDOMAIN.to_string()));
    assert_eq!(from_json(br#"{"Status":2}"#), Err("DNS status 2".to_string()));
    assert!(from_json(b"<html>").is_err());
}

/// RFC 3597's generic form, which a resolver may give for a type it does not
/// present, reads as the wire form; its length must be its data's.
#[test]
fn the_generic_form_reads_as_the_wire_form() {
    let rdata = &CLOUDFLARE_WIRE[RDATA];
    let generic = format!("\\# {} {}", rdata.len(), hex(rdata));
    assert_eq!(from_text(&generic), Ok(Some((1, unhex(LIST)))));
    let spaced: Vec<String> = rdata.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(from_text(&format!("\\# 133 {}", spaced.join(" "))), Ok(Some((1, unhex(LIST)))));
    assert!(from_text(&format!("\\# 132 {}", hex(rdata))).is_err(), "a length that is not the data's");
    assert!(from_text("\\# 2 0g01").is_err(), "a digit that is no hex");
}

/// RFC 9460 section 2.2: keys in increasing order, each once; a target that
/// is compressed is no name.
#[test]
fn parameters_out_of_order_or_twice_and_a_compressed_target_are_refused() {
    let list = unhex(LIST);
    let mut record = vec![0, 1, 0, 0, 5, 0, list.len() as u8];
    record.extend_from_slice(&list);
    assert_eq!(from_rdata(&record), Ok(Some((1, list.clone()))));
    let mut after = record.clone();
    after.extend_from_slice(&[0, 1, 0, 3, 2, b'h', b'2']);
    assert!(from_rdata(&after).unwrap_err().contains("increasing order"));
    let mut twice = record.clone();
    twice.extend_from_slice(&record[3..]);
    assert!(from_rdata(&twice).unwrap_err().contains("increasing order"));
    assert!(from_rdata(&[0, 1, 0xc0, 0x0c]).unwrap_err().contains("compressed"));
}

/// Of two records, the one of the lowest priority gives the list, whatever
/// their order in the answer.
#[test]
fn the_list_of_the_lowest_priority_wins() {
    let first = unhex(LIST);
    let mut second = first.clone();
    // Another config id: the lengths are the same.
    second[6] = 0x01;
    let b64 = |list: &[u8]| base64::engine::general_purpose::STANDARD.encode(list);
    let json = format!(
        r#"{{"Status":0,"Answer":[{{"type":65,"TTL":120,"data":"2 . ech={}"}},{{"type":65,"TTL":90,"data":"1 . ech={}"}}]}}"#,
        b64(&first),
        b64(&second)
    );
    assert_eq!(from_json(json.as_bytes()), Ok(Some(Published { list: second, ttl: Some(90) })));
}
