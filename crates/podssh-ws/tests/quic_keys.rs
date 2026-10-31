//! The keys of QUIC from podssh's own provider (T-301), against vectors that
//! podssh did not write: RFC 9001's Initial packets (appendix A, QUIC v1),
//! RFC 9369's for QUIC v2 (as rustls's own tests hold them), FIPS-197's AES-256
//! for the header mask, and the GCM specification's test case 14 for an
//! AES-256-GCM packet. Each goes through rustls's public QUIC interface, as a
//! QUIC stack calls it.

use podssh_ws::crypto::quic::{AES_128_GCM, AES_256_GCM};
use rustls::crypto::cipher::{AeadKey, Iv};
use rustls::quic::{Algorithm, Keys, Version};
use rustls::{SupportedCipherSuite, Tls13CipherSuite};

fn hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect()
}

fn aes_128_suite() -> &'static Tls13CipherSuite {
    match podssh_ws::crypto::suites::TLS13_AES_128_GCM_SHA256 {
        SupportedCipherSuite::Tls13(suite) => suite,
        _ => unreachable!("a TLS 1.3 suite"),
    }
}

/// The client's chosen connection ID of RFC 9001, appendix A.
const DCID: &str = "8394c8f03e515708";

/// RFC 9001, A.3 and RFC 9369, A.3: the server's Initial, with its ACK and
/// CRYPTO frames.
const SERVER_PAYLOAD: &str = "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
    88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
    0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304";

/// Protect the server's Initial with `keys` as a QUIC stack does: seal the
/// payload, then mask the header from the sample at the third byte of the
/// ciphertext (a packet number of two bytes); then remove both again.
fn server_initial(keys: &Keys, header: &str, protected: &str) {
    let mut header = hex(header);
    let plain = hex(SERVER_PAYLOAD);
    let mut payload = plain.clone();
    let tag = keys.local.packet.encrypt_in_place(1, &header, &mut payload).expect("sealed");
    let (first, rest) = header.split_at_mut(1);
    let at = rest.len() - 2;
    keys.local.header.encrypt_in_place(&payload[2..18], &mut first[0], &mut rest[at..]).expect("masked");
    let mut packet = header.clone();
    packet.extend_from_slice(&payload);
    packet.extend_from_slice(tag.as_ref());
    assert_eq!(packet, hex(protected), "the protected packet of the vector");

    // And back, as the client reads it with the server's keys.
    let (first, rest) = header.split_at_mut(1);
    keys.local.header.decrypt_in_place(&payload[2..18], &mut first[0], &mut rest[at..]).expect("unmasked");
    let mut sealed = payload.clone();
    sealed.extend_from_slice(tag.as_ref());
    let opened = keys.local.packet.decrypt_in_place(1, &header, &mut sealed).expect("opened");
    assert_eq!(opened, &plain[..]);
}

#[test]
fn rfc_9001_the_server_initial_is_protected_and_opened_byte_for_byte() {
    let keys = Keys::initial(Version::V1, aes_128_suite(), &AES_128_GCM, &hex(DCID), rustls::Side::Server);
    server_initial(
        &keys,
        "c1000000010008f067a5502a4262b50040750001",
        "cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
         5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
         dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
         022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4
         2158407dd074ee",
    );
}

#[test]
fn rfc_9369_the_same_packet_under_quic_v2() {
    let keys = Keys::initial(Version::V2, aes_128_suite(), &AES_128_GCM, &hex(DCID), rustls::Side::Server);
    server_initial(
        &keys,
        "d16b3343cf0008f067a5502a4262b50040750001",
        "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698
         baeea26b91eb761d9b89237bbf87263017915358230035f7fd3945d88965cf17
         f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e42757507698075b2
         c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca8
         4bed8521e2e140",
    );
}

#[test]
fn rfc_9001_the_client_initial_header_is_masked_from_its_sample() {
    let keys = Keys::initial(Version::V1, aes_128_suite(), &AES_128_GCM, &hex(DCID), rustls::Side::Client);
    let mut header = hex("c300000001088394c8f03e5157080000449e00000002");
    let sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");
    let (first, rest) = header.split_at_mut(1);
    let at = rest.len() - 4;
    keys.local.header.encrypt_in_place(&sample, &mut first[0], &mut rest[at..]).expect("masked");
    assert_eq!(header, hex("c000000001088394c8f03e5157080000449e7b9aec34"));
}

#[test]
fn fips_197_aes_256_gives_the_mask_of_a_short_header() {
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let header_key = AES_256_GCM.header_protection_key(AeadKey::from(key));
    let sample = hex("00112233445566778899aabbccddeeff");
    // AES-256 of the sample is 8ea2b7ca516745bfeafc49904b496089 (FIPS-197,
    // C.3): five bits of a short header's first byte take 0x8e, and the
    // packet number of four bytes takes a2 b7 ca 51.
    let (mut first, mut number) = (0x43u8, [0u8; 4]);
    header_key.encrypt_in_place(&sample, &mut first, &mut number).expect("masked");
    assert_eq!((first, number), (0x43 ^ (0x8e & 0x1f), [0xa2, 0xb7, 0xca, 0x51]));
    header_key.decrypt_in_place(&sample, &mut first, &mut number).expect("unmasked");
    assert_eq!((first, number), (0x43, [0; 4]));
    assert!(header_key.encrypt_in_place(&sample[..15], &mut first, &mut number).is_err(), "a short sample");
}

#[test]
fn gcm_test_case_14_seals_an_aes_256_packet_and_a_changed_byte_is_refused() {
    let packet = AES_256_GCM.packet_key(AeadKey::from([0u8; 32]), Iv::new([0u8; 12]));
    // Packet number 0 leaves the IV as the nonce: the GCM specification's
    // test case 14, a key, an IV and 16 bytes of zeros.
    let mut payload = [0u8; 16];
    let tag = packet.encrypt_in_place(0, &[], &mut payload).expect("sealed");
    assert_eq!(payload.to_vec(), hex("cea7403d4d606b6e074ec5d3baf39d18"));
    assert_eq!(tag.as_ref(), &hex("d0d1c8a799996bf0265b98b5d48ab919")[..]);
    let mut sealed = payload.to_vec();
    sealed.extend_from_slice(tag.as_ref());
    let mut changed = sealed.clone();
    changed[3] ^= 1;
    assert!(packet.decrypt_in_place(0, &[], &mut changed).is_err(), "a changed byte");
    assert!(packet.decrypt_in_place(1, &[], &mut sealed.clone()).is_err(), "another packet number");
    assert_eq!(packet.decrypt_in_place(0, &[], &mut sealed).expect("opened"), &[0u8; 16][..]);
    assert_eq!((packet.tag_len(), packet.confidentiality_limit(), packet.integrity_limit()), (16, 1 << 23, 1 << 52));
}

/// The mask of RFC 9001's client key on a sample of zeros, as OpenSSL 3.0.13
/// gives it (`openssl enc -aes-128-ecb -K 9f50449e04a0e810283a1e9933adedd2
/// -nopad`): 3c84e0abe1. Its first byte has the bit 0x10, which a long header
/// keeps and a short one takes; the RFC's own samples give masks without it.
#[test]
fn a_long_header_masks_four_bits_and_a_short_one_five() {
    let keys = Keys::initial(Version::V1, aes_128_suite(), &AES_128_GCM, &hex(DCID), rustls::Side::Client);
    let sample = [0u8; 16];
    for (first, masked, number, masked_number) in [
        (0xc3u8, 0xcfu8, [0, 0, 0, 2], [0x84, 0xe0, 0xab, 0xe3]),
        (0x43, 0x5f, [0, 0, 0, 2], [0x84, 0xe0, 0xab, 0xe3]),
        // A packet number of one byte: the three after it stay.
        (0xc0, 0xcc, [2, 0, 0, 0], [0x86, 0, 0, 0]),
    ] {
        let (mut f, mut n) = (first, number);
        keys.local.header.encrypt_in_place(&sample, &mut f, &mut n).expect("masked");
        assert_eq!((f, n), (masked, masked_number), "{first:#04x}");
        keys.local.header.decrypt_in_place(&sample, &mut f, &mut n).expect("unmasked");
        assert_eq!((f, n), (first, number), "{first:#04x}, back");
    }
}
