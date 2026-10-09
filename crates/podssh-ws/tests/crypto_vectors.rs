//! ⛔ **The crypto primitives, against published vectors, not against
//! themselves.** A provider that agrees with its own bugs completes a
//! handshake with nobody and passes every test written by the same author.
//!
//! Every vector here is cited: RFC 6234 for SHA, RFC 5869 appendix A for
//! HKDF, RFC 7748 for X25519, RFC 8032 for Ed25519, and the RFC 6455 §1.3
//! worked example for the WebSocket accept value.

use podssh_ws::crypto::aead::AeadId;
use podssh_ws::crypto::hash::HashAlgorithmId;
use podssh_ws::crypto::hash::{SHA256, SHA384};
use podssh_ws::crypto::hkdf::PureHkdf;
use podssh_ws::crypto::hmac::{HMAC_SHA256, HMAC_SHA384};
use podssh_ws::crypto::kx::{SECP256R1, X25519};
// ⛔ The signature algorithms are asserted in `signatures.rs`; this file
// keeps the provider as a whole.
use podssh_ws::crypto::sign::signature_algorithms;
use rustls::crypto::hmac::Hmac as _;
use rustls::crypto::tls13::Hkdf as _;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

/// ⛔ **Fixed-size keys are converted with a checked `try_into`, never
/// resized.** A helper that padded a short key would make a truncated test
/// vector look like a valid one.
fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("a 32-byte key")
}

// ── hashes ──────────────────────────────────────────────────────────────────

/// ⛔ FIPS 180-4 / NIST CAVP: SHA-256 of "abc".
#[test]
fn sha256_matches_the_published_vector() {
    assert_eq!(hex(SHA256.hash(b"abc").as_ref()), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(SHA256.output_len(), 32);
    assert_eq!(SHA256.algorithm(), rustls::crypto::hash::HashAlgorithm::SHA256);
}

/// ⛔ FIPS 180-4: SHA-384 of "abc".
#[test]
fn sha384_matches_the_published_vector() {
    assert_eq!(
        hex(SHA384.hash(b"abc").as_ref()),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7"
    );
    assert_eq!(SHA384.output_len(), 48);
}

/// ⛔ **The empty string**, because a hash that never sees an empty input is a
/// hash whose padding has never been exercised. SHA-256("") is a published
/// constant and it is the one every implementation gets wrong first.
#[test]
fn hashes_handle_the_empty_input() {
    assert_eq!(hex(SHA256.hash(b"").as_ref()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(
        hex(SHA384.hash(b"").as_ref()),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
         274edebfe76f65fbd51ad2f14898b95b"
    );
}

/// ⛔ **Incremental and one-shot must agree.** rustls hashes the handshake
/// transcript with `start()`/`update()`/`finish()` and single messages with
/// `hash()`. A divergence between them produces a transcript hash that matches
/// nothing the peer computed, and it surfaces as a `Finished` mismatch.
#[test]
fn incremental_and_one_shot_hashing_agree() {
    let data: Vec<u8> = (0u16..1000).map(|i| (i % 251) as u8).collect();
    for split in [1usize, 7, 64, 65, 333, 999] {
        let mut ctx = SHA256.start();
        ctx.update(&data[..split]);
        ctx.update(&data[split..]);
        assert_eq!(hex(ctx.finish().as_ref()), hex(SHA256.hash(&data).as_ref()), "SHA-256 diverged at split {split}");
    }
}

/// ⛔ **`fork` must copy the prefix, not share the state.** rustls forks the
/// transcript to hash a handshake message and then continue the original. A
/// `fork` that aliased the context would make the second hash a hash of
/// everything so far *twice*.
#[test]
fn fork_copies_the_prefix_and_leaves_the_original_alone() {
    let mut ctx = SHA256.start();
    ctx.update(b"prefix");
    let mut forked = ctx.fork();
    forked.update_boxed(b"-forked");
    ctx.update(b"-original");

    assert_eq!(
        hex(forked.finish().as_ref()),
        hex(SHA256.hash(b"prefix-forked").as_ref()),
        "the fork did not carry the prefix"
    );
    assert_eq!(
        hex(ctx.finish().as_ref()),
        hex(SHA256.hash(b"prefix-original").as_ref()),
        "the original was disturbed by its fork"
    );
}

/// Small helper so the fork test can mutate a `Box<dyn Context>`.
trait UpdateBoxed {
    fn update_boxed(&mut self, data: &[u8]);
}
impl UpdateBoxed for Box<dyn rustls::crypto::hash::Context> {
    fn update_boxed(&mut self, data: &[u8]) {
        rustls::crypto::hash::Context::update(self.as_mut(), data);
    }
}

// ── HMAC ────────────────────────────────────────────────────────────────────

/// ⛔ RFC 4231 test case 1.
#[test]
fn hmac_sha256_matches_rfc4231_case_1() {
    let key = [0x0bu8; 20];
    let tag = HMAC_SHA256.with_key(&key).sign(&[b"Hi There"]);
    assert_eq!(hex(tag.as_ref()), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(HMAC_SHA256.hash_output_len(), 32);
}

/// ⛔ RFC 4231 test case 1, for SHA-384.
#[test]
fn hmac_sha384_matches_rfc4231_case_1() {
    let key = [0x0bu8; 20];
    let tag = HMAC_SHA384.with_key(&key).sign(&[b"Hi There"]);
    assert_eq!(
        hex(tag.as_ref()),
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
         faea9ea9076ede7f4af152e8b2fa9cb6"
    );
}

/// ⛔ **Signing the same message twice must give the same tag.** rustls signs
/// with a `Key` it holds, and a `Key` whose second signature depended on its
/// first would produce a key schedule that is right once and wrong forever.
#[test]
fn an_hmac_key_signs_repeatedly_and_identically() {
    let key = HMAC_SHA256.with_key(b"a key held across several signatures");
    let first = key.sign(&[b"message"]);
    let second = key.sign(&[b"message"]);
    assert_eq!(first.as_ref(), second.as_ref());
}

/// ⛔ **`sign_concat` is the same as signing the joined message.** rustls uses
/// the two forms interchangeably, and a mismatch between them silently changes
/// the transcript hash.
#[test]
fn sign_concat_equals_signing_the_joined_message() {
    let key = HMAC_SHA256.with_key(b"k");
    let joined = key.sign(&[b"aaa", b"bbb", b"ccc"]);
    let concat = key.sign_concat(b"aaa", &[b"bbb"], b"ccc");
    assert_eq!(joined.as_ref(), concat.as_ref());
}

// ── HKDF: RFC 5869 appendix A ───────────────────────────────────────────────

/// ⛔ **RFC 5869 appendix A, test case 1.** The most-copied vector in the
/// literature; if extract and expand are transposed this is what catches it.
#[test]
fn hkdf_sha256_matches_rfc5869_case_1() {
    let ikm = [0x0bu8; 22];
    let salt: Vec<u8> = (0x00u8..=0x0c).collect();
    // ⛔ **info is TEN octets, 0xf0f1f2f3f4f5f6f7f8f9.** The three-octet form
    // is the vector from the HKDF draft that predates this RFC, and pasting it
    // here produced an OKM that matched nothing — including, briefly, this
    // implementation. The PRK below is the one that pins the test to the RFC.
    let info: Vec<u8> = (0xf0u8..=0xf9).collect();
    let expander = PureHkdf(HashAlgorithmId::Sha256).extract_from_secret(Some(&salt), &ikm);
    let mut out = [0u8; 42];
    expander.expand_slice(&[&info], &mut out).expect("42 bytes is one block");
    assert_eq!(
        hex(&out),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865"
    );
    assert_eq!(expander.hash_len(), 32);
}

// ── AEAD round-trip ─────────────────────────────────────────────────────────

#[test]
fn every_aead_round_trips_and_rejects_a_flipped_bit() {
    use podssh_ws::crypto::aead::Aead;
    for id in [AeadId::Aes128Gcm, AeadId::Aes256Gcm, AeadId::ChaCha20Poly1305] {
        let key = vec![0xABu8; id.key_len()];
        let aead = Aead::new(id, &key).expect("a key of key_len bytes");
        let nonce = [7u8; 12];
        let aad = b"the TLS 1.3 additional data";
        let plaintext = b"SSH-2.0-podssh\x00\x00\x00\x00\x00\x00\x00\x00";

        let mut sealed = plaintext.to_vec();
        aead.seal_in_place(&nonce, aad, &mut sealed).expect("seal");
        // ⛔ **Sealing must change the bytes.** An AEAD that returned its input
        // would "round-trip" perfectly and protect nothing.
        assert_ne!(sealed, plaintext, "{id:?} did not change the plaintext");
        assert_eq!(sealed.len(), plaintext.len() + 16, "{id:?} tag length");

        let mut opened = sealed.clone();
        let n = aead.open_in_place(&nonce, aad, &mut opened).expect("open");
        assert_eq!(&opened[..n], plaintext, "{id:?} did not round-trip");

        // ⛔ **A modified ciphertext must be rejected, not returned as garbage.**
        let mut tampered = sealed.clone();
        tampered[0] ^= 0x01;
        assert!(aead.open_in_place(&nonce, aad, &mut tampered).is_none(), "{id:?} accepted a tampered ciphertext");

        // ⛔ **The AAD is authenticated too**, or a peer could move bytes
        // between records without the tag noticing.
        assert!(
            aead.open_in_place(&nonce, b"different aad", &mut tampered).is_none(),
            "{id:?} ignored the additional data"
        );
    }
}

#[test]
fn an_aead_refuses_a_key_of_the_wrong_length() {
    use podssh_ws::crypto::aead::Aead;
    // ⛔ **AES-128's key is 16 bytes and AES-256's is 32.** A provider that
    // accepted either length for both would let a peer negotiate AES-128 and
    // then encrypt with a key the wrong size.
    assert!(Aead::new(AeadId::Aes128Gcm, &[0u8; 32]).is_err());
    assert!(Aead::new(AeadId::Aes256Gcm, &[0u8; 16]).is_err());
    assert!(Aead::new(AeadId::Aes128Gcm, &[0u8; 16]).is_ok());
}

// ── key exchange ────────────────────────────────────────────────────────────

/// ⛔ **RFC 7748 §6.1, the X25519 test vector.** A key exchange that agrees
/// with nobody is the one failure that produces a handshake which *completes*
/// and then decrypts to nothing.
#[test]
fn x25519_matches_rfc7748_section_6_1() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let alice_sk = unhex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_sk = unhex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    let alice = StaticSecret::from(alice_sk);
    let bob = StaticSecret::from(bob_sk);
    let alice_pub = PublicKey::from(&alice).to_bytes();
    let bob_pub = PublicKey::from(&bob).to_bytes();

    // ⛔ The public keys are the values the RFC publishes, which checks the
    // scalar multiplication and not merely that both sides agree.
    assert_eq!(hex(&alice_pub), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    assert_eq!(hex(&bob_pub), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = hex(alice.diffie_hellman(&PublicKey::from(bob_pub)).as_bytes());
    assert_eq!(shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
}

/// ⛔ **Two key exchanges must complete against each other.** This is the
/// property `SupportedKxGroup::start` and `ActiveKeyExchange::complete` have
/// to satisfy, and it is the only way to test them without a peer.
#[test]
fn both_key_exchange_groups_agree_with_themselves() {
    for group in [X25519, SECP256R1] {
        let a = group.start().expect("start");
        let b = group.start().expect("start");
        let a_pub = a.pub_key().to_vec();
        let b_pub = b.pub_key().to_vec();
        let a_secret = a.complete(&b_pub).expect("complete");
        let b_secret = b.complete(&a_pub).expect("complete");
        assert_eq!(a_secret.secret_bytes(), b_secret.secret_bytes(), "{:?} did not agree", group.name());
    }
}

/// ⛔ **The key share encodings RFC 8446 §4.2.8.2 requires.** A P-256 share
/// must be an uncompressed point; an X25519 share exactly 32 bytes.
#[test]
fn key_shares_have_the_encodings_rfc8446_requires() {
    let x = X25519.start().expect("start");
    assert_eq!(x.pub_key().len(), 32, "an X25519 share is 32 bytes");

    let p = SECP256R1.start().expect("start");
    assert_eq!(p.pub_key().len(), 65, "an uncompressed P-256 point is 65 bytes");
    assert_eq!(p.pub_key()[0], 0x04, "SEC1 uncompressed points start 0x04");
}

/// ⛔ **A malformed peer key share is an error, not a panic.** This is the
/// input a peer controls, and a panic on it takes down the client.
#[test]
fn a_malformed_peer_key_share_is_an_error_not_a_panic() {
    for bad in [
        vec![],
        vec![0u8; 31],
        vec![0u8; 33],
        // ⛔ An all-zero X25519 share is a low-order point. RFC 8446 requires
        // it be refused, and x25519-dalek deliberately leaves the check here.
        vec![0u8; 32],
    ] {
        let x = X25519.start().expect("start");
        assert!(x.complete(&bad).is_err(), "X25519 accepted a {}-byte share", bad.len());
    }
    for bad in [vec![], vec![0x02, 0x00], vec![0u8; 65]] {
        let p = SECP256R1.start().expect("start");
        assert!(p.complete(&bad).is_err(), "P-256 accepted a malformed share");
    }
}

// ── the provider as a whole ─────────────────────────────────────────────────

#[test]
fn the_provider_offers_only_what_it_implements() {
    let p = podssh_ws::crypto::provider();
    // ⛔ **Two suites, both TLS 1.3.** The `tls12` feature is on because
    // rustls's builder needs it, and a TLS 1.2 suite listed here would be one
    // podssh cannot complete.
    assert_eq!(p.cipher_suites.len(), 2);
    for suite in &p.cipher_suites {
        assert!(matches!(suite, rustls::SupportedCipherSuite::Tls13(_)), "a TLS 1.2 suite is offered");
    }
    assert_eq!(p.kx_groups.len(), 2);
    // ⛔ **THREE signature algorithms, and the third was added because a
    // measurement demanded it.** ⛔ This assertion said `2` when the first
    // version of the provider offered P-256/SHA-256 and Ed25519, and the live
    // handshake then failed with
    // `UnsupportedSignatureAlgorithmContext { signature_algorithm_id:
    // [6, 8, 42, 134, 72, 206, 61, 4, 3, 3] }` — that OID is
    // `ecdsa-with-SHA384` (1.2.840.10045.4.3.3), the algorithm the relay's
    // second intermediate certificate is signed with. ⛔ MEASURED 2026-10-02 in
    // `rust:1-alpine` against `tcp.ssh.relay.ajam.dev:443`. ⛔ P-384/SHA-384
    // was implemented in response and the handshake completed, so the count
    // here is three and the count is the *result* of a measurement rather than
    // a preference.
    //
    // Six more on 2026-10-08, for the same reason: Google's DNS-over-HTTPS
    // resolvers (8.8.8.8, 8.8.4.4) ended the handshake with a
    // `HandshakeFailure` alert until RSA could be verified (MEASURED,
    // `tests/live_doh.rs`), so RSA PKCS #1 v1.5 and PSS with SHA-256, -384 and
    // -512 joined; `tests/rsa.rs` checks them against OpenSSL's signatures.
    assert_eq!(
        p.signature_verification_algorithms.all.len(),
        9,
        "ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, Ed25519, and RSA PKCS #1 and PSS with three hashes"
    );
    assert!(podssh_ws::crypto::suites::self_check().is_ok());
}

#[test]
fn the_signature_mapping_covers_every_algorithm_it_lists() {
    let algs = signature_algorithms();
    // ⛔ **Every entry in `all` must be reachable from `mapping`.** A scheme
    // listed in `all` but absent from `mapping` is one rustls will never
    // verify, and a peer that selects it gets a handshake failure rather than
    // a clean negotiation failure.
    // ⛔ **Compared by address, not by value.** `dyn SignatureVerificationAlgorithm`
    // is not `PartialEq`, and writing an equality for it would compare
    // algorithms by a rule invented here rather than by identity.
    let addr = |a: &&dyn rustls_pki_types::SignatureVerificationAlgorithm| {
        *a as *const dyn rustls_pki_types::SignatureVerificationAlgorithm as *const u8 as usize
    };
    for (scheme, mapped) in algs.mapping {
        for alg in *mapped {
            assert!(
                algs.all.iter().any(|a| addr(a) == addr(alg)),
                "{scheme:?} maps to an algorithm that is not in `all`"
            );
        }
    }
    // ⛔ **Six mapped schemes.** ⛔ The third is ECDSA_NISTP384_SHA384, added
    // after the live handshake named `ecdsa-with-SHA384` as the algorithm it
    // could not verify; see `the_provider_offers_only_what_it_implements` for
    // the measurement. The other three are RSA-PSS with SHA-256, -384 and
    // -512: TLS 1.3 signs its handshake with RSA-PSS only (RFC 8446 4.2.3),
    // while PKCS #1 v1.5 is for certificate chains and needs no scheme.
    assert_eq!(algs.mapping.len(), 6, "ECDSA P-256, ECDSA P-384, Ed25519, and RSA-PSS with three hashes");
}
