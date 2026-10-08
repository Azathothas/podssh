//! RSA verification in podssh's TLS provider, against signatures OpenSSL made
//! (tests/fixtures/rsa/README.md).

use podssh_ws::crypto::rsa_sig::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PSS_SHA256, RSA_PSS_SHA384};

const MSG: &[u8] = include_bytes!("fixtures/rsa/msg");
const KEY: &[u8] = include_bytes!("fixtures/rsa/pub.der");
const PKCS1_SHA256: &[u8] = include_bytes!("fixtures/rsa/pkcs1.sig");
const PSS_SHA384: &[u8] = include_bytes!("fixtures/rsa/pss384.sig");
const SMALL_KEY: &[u8] = include_bytes!("fixtures/rsa/small.der");
const SMALL_SIG: &[u8] = include_bytes!("fixtures/rsa/small.sig");

#[test]
fn openssl_signatures_verify() {
    RSA_PKCS1_SHA256.verify_signature(KEY, MSG, PKCS1_SHA256).expect("PKCS #1 v1.5 SHA-256");
    RSA_PSS_SHA384.verify_signature(KEY, MSG, PSS_SHA384).expect("PSS SHA-384");
}

#[test]
fn a_changed_message_padding_or_hash_is_refused() {
    let mut other = MSG.to_vec();
    other[0] ^= 1;
    assert!(RSA_PKCS1_SHA256.verify_signature(KEY, &other, PKCS1_SHA256).is_err());
    assert!(RSA_PSS_SHA256.verify_signature(KEY, MSG, PKCS1_SHA256).is_err(), "PKCS #1 signature as PSS");
    assert!(RSA_PKCS1_SHA384.verify_signature(KEY, MSG, PSS_SHA384).is_err(), "PSS signature as PKCS #1");
    assert!(RSA_PSS_SHA256.verify_signature(KEY, MSG, PSS_SHA384).is_err(), "wrong hash");
    let mut sig = PKCS1_SHA256.to_vec();
    sig[10] ^= 0x40;
    assert!(RSA_PKCS1_SHA256.verify_signature(KEY, MSG, &sig).is_err());
}

#[test]
fn a_key_under_2048_bits_is_refused_even_with_a_good_signature() {
    assert!(RSA_PKCS1_SHA256.verify_signature(SMALL_KEY, MSG, SMALL_SIG).is_err());
}
