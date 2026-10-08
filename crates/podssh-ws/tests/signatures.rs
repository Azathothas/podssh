//! ⛔ **Signature verification, against published vectors and against a live
//! chain.**
//!
//! ⛔ **Why this is a second file.** `crypto_vectors.rs` reached 510 lines when
//! the provider grew a third signature algorithm, and the 500-line cap is a
//! gate rather than advice. ⛔ The block moved here whole; no comment was
//! deleted to make room, because a file that only fits because its comments
//! were removed is not a split.

use podssh_ws::crypto::sign::{ECDSA_P256_SHA256, ECDSA_P384_SHA384, ED25519};
use rustls_pki_types::SignatureVerificationAlgorithm;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── ECDSA P-256 with SHA-256 ────────────────────────────────────────────────

/// ⛔ **ECDSA P-256/SHA-256, self-signed and verified.** The key and the
/// message are generated here, so this asserts the *encoding* contract: a raw
/// SEC1 point in, a DER signature out.
#[test]
fn ecdsa_p256_sha256_verifies_a_real_signature_and_rejects_a_tampered_one() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    let signing_key = SigningKey::from_bytes(&[0x42u8; 32].into()).expect("a scalar");
    let verifying_key = signing_key.verifying_key();
    let message = b"the bytes rustls signs in a TLS 1.3 CertificateVerify";
    let signature: Signature = signing_key.sign(message);

    let spki_point = verifying_key.to_encoded_point(false);
    let raw = spki_point.as_bytes();
    assert_eq!(raw[0], 0x04, "webpki is handed the raw point, uncompressed");

    assert!(
        ECDSA_P256_SHA256
            .verify_signature(raw, message, signature.to_der().as_bytes())
            .is_ok(),
        "a valid ECDSA signature did not verify"
    );

    // ⛔ **The message is authenticated.** A signature that verified over a
    // different message would accept a replayed handshake signature.
    assert!(
        ECDSA_P256_SHA256
            .verify_signature(raw, b"a different message", signature.to_der().as_bytes())
            .is_err(),
        "ECDSA verified a signature over the wrong message"
    );
    // ⛔ **So is the key.** A signature verified under any other key would make
    // the chain's issuer irrelevant.
    let other = SigningKey::from_bytes(&[0x43u8; 32].into()).expect("a scalar");
    assert!(
        ECDSA_P256_SHA256
            .verify_signature(
                other.verifying_key().to_encoded_point(false).as_bytes(),
                message,
                signature.to_der().as_bytes()
            )
            .is_err(),
        "ECDSA verified under the wrong key"
    );
    // ⛔ **And a truncated signature is rejected**, not treated as a DER parse
    // that happens to succeed.
    let der = signature.to_der();
    assert!(
        ECDSA_P256_SHA256
            .verify_signature(raw, message, &der.as_bytes()[..der.len() - 1])
            .is_err(),
        "ECDSA accepted a truncated signature"
    );
}

/// ⛔ **Ed25519, RFC 8032 test vector 1.** The secret, public and message are
/// the RFC's, so this is a check against the standard and not a round-trip
/// with itself.
#[test]
fn ed25519_matches_rfc8032_vector_1() {
    use ed25519_dalek::{Signer, VerifyingKey};

    let secret: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
        0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
        0x1c, 0xae, 0x7f, 0x60,
    ];
    let expected_public: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
        0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
        0xf7, 0x07, 0x51, 0x1a,
    ];
    let message: &[u8] = b"";

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let signature = signing_key.sign(message);
    assert_eq!(
        hex(&signature.to_bytes()),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    assert_eq!(
        hex(signing_key.verifying_key().as_bytes()),
        hex(&expected_public)
    );

    assert!(
        ED25519
            .verify_signature(&expected_public, message, &signature.to_bytes())
            .is_ok(),
        "the RFC 8032 signature did not verify"
    );
    // ⛔ **A public key of the wrong length is rejected.** ⛔ The `try_into` in
    // `Ed25519Verify` is what stops a 33-byte "Ed25519 key" from being
    // zero-extended into a valid-looking one.
    assert!(ED25519
        .verify_signature(&[0u8; 31], message, &signature.to_bytes())
        .is_err());
    assert!(ED25519
        .verify_signature(&[0u8; 33], message, &signature.to_bytes())
        .is_err());
}

// ── ECDSA P-384 with SHA-384 ────────────────────────────────────────────────

/// ⛔ **P-384/SHA-384, and this algorithm exists because a measurement named
/// it.** ⛔ MEASURED 2026-10-02 in `rust:1-alpine`: the live handshake failed
/// with `UnsupportedSignatureAlgorithmContext { signature_algorithm_id:
/// [6, 8, 42, 134, 72, 206, 61, 4, 3, 3] }`, and that OID is
/// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3) — the algorithm the relay's
/// second intermediate certificate is signed with.
///
/// ⛔ The same three rules as P-256 hold here, and they are asserted again
/// rather than assumed: a valid signature verifies, and a different message, a
/// different key and a truncated signature do not.
#[test]
fn ecdsa_p384_sha384_verifies_and_rejects_the_same_three_ways() {
    use p384::ecdsa::signature::Signer;
    use p384::ecdsa::{Signature, SigningKey};

    let signing_key = SigningKey::from_bytes(&[0x51u8; 48].into()).expect("a scalar");
    let verifying_key = signing_key.verifying_key();
    let message = b"a transcript hash signed over P-384";
    let signature: Signature = signing_key.sign(message);
    let point = verifying_key.to_encoded_point(false);
    let raw = point.as_bytes();
    let der = signature.to_der();

    assert_eq!(raw[0], 0x04, "an uncompressed P-384 point starts 0x04");
    assert_eq!(raw.len(), 97, "an uncompressed P-384 point is 97 bytes");

    assert!(
        ECDSA_P384_SHA384
            .verify_signature(raw, message, der.as_bytes())
            .is_ok(),
        "a valid P-384 signature did not verify"
    );
    assert!(
        ECDSA_P384_SHA384
            .verify_signature(raw, b"a different message", der.as_bytes())
            .is_err(),
        "⛔ P-384 verified a signature over the wrong message"
    );
    let other = SigningKey::from_bytes(&[0x52u8; 48].into()).expect("a scalar");
    let other_point = other.verifying_key().to_encoded_point(false);
    assert!(
        ECDSA_P384_SHA384
            .verify_signature(
                other_point.as_bytes(),
                message,
                der.as_bytes()
            )
            .is_err(),
        "⛔ P-384 verified under the wrong key"
    );
    assert!(
        ECDSA_P384_SHA384
            .verify_signature(raw, message, &der.as_bytes()[..der.len() - 1])
            .is_err(),
        "⛔ P-384 accepted a truncated signature"
    );
}

/// ⛔ **A P-384 key is not a P-256 key.** ⛔ The two algorithms differ only in
/// the `AlgorithmIdentifier` they report, so a provider that got the mapping
/// wrong would accept a P-256 signature under the P-384 name — and the
/// cross-check here is what says it does not.
#[test]
fn a_p256_signature_does_not_verify_as_p384() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey as P256Signing;

    let key = P256Signing::from_bytes(&[0x61u8; 32].into()).expect("a scalar");
    let message = b"cross-curve";
    let sig: p256::ecdsa::Signature = key.sign(message);
    let point = key.verifying_key().to_encoded_point(false);

    // A 65-byte point cannot be a P-384 key: the length is 97.
    assert!(ECDSA_P384_SHA384
        .verify_signature(point.as_bytes(), message, sig.to_der().as_bytes())
        .is_err());
}
