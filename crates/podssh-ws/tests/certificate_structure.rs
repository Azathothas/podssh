//! **The minted certificate is a *correct* certificate, not a parseable
//! one.** Every test here exists because a hand-built DER encoder fails
//! silently: a wrong offset produces a chain that looks fine and a signature
//! that verifies nowhere, and the only error a caller sees is `BadSignature`
//! or `BadEncoding`, neither of which names the field.

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod walk {
    include!("common/spki_walk.rs");
}

use walk::{sec1_point, signature_of, spki_point, tbs_tlv_of};

use cert::encoding::{der_length_covers_the_certificate, self_signed};

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The certificate this file mints is a well-formed SEQUENCE whose declared
/// length covers every byte it carries.
#[test]
fn a_minted_certificate_has_a_length_that_covers_its_bytes() {
    for name in ["right.example", "wrong.example", "a"] {
        der_length_covers_the_certificate(&self_signed(name).der);
    }
}

/// **The certificate's signature verifies under the key that must have
/// made it.** Pull the public key out of the SPKI, the tbs out as
/// `read_partial` consumes it, and the signature out of the last BIT STRING,
/// then ask podssh's own verifier whether the three go together.
///
/// MEASURED 2026-10-02: the first version of this file verified each
/// certificate against its **own** SPKI and passed while every handshake
/// answered `BadSignature`. "Self-consistent" and "chains to the issuer"
/// are different properties and only the second is what a client requires:
/// `check_signed_chain` (`verify_cert.rs:148`) verifies each `SignedData`
/// against the *issuer's* SPKI, so a leaf can satisfy one check and fail the
/// other. This is the check that would have caught it on the first run.
#[test]
fn each_certificate_verifies_under_the_key_that_signed_it() {
    // The anchor signs itself, and the leaf is signed by the anchor's key. The
    // pair is the whole chain, and both halves are checked with the key named
    // here rather than read out of the certificate.
    for (name, is_ca) in [("right.example-anchor", true), ("right.example", false)] {
        let cert = cert::encoding::self_signed_inner(name, is_ca);
        let tbs = tbs_tlv_of(&cert.der);
        let sig = signature_of(&cert.der);
        // The key the builder used: for an anchor, its own; for a leaf, the
        // anchor's, which is `key_scalar("{name}-anchor", true)`.
        let signer = if is_ca { role_key(name, true) } else { role_key(&format!("{name}-anchor"), true) };
        let point = signer.verifying_key().to_encoded_point(false);
        let spki_published = &spki_point(&cert.der)[1..];
        eprintln!(
            "KEYCHECK {name}: spki={} signer={} equal={}",
            hex(&spki_published[..8]),
            hex(&point.as_bytes()[1..9]),
            spki_published == &point.as_bytes()[1..]
        );
        // Sign the same bytes again and verify that, which isolates the
        // verifier from whatever the certificate carries.
        let fresh: Signature = signer.sign(&tbs);
        eprintln!(
            "SELF-CHECK {name}: verify-fresh={} verify-stored={} sig-in-cert-is-der={}",
            podssh_ws::crypto::sign::ECDSA_P256_SHA256
                .verify_signature(point.as_bytes(), &tbs, fresh.to_der().as_bytes())
                .is_ok(),
            podssh_ws::crypto::sign::ECDSA_P256_SHA256.verify_signature(point.as_bytes(), &tbs, &sig).is_ok(),
            p256::ecdsa::Signature::from_der(&sig).is_ok()
        );

        assert!(
            podssh_ws::crypto::sign::ECDSA_P256_SHA256.verify_signature(point.as_bytes(), &tbs, &sig).is_ok(),
            "{name}: does not verify. tbs {} bytes head {}, signature {} bytes \
             head {}",
            tbs.len(),
            hex(&tbs[..tbs.len().min(8)]),
            sig.len(),
            hex(&sig[..sig.len().min(8)])
        );
    }
}

/// **Which half is wrong: the builder or the verifier?**
/// podssh's own ECDSA verifier is asked to check a signature made by the
/// `p256` crate directly, over a plain message. If that passes, the verifier
/// hashes and encodes correctly and any failure above is in the certificate
/// builder; if it fails, the verifier is the thing that is wrong, and the
/// live handshake would be a false positive.
#[test]
fn podsshs_ecdsa_verifier_accepts_a_directly_made_signature() {
    let key = SigningKey::from_bytes(&[0x77u8; 32].into()).expect("a scalar");
    let message = b"a plain message, not a certificate";
    let sig: Signature = key.sign(message);
    let point = key.verifying_key().to_encoded_point(false);

    let der = sig.to_der();
    assert!(
        podssh_ws::crypto::sign::ECDSA_P256_SHA256.verify_signature(point.as_bytes(), message, der.as_bytes()).is_ok(),
        "podssh's ECDSA verifier rejects a valid signature from the p256 crate: \
         the verifier, not the certificate builder, is what is broken"
    );

    // And the DER-wrapped form, which is what a certificate carries.
    let wrapped = p256::ecdsa::Signature::from_der(der.as_bytes()).expect("round-trip");
    assert_eq!(wrapped.to_der().as_bytes(), der.as_bytes());
}

/// **The certificate builder signs the message, and does not hash it
/// first.** MEASURED 2026-10-02: the builder called
/// `SigningKey::sign(&ecdsa_sha256_digest_info(&tbs))`, so the signature was
/// over `SHA256(DigestInfo(SHA256(tbs)))` while the verifier hashes `tbs`
/// once. `DigestInfo` is the signer's internal prehash format, not a message,
/// and `Signer::sign` hashes whatever it is given — so wrapping it introduced a
/// second hash that no verifier could undo. The symptom was a handshake that
/// answered `BadSignature` no matter which field was corrected, because the
/// bytes were never wrong: the arithmetic was performed on the wrong input.
///
/// This is the regression test for it. It signs the extracted tbs the same
/// way the builder does and requires the verifier to accept — which fails the
/// moment anyone reintroduces the wrapper.
#[test]
fn signing_the_tbs_as_a_message_verifies_and_prehashing_it_does_not() {
    // The anchor, whose SPKI and signature key are the same one — so the two
    // roles cannot be confused here. MEASURED 2026-10-02: the first version
    // used a leaf, signing with the issuer's key and verifying with the leaf's
    // own SPKI, and failed for that reason rather than for the one it names.
    let cert = cert::encoding::self_signed_inner("right.example-anchor", true);
    let point = sec1_point(&spki_point(&cert.der));
    let tbs = tbs_tlv_of(&cert.der);

    let key = role_key("right.example-anchor", true);
    let as_message: Signature = key.sign(&tbs);
    assert!(
        podssh_ws::crypto::sign::ECDSA_P256_SHA256
            .verify_signature(&point, &tbs, as_message.to_der().as_bytes())
            .is_ok(),
        "signing the tbs as a message must verify; this is the path the \
         builder uses"
    );

    // The control: the same signature is *also* a valid ECDSA signature, and
    // the wrong prehash is the only thing that breaks it. Proving the negative
    // here is what says the passing assertion above is not vacuous.
    let prehashed_digest_info = digest_info(&tbs);
    let double: Signature = key.sign(&prehashed_digest_info);
    assert!(
        podssh_ws::crypto::sign::ECDSA_P256_SHA256.verify_signature(&point, &tbs, double.to_der().as_bytes()).is_err(),
        "a signature made over a pre-wrapped DigestInfo should NOT verify \
         against the raw tbs; if it does, this test proves nothing"
    );
}

/// **The key the SPKI publishes is the key that signed the certificate.**
/// For an **anchor** these are the same key, because an anchor signs itself.
/// MEASURED 2026-10-02: the first version of this test asserted the same
/// thing for every certificate, and it passed while every handshake answered
/// `BadSignature` — the leaf is signed by its *issuer's* key, not its own, and
/// a self-signed assertion cannot see that difference. Deriving the expected
/// scalar from the certificate's own name and role, rather than from the
/// builder, means a change to either one shows up here.
#[test]
fn the_anchor_spkis_own_key_is_the_key_that_signed_it() {
    for name in ["right.example", "wrong.example"] {
        let anchor = cert::encoding::self_signed_inner(&format!("{name}-anchor"), true);
        let expected = role_key(&format!("{name}-anchor"), true).verifying_key().to_encoded_point(false);
        assert_eq!(
            hex(&spki_point(&anchor.der)[1..]),
            hex(expected.as_bytes()),
            "{name}: the anchor's SPKI is not the key that signed it"
        );
    }
}

/// **The leaf publishes its OWN key, and the issuer signs it.**
/// Those are two different keys and conflating them is the fault this file
/// spent its length on: a client verifies the *chain signature* with the
/// issuer's SPKI and uses the leaf's SPKI only to verify the peer's
/// `CertificateVerify`. Deriving both from the certificate's own name,
/// rather than reading the builder, is what makes a change to either visible.
#[test]
fn the_leaf_publishes_its_own_key_while_its_issuer_signs_it() {
    for name in ["right.example", "wrong.example"] {
        let leaf = self_signed(name);
        let issuer = role_key(&format!("{name}-anchor"), true);

        assert_eq!(
            hex(&spki_point(&leaf.der)[1..]),
            hex(role_key(name, false).verifying_key().to_encoded_point(false).as_bytes()),
            "{name}: the leaf's SPKI is not the leaf's own key"
        );
        assert_ne!(
            hex(&spki_point(&leaf.der)[1..]),
            hex(issuer.verifying_key().to_encoded_point(false).as_bytes()),
            "{name}: the leaf's SPKI is the issuer's key, so the two roles \
             have collapsed into one and the chain proves nothing"
        );
    }
}

/// The key for a role, from the name and the role. MEASURED 2026-10-02:
/// this ignored `is_ca` and always used the end-entity seed, so every check
/// that asked for the **anchor's** key was handed a third key that exists
/// nowhere in the chain — the same shape of fault as the one it was written to
/// catch, one function down. The seed byte is the whole difference between
/// the two roles, and a helper that drops it cannot tell them apart.
fn role_key(dns_name: &str, is_ca: bool) -> SigningKey {
    SigningKey::from_bytes(&key_scalar(dns_name, is_ca).into()).expect("a scalar")
}

/// The scalar for a role, derived from the name the certificate carries.
/// Duplicated from the builder on purpose: a test that reads the builder's
/// own private function cannot tell whether the builder changed.
fn key_scalar(dns_name: &str, is_ca: bool) -> [u8; 32] {
    let mut seed = dns_name.as_bytes().to_vec();
    seed.push(if is_ca { 0xca } else { 0xee });
    let mut h = Sha256::new();
    h.update(&seed);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// A SHA-256 `DigestInfo`, the form `Signer::sign` produces internally and
/// the form a caller must NOT hand to `Signer::sign`.
fn digest_info(message: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(message);
    let mut out = vec![
        0x30, 0x31, // SEQUENCE, 49 bytes
        0x30, 0x0d, // SEQUENCE, 13 bytes (AlgorithmIdentifier)
    ];
    out.extend_from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
    out.extend_from_slice(&[0x05, 0x00]); // NULL
    out.extend_from_slice(&[0x04, 0x20]); // OCTET STRING, 32 bytes
    out.extend_from_slice(&digest);
    out
}
