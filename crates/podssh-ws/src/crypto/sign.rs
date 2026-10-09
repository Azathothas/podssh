//! Signature verification, for the certificate chain and for the handshake.
//!
//! **The `AlgorithmIdentifier`s come from `rustls-pki-types`, never from
//! hand-written DER.** A wrong OID does not fail loudly: it fails as "unknown
//! public key algorithm", which reads as a corrupt chain rather than as a
//! provider that names the wrong curve.

use std::fmt;
use std::sync::Arc;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::SignatureScheme;
use rustls_pki_types::alg_id;
use rustls_pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

use super::rsa_sig;

/// Only three algorithms, and **each one is here because the live relay's
/// certificate chain required it.** An algorithm nobody has exchanged a
/// certificate with is a claim.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256Sha256;
/// **P-384 with SHA-384, and the measurement demanded it.** The first
/// version of this provider offered P-256/SHA-256 and Ed25519 only, and the
/// live handshake failed with
/// `UnsupportedSignatureAlgorithmContext { signature_algorithm_id:
/// [6, 8, 42, 134, 72, 206, 61, 4, 3, 3] }` — that OID is
/// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3), and it is the algorithm the
/// relay's second intermediate certificate is signed with. MEASURED
/// 2026-10-02 in `rust:1-alpine` against `tcp.ssh.relay.ajam.dev:443`.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP384Sha384;
pub static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519Verify;

/// RSA joined on 2026-10-08, when a measurement needed it (see
/// [`super::rsa_sig`]): Google's DNS-over-HTTPS resolvers refuse a client
/// that cannot verify RSA, and TLS-intercepting proxies often use RSA.
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P384_SHA384,
        ECDSA_P256_SHA256,
        ED25519,
        rsa_sig::RSA_PKCS1_SHA256,
        rsa_sig::RSA_PKCS1_SHA384,
        rsa_sig::RSA_PKCS1_SHA512,
        rsa_sig::RSA_PSS_SHA256,
        rsa_sig::RSA_PSS_SHA384,
        rsa_sig::RSA_PSS_SHA512,
    ],
    // **The order is the preference sent to the peer, and it came from the
    // measurement rather than from taste.** P-384 is first because the chain
    // is signed with SHA-384. P-256 stays because the leaf and the first
    // intermediate are on it — a client that dropped it would fail on the
    // next certificate the edge serves.
    mapping: &[
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[ECDSA_P384_SHA384, ECDSA_P256_SHA256]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256, ECDSA_P384_SHA384]),
        (SignatureScheme::ED25519, &[ED25519]),
        // TLS 1.3 signs the handshake with RSA-PSS only (RFC 8446 4.2.3).
        (SignatureScheme::RSA_PSS_SHA256, &[rsa_sig::RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[rsa_sig::RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[rsa_sig::RSA_PSS_SHA512]),
    ],
};

pub fn signature_algorithms() -> WebPkiSupportedAlgorithms {
    SUPPORTED_SIG_ALGS
}

// ── ECDSA P-384 with SHA-384 ────────────────────────────────────────────────

#[derive(Debug)]
pub struct EcdsaP384Sha384;

impl SignatureVerificationAlgorithm for EcdsaP384Sha384 {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        // **The same key shape rule as P-256, and it is repeated rather than
        // shared because each names a different crate type.** A generic helper
        // over "an EC curve" would need a trait these two crates do not share.
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let sig = p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        use p384::ecdsa::signature::Verifier as _;
        // `Verifier` hashes with P-384's default digest, SHA-384, which is
        // exactly the `ecdsa-with-SHA384` this algorithm declares. Pairing
        // this key with a P-256 signature would be a different algorithm, and
        // webpki would have to be trusted not to do that.
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P384
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA384
    }
}

// ── ECDSA P-256 with SHA-256 ────────────────────────────────────────────────

#[derive(Debug)]
pub struct EcdsaP256Sha256;

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        // **The EC point, with its SEC1 `0x04` tag.** `from_sec1_bytes`
        // parses the whole `ECPoint`, tag included, so a bare 64-byte
        // coordinate pair is refused and the refusal is indistinguishable from
        // a bad signature: both are `InvalidSignature`.
        //
        // MEASURED 2026-10-02 in `rust:1-alpine`: this is not theoretical.
        // `rustls-webpki` hands the `SignatureVerificationAlgorithm` the
        // content of the SPKI's BIT STRING *with the unused-bits byte still
        // attached* — `signed_data.rs:241` passes `spki.key_value`, and
        // `der.rs:344` builds that by `read_byte()` for the unused-bit count
        // and then `read_bytes_to_end()`. So the live relay's certificate
        // chain verified because its `0x04` happened to sit one position before
        // `from_sec1_bytes` found a point it accepted, while podssh's own
        // hand-minted certificate — whose point also starts `04` — was refused
        // with `BadSignature` in every one of the three hostname tests.
        // Two forms are accepted, and both are a real encoding: the SEC1
        // point, and the point with the tag removed (RFC 5480 §2.2 and RFC 5915
        // carry them in that order and both occur in the wild).
        let key = match public_key.first() {
            Some(0x04) => VerifyingKey::from_sec1_bytes(public_key),
            _ => {
                let mut tagged = Vec::with_capacity(public_key.len() + 1);
                tagged.push(0x04);
                tagged.extend_from_slice(public_key);
                VerifyingKey::from_sec1_bytes(&tagged)
            }
        }
        .map_err(|_| InvalidSignature)?;
        let sig = Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        // `Verifier` hashes the message with the curve's default digest,
        // which for P-256 is SHA-256 — matching `ECDSA_SHA256` above. A
        // signature over a different digest is a different algorithm.
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}

// ── Ed25519 ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Ed25519Verify;

impl SignatureVerificationAlgorithm for Ed25519Verify {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        use ed25519_dalek::Verifier as _;
        // `from_bytes` takes the 32-byte raw key, and the signature is the
        // raw 64-byte `R || s`, not a DER SEQUENCE. DER-wrapping either is the
        // single most common way to get a chain that validates nowhere. The
        // lengths are checked rather than converted, because a `try_into` that
        // pads a short key would turn a malformed SPKI into a valid-looking
        // verification attempt.
        let key_bytes: &[u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(key_bytes).map_err(|_| InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

// ── the private-key side, which a client never uses ────────────────────────

/// podssh is a client. It never presents a certificate, so `load_private_key`
/// has no legitimate caller and returns an error rather than a key nobody can
/// use. A `KeyProvider` that parsed a key it could never sign with would be a
/// second, unreachable signing path.
pub struct NoClientKeys;

impl fmt::Debug for NoClientKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoClientKeys")
    }
}

impl rustls::crypto::KeyProvider for NoClientKeys {
    fn load_private_key(
        &self,
        _key_der: rustls_pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Err(rustls::Error::General("podssh is a client and holds no private keys".into()))
    }
}
