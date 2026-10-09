//! RSA signature verification: PKCS #1 v1.5 (certificate chains) and PSS
//! (TLS 1.3 handshakes, and chains that use it), with SHA-256, -384 and -512.
//!
//! Added 2026-10-08 because a measurement needed it: Google's DNS-over-HTTPS
//! resolvers (8.8.8.8) end the handshake unless the client can verify RSA, and
//! TLS-intercepting proxies commonly present RSA certificates. Verification
//! uses public keys only, so the `rsa` crate's private-key timing issue
//! (RUSTSEC-2023-0071) does not apply. Keys must be 2048 to 4096 bits.

use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, Pss, RsaPublicKey};
use rustls_pki_types::{alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Debug, Clone, Copy)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy)]
enum Padding {
    Pkcs1,
    Pss,
}

/// One RSA verification algorithm: a hash and a padding.
#[derive(Debug)]
pub struct RsaVerify {
    hash: Hash,
    padding: Padding,
}

pub static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm =
    &RsaVerify { hash: Hash::Sha256, padding: Padding::Pkcs1 };
pub static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm =
    &RsaVerify { hash: Hash::Sha384, padding: Padding::Pkcs1 };
pub static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm =
    &RsaVerify { hash: Hash::Sha512, padding: Padding::Pkcs1 };
pub static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm =
    &RsaVerify { hash: Hash::Sha256, padding: Padding::Pss };
pub static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm =
    &RsaVerify { hash: Hash::Sha384, padding: Padding::Pss };
pub static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm =
    &RsaVerify { hash: Hash::Sha512, padding: Padding::Pss };

/// The smallest key accepted, as webpki's own backends require.
const MIN_BITS: usize = 2048;

fn public_key(der: &[u8]) -> Result<RsaPublicKey, InvalidSignature> {
    // `from_pkcs1_der` also refuses keys over 4096 bits.
    let key = RsaPublicKey::from_pkcs1_der(der).map_err(|_| InvalidSignature)?;
    if key.n().bits() < MIN_BITS {
        return Err(InvalidSignature);
    }
    Ok(key)
}

impl SignatureVerificationAlgorithm for RsaVerify {
    fn verify_signature(
        &self,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = public_key(public_key_der)?;
        let result = match (self.hash, self.padding) {
            (Hash::Sha256, Padding::Pkcs1) => {
                key.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(message), signature)
            }
            (Hash::Sha384, Padding::Pkcs1) => {
                key.verify(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(message), signature)
            }
            (Hash::Sha512, Padding::Pkcs1) => {
                key.verify(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(message), signature)
            }
            // Salt length = digest length, as TLS 1.3 and X.509 require.
            (Hash::Sha256, Padding::Pss) => key.verify(Pss::new::<Sha256>(), &Sha256::digest(message), signature),
            (Hash::Sha384, Padding::Pss) => key.verify(Pss::new::<Sha384>(), &Sha384::digest(message), signature),
            (Hash::Sha512, Padding::Pss) => key.verify(Pss::new::<Sha512>(), &Sha512::digest(message), signature),
        };
        result.map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match (self.hash, self.padding) {
            (Hash::Sha256, Padding::Pkcs1) => alg_id::RSA_PKCS1_SHA256,
            (Hash::Sha384, Padding::Pkcs1) => alg_id::RSA_PKCS1_SHA384,
            (Hash::Sha512, Padding::Pkcs1) => alg_id::RSA_PKCS1_SHA512,
            (Hash::Sha256, Padding::Pss) => alg_id::RSA_PSS_SHA256,
            (Hash::Sha384, Padding::Pss) => alg_id::RSA_PSS_SHA384,
            (Hash::Sha512, Padding::Pss) => alg_id::RSA_PSS_SHA512,
        }
    }
}
