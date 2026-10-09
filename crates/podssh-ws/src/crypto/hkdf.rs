//! HKDF for the TLS 1.3 key schedule.
//!
//! **RFC 5869, and the test vectors are the ones in its appendix A.** The
//! key schedule is the one place where a subtly wrong extract produces a
//! handshake that completes and then decrypts to garbage, so this is asserted
//! against the published vectors rather than against itself.

use std::fmt;

use rustls::crypto::hmac::Tag;
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use sha2::Sha256;
use zeroize::Zeroize;

use super::hash::HashAlgorithmId;

/// `hkdf::Hkdf` is monomorphised over the hash, so there are two of them
/// here and the `id` decides which. The alternative — a boxed `DynHash` —
/// would need a trait object per hash and buys nothing at two variants.
pub struct PureHkdf(pub HashAlgorithmId);

impl fmt::Debug for PureHkdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PureHkdf({:?})", self.0)
    }
}

impl Hkdf for PureHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = vec![0u8; self.0.output_len()];
        self.extract_from_secret(salt, &zeroes)
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let hash_len = self.0.output_len();
        // RFC 5869 §2.2: an absent salt is `HashLen` zero bytes, NOT an empty
        // salt. RFC 8446 §7.1 relies on this for the early-secret derivation,
        // so a `None` mapped to `&[]` produces a key schedule that differs from
        // every other implementation's and fails at the first Finished.
        let default_salt = [0u8; 64];
        let salt: &[u8] = salt.unwrap_or(&default_salt[..hash_len]);
        Box::new(Expander { id: self.0, prk: self.extract_prk(salt, secret) })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(Expander { id: self.0, prk: okm.as_ref().to_vec() })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        use super::hmac::{HMAC_SHA256, HMAC_SHA384};
        use rustls::crypto::hmac::Hmac as _;
        let hmac = match self.0 {
            HashAlgorithmId::Sha256 => &HMAC_SHA256,
            HashAlgorithmId::Sha384 => &HMAC_SHA384,
        };
        hmac.with_key(key.as_ref()).sign(&[message])
    }
}

impl PureHkdf {
    /// `HKDF-Extract(salt, ikm)`, returning the PRK.
    ///
    /// **`extract` returns `(Output<H>, Hkdf)` and the first element is the
    /// PRK.** Taking the second and expanding it would silently run
    /// extract-then-expand-one-block and produce a PRK that is not the RFC's.
    fn extract_prk(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        // Each arm converts inside itself. The two `Output` types are
        // different `GenericArray`s, so binding one and converting after the
        // match does not typecheck — which is the compiler refusing to let the
        // two hashes' PRKs be confused.
        match self.0 {
            HashAlgorithmId::Sha256 => hkdf::Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
            HashAlgorithmId::Sha384 => hkdf::Hkdf::<sha2::Sha384>::extract(Some(salt), ikm).0.to_vec(),
        }
    }

    /// **`HKDF-Extract` on its own, for the RFC 5869 vector.**
    ///
    /// The appendix A vectors publish the PRK as well as the OKM, and
    /// asserting both separates an extract bug from an expand bug — a test
    /// that checks only the OKM cannot say which half is wrong.
    pub fn extract_prk_for_test(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        self.extract_prk(salt, ikm)
    }
}

struct Expander {
    id: HashAlgorithmId,
    prk: Vec<u8>,
}

impl Expander {
    fn expand(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        if output.len() > 255 * self.id.output_len() {
            return Err(OutputLengthError);
        }
        // `expand_multi_info` takes the info components separately, so the
        // concatenation rustls hands over as slices is never materialised.
        match self.id {
            HashAlgorithmId::Sha256 => hkdf::Hkdf::<Sha256>::from_prk(&self.prk)
                .map_err(|_| OutputLengthError)?
                .expand_multi_info(info, output)
                .map_err(|_| OutputLengthError),
            HashAlgorithmId::Sha384 => hkdf::Hkdf::<sha2::Sha384>::from_prk(&self.prk)
                .map_err(|_| OutputLengthError)?
                .expand_multi_info(info, output)
                .map_err(|_| OutputLengthError),
        }
    }
}

impl Drop for Expander {
    fn drop(&mut self) {
        // A PRK is key material. `zeroize` is already a dependency and the
        // rest of this crate uses it; an expander that leaves its PRK on the
        // heap is the one place the whole design leaks.
        self.prk.zeroize();
    }
}

impl HkdfExpander for Expander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        self.expand(info, output)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut out = vec![0u8; self.id.output_len()];
        self.expand(info, &mut out).expect("a block of HashLen bytes cannot exceed 255 * HashLen");
        OkmBlock::new(&out)
    }

    fn hash_len(&self) -> usize {
        self.id.output_len()
    }
}
