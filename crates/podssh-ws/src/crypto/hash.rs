//! SHA-256 and SHA-384 as `rustls::crypto::hash`.
//!
//! ⛔ **The provider is a proposal until it has exchanged a certificate with a
//! real peer.** A `CryptoProvider` that has never completed a handshake is a
//! struct with plausible contents, so every piece of it is asserted against a
//! published test vector rather than against itself.

use std::fmt;

use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use sha2::{Digest, Sha256, Sha384};

/// ⛔ One enum rather than two types, so a suite cannot be built with a SHA-256
/// hash and a SHA-384 HKDF. That pairing is not detectable at the type level
/// once both are behind `&'static dyn`, and it produces a handshake that
/// fails in the key schedule rather than at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithmId {
    Sha256,
    Sha384,
}

impl HashAlgorithmId {
    pub fn algorithm(self) -> HashAlgorithm {
        match self {
            HashAlgorithmId::Sha256 => HashAlgorithm::SHA256,
            HashAlgorithmId::Sha384 => HashAlgorithm::SHA384,
        }
    }

    /// The output length in bytes, which is `HashLen` in RFC 5869.
    pub fn output_len(self) -> usize {
        match self {
            HashAlgorithmId::Sha256 => 32,
            HashAlgorithmId::Sha384 => 48,
        }
    }
}

pub static SHA256: &dyn Hash = &PureHash(HashAlgorithmId::Sha256);
pub static SHA384: &dyn Hash = &PureHash(HashAlgorithmId::Sha384);

#[derive(Debug)]
pub struct PureHash(pub HashAlgorithmId);

/// ⛔ `Sha256` and `Sha384` are different types, so the enum is dispatched
/// rather than boxed. A `Box<dyn Digest>` here would heap-allocate on every
/// `start()`, which for a transcript hash is a per-record cost.
#[derive(Clone)]
enum AnyDigest {
    S256(Sha256),
    S384(Sha384),
}

impl AnyDigest {
    fn new(id: HashAlgorithmId) -> Self {
        match id {
            HashAlgorithmId::Sha256 => AnyDigest::S256(Sha256::new()),
            HashAlgorithmId::Sha384 => AnyDigest::S384(Sha384::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            AnyDigest::S256(h) => h.update(data),
            AnyDigest::S384(h) => h.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            AnyDigest::S256(h) => h.finalize().to_vec(),
            AnyDigest::S384(h) => h.finalize().to_vec(),
        }
    }
}

impl Hash for PureHash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(PureContext {
            digest: AnyDigest::new(self.0),
        })
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&AnyDigest::new(self.0).finalize_with(data))
    }

    fn output_len(&self) -> usize {
        self.0.output_len()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.0.algorithm()
    }
}

impl AnyDigest {
    /// The one-shot form, so `hash()` and `start().finish()` cannot disagree
    /// about the padding — the transcript hash and the standalone hash must be
    /// the same function.
    fn finalize_with(mut self, data: &[u8]) -> Vec<u8> {
        self.update(data);
        self.finalize()
    }
}

struct PureContext {
    digest: AnyDigest,
}

impl Context for PureContext {
    fn fork_finish(&self) -> Output {
        Output::new(&self.digest.clone().finalize())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(PureContext {
            digest: self.digest.clone(),
        })
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.digest.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.digest.update(data);
    }
}

impl fmt::Display for PureHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
