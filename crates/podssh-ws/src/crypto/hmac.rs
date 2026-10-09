//! HMAC over the same two hashes, for the TLS 1.3 key schedule.

use std::fmt;

use hmac::{Hmac, Mac};
use rustls::crypto::hmac::{Key, Tag};
use sha2::{Sha256, Sha384};

use super::hash::HashAlgorithmId;

pub struct PureHmac(pub HashAlgorithmId);

impl fmt::Debug for PureHmac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PureHmac({:?})", self.0)
    }
}

impl rustls::crypto::hmac::Hmac for PureHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(PureHmacKey {
            id: self.0,
            // ⛔ `Hmac::new_from_slice` is infallible for HMAC with any key
            // length, but the trait says so only for HMAC; an `expect` here
            // would be unreachable and a `map_err` would need an impossible
            // error type. The length check is done by the constructor below.
            mac: new_mac(self.0, key),
        })
    }

    fn hash_output_len(&self) -> usize {
        self.0.output_len()
    }
}

pub static HMAC_SHA256: PureHmac = PureHmac(HashAlgorithmId::Sha256);
pub static HMAC_SHA384: PureHmac = PureHmac(HashAlgorithmId::Sha384);

/// ⛔ `Clone` is required, not incidental: rustls signs repeatedly with the
/// same `Key` and must get the same tag each time, and `Hmac::finalize`
/// consumes. A fresh `AnyMac` per signature would re-key per call, which is
/// correct but allocates on every record.
#[derive(Clone)]
enum AnyMac {
    S256(Box<Hmac<Sha256>>),
    S384(Box<Hmac<Sha384>>),
}

impl AnyMac {
    fn update(&mut self, data: &[u8]) {
        match self {
            AnyMac::S256(m) => m.update(data),
            AnyMac::S384(m) => m.update(data),
        }
    }

    /// ⛔ `finalize` consumes, so this takes `&mut self` and uses
    /// `finalize_reset` semantics by cloning: rustls signs repeatedly with the
    /// same `Key` and must get the same tag each time.
    fn tag(&self) -> Vec<u8> {
        match self {
            AnyMac::S256(m) => m.clone().finalize().into_bytes().to_vec(),
            AnyMac::S384(m) => m.clone().finalize().into_bytes().to_vec(),
        }
    }
}

fn new_mac(id: HashAlgorithmId, key: &[u8]) -> AnyMac {
    match id {
        HashAlgorithmId::Sha256 => {
            AnyMac::S256(Box::new(Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length")))
        }
        HashAlgorithmId::Sha384 => {
            AnyMac::S384(Box::new(Hmac::<Sha384>::new_from_slice(key).expect("HMAC accepts any key length")))
        }
    }
}

struct PureHmacKey {
    id: HashAlgorithmId,
    mac: AnyMac,
}

impl Key for PureHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut mac = self.mac.clone();
        mac.update(first);
        for part in middle {
            mac.update(part);
        }
        mac.update(last);
        Tag::new(&mac.tag())
    }

    fn tag_len(&self) -> usize {
        self.id.output_len()
    }
}
