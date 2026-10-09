//! Ephemeral key exchange: X25519 and secp256r1.
//!
//! **The two groups the relay's TLS stack actually negotiates.** Every
//! group here has completed a handshake with the live peer; a group that had
//! not would be a claim, not a capability.

use std::fmt;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rustls::crypto::{ActiveKeyExchange, GetRandomFailed, SecureRandom, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize as _;

/// `x25519-dalek` 2.0's `StaticSecret` clamps on construction, which is what
/// RFC 7748 requires; it is generated from 32 OS bytes and re-clamped.
pub static X25519: &dyn SupportedKxGroup = &KxGroup { name: NamedGroup::X25519 };

pub static SECP256R1: &dyn SupportedKxGroup = &KxGroup { name: NamedGroup::secp256r1 };

struct KxGroup {
    name: NamedGroup,
}

impl fmt::Debug for KxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

/// A `Vec` of secrets zeroized on drop, rather than trusting every
/// constructor to remember. A private scalar left on the heap after a dropped
/// key exchange is a key that outlives the session it belonged to.
struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        start_with(self.name, &crate::crypto::random::OsRandom)
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        // Not an FFDHE group, and saying `None` explicitly avoids the
        // linker-unfriendly `FfdheGroup::from_named_group` the default
        // implementation calls.
        None
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

/// Start a key exchange of `group`, its secret drawn from `random`. A source
/// that gives no bytes is `Error::FailedToGetRandomBytes`, never a panic: no
/// generator here can panic. The source is a parameter so that a test can
/// plant one that fails.
pub fn start_with(group: NamedGroup, random: &dyn SecureRandom) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    match group {
        NamedGroup::X25519 => {
            let mut bytes = [0u8; 32];
            random.fill(&mut bytes)?;
            let secret = StaticSecret::from(bytes);
            let public = x25519_dalek::PublicKey::from(&secret);
            let exchange =
                X25519Exchange { secret, public: public.to_bytes().to_vec(), _wipe: SecretBytes(bytes.to_vec()) };
            bytes.zeroize();
            Ok(Box::new(exchange))
        }
        NamedGroup::secp256r1 => {
            let secret = p256_secret(random)?;
            let public = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
            Ok(Box::new(P256Exchange { secret, public }))
        }
        // Unreachable: the only two values of this type are the statics
        // above. This is a *local* configuration fault, not a peer fault,
        // so it is a `General` error and deliberately not one of the
        // `PeerMisbehaved` variants — blaming the relay for a bug in
        // podssh's own provider is how a real fault gets misdiagnosed.
        _ => Err(Error::General("podssh: a key exchange group with no implementation was constructed".into())),
    }
}

/// A P-256 secret from 32 drawn bytes. A draw that is zero or not below the
/// order of the group (about one in 2^32) is drawn again, eight times at
/// most; a source that gives only such draws is as broken as one that gives
/// none. `EphemeralSecret::random` would panic where the source fails.
fn p256_secret(random: &dyn SecureRandom) -> Result<p256::SecretKey, Error> {
    for _ in 0..8 {
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        random.fill(&mut bytes[..])?;
        if let Ok(secret) = p256::SecretKey::from_slice(&bytes[..]) {
            return Ok(secret);
        }
    }
    Err(GetRandomFailed.into())
}

struct X25519Exchange {
    secret: StaticSecret,
    /// Held only so the scalar bytes are wiped when the exchange is dropped.
    /// `StaticSecret`'s own `Drop` is not in its API contract, so relying on it
    /// would be relying on an implementation detail for key material.
    _wipe: SecretBytes,
    public: Vec<u8>,
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        // RFC 8446 §4.2.8.2: a key share in curve25519 is exactly 32 bytes,
        // and a length that is not is a malformed share rather than one to be
        // padded or truncated.
        if peer.len() != 32 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let peer_key = XPublicKey::from(<[u8; 32]>::try_from(peer).map_err(|_| {
            // Unreachable after the length check above, and kept rather than
            // unwrapped so a future edit to that check cannot turn a peer
            // error into a panic.
            PeerMisbehaved::InvalidKeyShare
        })?);
        let shared = self.secret.diffie_hellman(&peer_key);
        // An all-zero shared secret is the small-subgroup / low-order-point
        // case. RFC 8446 requires it be treated as an invalid key share, and
        // x25519-dalek deliberately leaves the check to the caller.
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(shared.as_bytes().to_vec()))
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }
}

struct P256Exchange {
    /// Zeroized on drop by `p256`.
    secret: p256::SecretKey,
    public: Vec<u8>,
}

impl ActiveKeyExchange for P256Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        // SEC1 §2.3.3, cited by rustls's own reference: an uncompressed
        // point starts 0x04. A compressed or hybrid encoding is not what a
        // TLS key share may be.
        if peer.first() != Some(&0x04) {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let peer_key = PublicKey::from_sec1_bytes(peer).map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer_key.as_affine());
        Ok(SharedSecret::from(shared.raw_secret_bytes().to_vec()))
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }
}
