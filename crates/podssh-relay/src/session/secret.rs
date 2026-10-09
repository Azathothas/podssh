//! The values of the handshake: the session id, the nonces, the resume
//! secret and the proofs, and where their random bytes come from.
//!
//! A new session's secret comes from an X25519 exchange through HKDF-SHA256,
//! over both nonces of its first link. A resume proves the secret with an
//! HMAC-SHA256 over both nonces of the new link and the prover's received
//! offset. Neither the secret nor a proof that works on another link crosses
//! the relay, which terminates TLS and can log each byte.

use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Bytes in a nonce, a public key, the secret and a proof.
pub const KEY_LEN: usize = 32;
/// Bytes in a session id.
pub const ID_LEN: usize = 16;

const SECRET_LABEL: &[u8] = b"podssh-session v1 secret";
const CLIENT_PROOF_LABEL: &[u8] = b"podssh-session v1 client proof";
const FAR_PROOF_LABEL: &[u8] = b"podssh-session v1 far proof";

/// The system gave no random bytes. It is never answered with weaker bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoRandom;

impl fmt::Display for NoRandom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the system gave no random bytes")
    }
}

impl std::error::Error for NoRandom {}

/// Where the layer's random bytes come from: the OS, or a planted source in
/// a test.
pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), NoRandom>;
}

/// The OS random source. Reading it can fail (no `getrandom`, a seccomp
/// filter); `try_fill_bytes` then returns an error where `fill_bytes` would
/// panic and end each session of the process (T-064).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), NoRandom> {
        use rand::RngCore;
        rand::rngs::OsRng.try_fill_bytes(buf).map_err(|_| NoRandom)
    }
}

/// A session's name on the far end: 128 random bits. Not a secret: it
/// crosses the relay in `OPEN`, and alone it resumes nothing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; ID_LEN]);

impl SessionId {
    /// The first 8 hex digits, enough to tell sessions apart in a message.
    pub fn short(&self) -> String {
        hex(&self.0[..4])
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", hex(&self.0))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

/// A fresh value of one side for one link. Public: it crosses the relay.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; KEY_LEN]);

impl Nonce {
    pub fn fresh(entropy: &mut dyn Entropy) -> Result<Nonce, NoRandom> {
        let mut bytes = [0u8; KEY_LEN];
        entropy.fill(&mut bytes)?;
        Ok(Nonce(bytes))
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", hex(&self.0))
    }
}

/// An HMAC-SHA256 that proves the secret on one link. It crosses the relay,
/// but it is kept out of messages and logs all the same.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof(pub [u8; KEY_LEN]);

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Proof(..)")
    }
}

/// The 256-bit resume secret. It is wiped when dropped, and never printed:
/// with the session id, it takes the session.
pub struct Secret([u8; KEY_LEN]);

impl Secret {
    /// The bytes, for a store or a test. Never for a message.
    pub fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// A secret from its bytes, as a store gives them back.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Secret {
        Secret(bytes)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// One side's X25519 key for a new session: drawn from the entropy, used
/// once, wiped on drop (the workspace turns on x25519-dalek's `zeroize`).
pub(crate) struct KeyPair {
    secret: StaticSecret,
    pub(crate) public: [u8; KEY_LEN],
}

impl KeyPair {
    pub(crate) fn fresh(entropy: &mut dyn Entropy) -> Result<KeyPair, NoRandom> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        entropy.fill(&mut bytes[..])?;
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(KeyPair { secret, public })
    }

    /// The shared value with the peer's public key, or `None` for a key of
    /// low order, which gives the same value for every secret (RFC 7748,
    /// section 6.1): x25519-dalek leaves that check to its caller.
    pub(crate) fn shared(&self, peer: &[u8; KEY_LEN]) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer));
        if !shared.was_contributory() {
            return None;
        }
        Some(Zeroizing::new(*shared.as_bytes()))
    }
}

/// What a new session's secret is made from.
pub struct Exchange<'a> {
    pub shared: &'a [u8; KEY_LEN],
    pub far_nonce: &'a Nonce,
    pub client_nonce: &'a Nonce,
    pub id: &'a SessionId,
    pub client_public: &'a [u8; KEY_LEN],
    pub far_public: &'a [u8; KEY_LEN],
}

/// HKDF-SHA256 with both nonces of the first link as the salt, the X25519
/// value as the input, and the label, the id and both public keys as the
/// info, so the secret is bound to this session and this exchange.
pub fn derive(exchange: &Exchange<'_>) -> Secret {
    let mut salt = [0u8; 2 * KEY_LEN];
    salt[..KEY_LEN].copy_from_slice(&exchange.far_nonce.0);
    salt[KEY_LEN..].copy_from_slice(&exchange.client_nonce.0);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), exchange.shared);
    let mut info = Vec::with_capacity(SECRET_LABEL.len() + 1 + ID_LEN + 2 * KEY_LEN);
    info.extend_from_slice(SECRET_LABEL);
    info.push(0);
    info.extend_from_slice(&exchange.id.0);
    info.extend_from_slice(exchange.client_public);
    info.extend_from_slice(exchange.far_public);
    let mut out = [0u8; KEY_LEN];
    // 32 bytes is far below HKDF-SHA256's limit of 8160, so this cannot fail.
    if hkdf.expand(&info, &mut out).is_err() {
        out.zeroize();
    }
    Secret(out)
}

/// Which side proves: each has its own label, so a proof of one side is
/// never a proof of the other, and a relay cannot reflect one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prover {
    Client,
    Far,
}

/// What a proof covers on one link.
pub struct Claim<'a> {
    pub prover: Prover,
    pub id: &'a SessionId,
    pub far_nonce: &'a Nonce,
    pub client_nonce: &'a Nonce,
    /// The prover's received offset: where the other side sends again from.
    pub offset: u64,
}

fn mac(secret: &Secret, claim: &Claim<'_>) -> Hmac<Sha256> {
    let label = match claim.prover {
        Prover::Client => CLIENT_PROOF_LABEL,
        Prover::Far => FAR_PROOF_LABEL,
    };
    // A key of any length is valid for HMAC; 32 bytes always are.
    let mut mac = match Hmac::<Sha256>::new_from_slice(&secret.0) {
        Ok(mac) => mac,
        Err(_) => unreachable_mac(),
    };
    mac.update(label);
    mac.update(&[0]);
    mac.update(&claim.id.0);
    mac.update(&claim.far_nonce.0);
    mac.update(&claim.client_nonce.0);
    mac.update(&claim.offset.to_be_bytes());
    mac
}

/// HMAC accepts each key length, so this is never reached; a key of 32 zero
/// bytes keeps it from panicking all the same.
#[cold]
fn unreachable_mac() -> Hmac<Sha256> {
    <Hmac<Sha256> as hmac::digest::KeyInit>::new(&Default::default())
}

pub fn prove(secret: &Secret, claim: &Claim<'_>) -> Proof {
    Proof(mac(secret, claim).finalize().into_bytes().into())
}

/// Whether `proof` is the proof of `claim` under `secret`, compared in
/// constant time.
pub fn verify(secret: &Secret, claim: &Claim<'_>, proof: &Proof) -> bool {
    mac(secret, claim).verify_slice(&proof.0).is_ok()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
