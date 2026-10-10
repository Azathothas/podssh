//! Who an end of a road is (T-087): one Ed25519 key for each role, the same
//! on each road. A node has one for each label, a client one for each user,
//! in the key files of T-163 ([`file`]). A key is shown by its SHA256
//! fingerprint, in OpenSSH's form, and named by it or by the key itself
//! ([`KeyName`]): in a node's allowlist ([`allow`]), an operator's pins
//! ([`pins`]), or a flag.
//!
//! The channel between two ends (`crate::e2e`) proves the key. Its Noise
//! static key is derived from the seed, and the Ed25519 key signs it, so no
//! key does two jobs: the Ed25519 key signs (as iroh's TLS does with it), and
//! the derived key agrees keys.

pub mod allow;
pub mod file;
pub mod pins;

use std::fmt;

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The label of the Noise static key's derivation from the seed.
const DH_LABEL: &[u8] = b"podssh e2e static key, version 1";
/// What the Ed25519 key signs: this, then the Noise static public key.
const BINDING_LABEL: &[u8] = b"podssh-e2e/1 static key\0";

/// The prefix of a fingerprint, as OpenSSH writes one.
pub const FINGERPRINT_PREFIX: &str = "SHA256:";

/// An end's secret: the 32-byte Ed25519 seed, which iroh takes as its secret
/// key too, and the Noise static key derived from it. It prints as its
/// fingerprint, never as a secret.
pub struct Identity {
    signing: SigningKey,
    dh: Zeroizing<[u8; 32]>,
    dh_public: [u8; 32],
    binding: [u8; 64],
}

impl Identity {
    pub fn from_seed(seed: &[u8; 32]) -> Identity {
        let signing = SigningKey::from_bytes(seed);
        let mut dh = Zeroizing::new([0u8; 32]);
        // 32 bytes is within HKDF-SHA256's 8160, so the expansion cannot fail.
        Hkdf::<Sha256>::new(None, seed).expand(DH_LABEL, &mut dh[..]).expect("HKDF-SHA256 gives 32 bytes");
        let dh_public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*dh)).to_bytes();
        let binding = signing.sign(&binding_message(&dh_public)).to_bytes();
        Identity { signing, dh, dh_public, binding }
    }

    /// The seed, for iroh, which takes it as its secret key.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key().to_bytes())
    }

    /// The Noise static key's secret half.
    pub fn dh_secret(&self) -> &[u8; 32] {
        &self.dh
    }

    /// The Noise static key's public half.
    pub fn dh_public(&self) -> &[u8; 32] {
        &self.dh_public
    }

    /// The Ed25519 key's signature of [`Identity::dh_public`]: the proof that
    /// this identity holds that Noise key.
    pub fn binding(&self) -> &[u8; 64] {
        &self.binding
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").field("public", &self.public().fingerprint()).finish()
    }
}

fn binding_message(dh_public: &[u8; 32]) -> Vec<u8> {
    [BINDING_LABEL, dh_public].concat()
}

/// An end's public key: the 32 bytes of an Ed25519 key. It prints as its
/// fingerprint.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// The SHA256 fingerprint, as OpenSSH shows an Ed25519 key: the digest of
    /// the key's SSH encoding (`ssh-ed25519` and the key, each with its
    /// length), in base64 with no padding.
    pub fn fingerprint(&self) -> String {
        let mut blob = Vec::with_capacity(51);
        for part in [&b"ssh-ed25519"[..], &self.0[..]] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        let digest = Sha256::digest(&blob);
        format!("{FINGERPRINT_PREFIX}{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest))
    }

    /// The key in lower-case hex, as iroh shows it.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Whether `binding` is this key's signature of the Noise static key
    /// `dh_public`. A key that is not a point of the curve signs nothing.
    pub fn signed(&self, dh_public: &[u8; 32], binding: &[u8; 64]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.0) else { return false };
        key.verify_strict(&binding_message(dh_public), &Signature::from_bytes(binding)).is_ok()
    }

    /// The key written as iroh writes it: 64 hex digits, or 52 characters
    /// of base32 (RFC 4648, no padding), in either case.
    pub fn parse(word: &str) -> Option<PublicKey> {
        match word.len() {
            64 => from_hex(word),
            52 => from_base32(word),
            _ => None,
        }
        .map(PublicKey)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.fingerprint())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

fn from_hex(word: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    for (i, pair) in word.as_bytes().chunks(2).enumerate() {
        let digit = |c: u8| (c as char).to_digit(16);
        out[i] = u8::try_from(digit(pair[0])? * 16 + digit(*pair.get(1)?)?).ok()?;
    }
    Some(out)
}

/// RFC 4648 base32 of 32 bytes: 52 characters, the last 4 bits zero.
fn from_base32(word: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let (mut acc, mut bits, mut at) = (0u32, 0u32, 0usize);
    for c in word.bytes() {
        let value = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(at)? = (acc >> bits) as u8;
            at += 1;
            acc &= (1 << bits) - 1;
        }
    }
    (at == 32 && acc == 0).then_some(out)
}

/// A key as a person names it: the key itself, or its fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyName {
    Key(PublicKey),
    /// `SHA256:` and 43 characters of base64, as [`PublicKey::fingerprint`]
    /// writes them.
    Fingerprint(String),
}

impl KeyName {
    /// A fingerprint (with or without its padding), or a key as
    /// [`PublicKey::parse`] reads one.
    pub fn parse(word: &str) -> Option<KeyName> {
        if let Some(rest) = word.strip_prefix(FINGERPRINT_PREFIX) {
            let rest = rest.strip_suffix('=').unwrap_or(rest);
            let digest = base64::engine::general_purpose::STANDARD_NO_PAD.decode(rest).ok()?;
            return (digest.len() == 32).then(|| KeyName::Fingerprint(format!("{FINGERPRINT_PREFIX}{rest}")));
        }
        PublicKey::parse(word).map(KeyName::Key)
    }

    pub fn matches(&self, key: &PublicKey) -> bool {
        match self {
            KeyName::Key(named) => named == key,
            KeyName::Fingerprint(named) => *named == key.fingerprint(),
        }
    }

    /// The fingerprint that the name gives.
    pub fn fingerprint(&self) -> String {
        match self {
            KeyName::Key(key) => key.fingerprint(),
            KeyName::Fingerprint(named) => named.clone(),
        }
    }
}

impl fmt::Display for KeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.fingerprint())
    }
}
