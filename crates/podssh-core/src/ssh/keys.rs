//! curve25519-sha256 (RFC 8731): ephemeral keys, the exchange hash H, the
//! key derivation (RFC 4253 §7.2), and host-key signature verification.
//!
//! ⛔ No crypto is implemented here. `x25519-dalek` multiplies,
//! `ed25519-dalek` and `rsa` verify, `sha2` hashes — this file only feeds
//! them the inputs RFC 8731 §1.2 and RFC 4253 §7.2 name, in the order they
//! name. The input ORDER is the whole of this file's correctness, which is
//! why the H-construction test flips each input separately.

use sha2::{Digest, Sha256};

use crate::ssh::types::{Reader, TypeError, put_mpint, put_string};

/// Why a key exchange is not an agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    Types(TypeError),
    /// The peer's public value is not 32 bytes.
    BadPeerKey { bytes: usize },
    /// The host-key blob names an algorithm outside the closed set.
    UnknownHostKey { alg: String },
    /// The signature does not verify (or does not parse).
    BadSignature,
    /// The RSA modulus/exponent do not form a key.
    BadRsaKey,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Types(e) => write!(f, "{e}"),
            Self::BadPeerKey { bytes } => write!(f, "peer key is {bytes} bytes, not 32"),
            Self::UnknownHostKey { alg } => write!(f, "host key algorithm {alg:?} is not offered"),
            Self::BadSignature => write!(f, "host key signature does not verify"),
            Self::BadRsaKey => write!(f, "RSA host key parameters do not form a key"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<TypeError> for KeyError {
    fn from(e: TypeError) -> Self {
        Self::Types(e)
    }
}

/// One side's ephemeral: the secret never leaves, the public goes in
/// KEX_ECDH_INIT (client) or KEX_ECDH_REPLY (server) as a plain `string`.
pub struct Ephemeral {
    secret: x25519_dalek::StaticSecret,
}

impl Ephemeral {
    pub fn generate() -> Self {
        Self { secret: x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng()) }
    }

    /// Test seam: a fixed secret, so vectors are reproducible. Only tests
    /// name it — production randomness is OS-sourced, always.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { secret: x25519_dalek::StaticSecret::from(bytes) }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.secret).to_bytes()
    }

    pub fn agree(&self, peer: &[u8]) -> Result<[u8; 32], KeyError> {
        if peer.len() != 32 {
            return Err(KeyError::BadPeerKey { bytes: peer.len() });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(peer);
        Ok(self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(arr)).to_bytes())
    }
}

/// The exchange hash H for curve25519-sha256 (RFC 8731 §1.2):
/// `SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)` where every
/// `||` is SSH string-concatenation and K is mpint-encoded. `i_c`/`i_s` are
/// the KEXINIT *payloads* (message byte included); `v_c`/`v_s` the raw
/// banner lines without CR LF.
pub fn exchange_hash(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8; 32],
    q_s: &[u8; 32],
    k: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut feed = |b: &[u8]| {
        h.update((b.len() as u32).to_be_bytes());
        h.update(b);
    };
    feed(v_c);
    feed(v_s);
    feed(i_c);
    feed(i_s);
    feed(k_s);
    feed(q_c);
    feed(q_s);
    let mut mk = Vec::new();
    put_mpint(&mut mk, k);
    h.update(&mk);
    h.finalize().into()
}

/// One derived key (RFC 4253 §7.2): `K1 = HASH(K || H || X ||
/// session_id)`, extended by `Kn = HASH(K || H || K1 || ... || Kn-1)` while
/// more bytes are needed. `k` is the raw shared secret (mpint-encoded
/// inside); `letter` is `b'A'`..`b'F'` naming which key.
pub fn derive_key(k: &[u8], h: &[u8; 32], letter: u8, session_id: &[u8], len: usize) -> Vec<u8> {
    let mut mk = Vec::new();
    put_mpint(&mut mk, k);
    let mut out = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < len {
        let mut h2 = Sha256::new();
        h2.update(&mk);
        h2.update(h);
        if prev.is_empty() {
            h2.update([letter]);
            h2.update(session_id);
        } else {
            h2.update(&prev);
        }
        prev = h2.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}

/// A parsed host-key blob `K_S`: algorithm name plus the key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub alg: String,
    pub blob: Vec<u8>,
}

/// Parse `K_S` (a `string` holding `string alg || key-parts`). Only the two
/// offered algorithms parse — anything else is `UnknownHostKey`, never a
/// key the verifier half-guesses.
pub fn parse_host_key(k_s: &[u8]) -> Result<HostKey, KeyError> {
    let mut r = Reader::new(k_s);
    let alg = std::str::from_utf8(r.string()?)
        .map_err(|_| KeyError::UnknownHostKey { alg: format!("{k_s:?}") })?
        .to_string();
    if alg != "ssh-ed25519" && alg != "rsa-sha2-256" {
        return Err(KeyError::UnknownHostKey { alg });
    }
    Ok(HostKey { alg, blob: r.rest().to_vec() })
}

/// Verify the `KEX_ECDH_REPLY` signature over H. The signature is itself a
/// `string` of `string alg || string sig`; the outer alg MUST equal the
/// host-key alg — a signature valid under a different algorithm than the key
/// offered is a substitution, not a verification.
pub fn verify_host_signature(key: &HostKey, h: &[u8; 32], sig: &[u8]) -> Result<(), KeyError> {
    let mut r = Reader::new(sig);
    let sig_alg = std::str::from_utf8(r.string()?).map_err(|_| KeyError::BadSignature)?;
    if sig_alg != key.alg {
        return Err(KeyError::BadSignature);
    }
    let sig_bytes = r.string()?;
    match key.alg.as_str() {
        "ssh-ed25519" => verify_ed25519(&key.blob, h, sig_bytes),
        "rsa-sha2-256" => verify_rsa(&key.blob, h, sig_bytes),
        _ => Err(KeyError::UnknownHostKey { alg: key.alg.clone() }),
    }
}

fn verify_ed25519(blob: &[u8], h: &[u8; 32], sig_bytes: &[u8]) -> Result<(), KeyError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    // `blob` is the key parts AFTER the alg string `parse_host_key` already
    // consumed: a single `string` holding the 32-byte key. Re-reading a name
    // here would parse the key bytes as a name and fail everything.
    let mut r = Reader::new(blob);
    let key_bytes = r.string()?;
    let key = VerifyingKey::from_bytes(key_bytes.try_into().map_err(|_| KeyError::BadSignature)?)
        .map_err(|_| KeyError::BadSignature)?;
    let sig = Signature::from_slice(sig_bytes).map_err(|_| KeyError::BadSignature)?;
    key.verify(h, &sig).map_err(|_| KeyError::BadSignature)
}

fn verify_rsa(blob: &[u8], h: &[u8; 32], sig_bytes: &[u8]) -> Result<(), KeyError> {
    use rsa::pkcs1v15::VerifyingKey as RsaVerify;
    use rsa::signature::Verifier;
    let mut r = Reader::new(blob);
    // rsa parts AFTER the alg string: mpint e || mpint n (same single-
    // expectation as above — no name re-read).
    let e = r.mpint()?;
    let n = r.mpint()?;
    let pubkey = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(n), rsa::BigUint::from_bytes_be(e))
        .map_err(|_| KeyError::BadRsaKey)?;
    let vk = RsaVerify::<sha2::Sha256>::new(pubkey);
    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes).map_err(|_| KeyError::BadSignature)?;
    vk.verify(h, &sig).map_err(|_| KeyError::BadSignature)
}

/// Render an ed25519 public key as an `ssh-ed25519` wire blob (for tests and,
/// later, known_hosts comparison): `string "ssh-ed25519" || string key`.
pub fn ed25519_blob(key_bytes: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, b"ssh-ed25519");
    put_string(&mut out, key_bytes);
    out
}
