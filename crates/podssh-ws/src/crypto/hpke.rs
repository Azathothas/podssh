//! HPKE (RFC 9180) in its base mode, for Encrypted Client Hello (T-642):
//! DHKEM(X25519, HKDF-SHA256), the KDF HKDF-SHA256, and the AEAD
//! AES-128-GCM or ChaCha20-Poly1305.
//!
//! **Why it is here.** rustls's client seals the inner ClientHello through
//! `rustls::crypto::hpke::Hpke`, and the one implementation that rustls
//! ships is aws-lc's, which is C and may not be in this crate (rule 4 of
//! `AGENTS.md`). This one is made of the crates that the provider uses
//! already: x25519-dalek, hkdf with sha2, and the AEADs of `aead.rs`.
//!
//! **Checked against RFC 9180's vectors, not against itself**
//! (`hpke_tests.rs`: A.1.1 and A.2.1, the keys, the schedule and each
//! sealed message): a seal and an open that agree with each other can both
//! be wrong in the same way.
//!
//! The suite's types are rustls's own, which rustls 0.23 names under
//! `rustls::internal` alone; an `Hpke` of any crate has to name them there.

use std::fmt;

use hkdf::Hkdf;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::Error;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::aead::{Aead, AeadId, NONCE_LEN};

/// The suites that podssh seals with, in order. Cloudflare's lists offer
/// X25519 with AES-128-GCM (read 2026-11-05), so that one is first.
pub static SUITES: &[&dyn Hpke] = &[X25519_SHA256_AES_128_GCM, X25519_SHA256_CHACHA20_POLY1305];

/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM: RFC 9180's A.1.
pub static X25519_SHA256_AES_128_GCM: &X25519Hpke = &X25519Hpke { aead: AeadId::Aes128Gcm };

/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305: RFC 9180's A.2.
pub static X25519_SHA256_CHACHA20_POLY1305: &X25519Hpke = &X25519Hpke { aead: AeadId::ChaCha20Poly1305 };

/// The KEM's identifier, and the KDF's (RFC 9180, sections 7.1 and 7.2).
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;

/// `Nsecret`, `Nenc`, `Npk` and `Nsk` of DHKEM(X25519, HKDF-SHA256): each is
/// 32 bytes.
const N: usize = 32;

/// The base mode's byte in the key schedule's context (section 5.1).
const MODE_BASE: u8 = 0x00;

/// The prefix of each labeled extract and expand (section 4).
const VERSION: &[u8] = b"HPKE-v1";

/// One suite: the KEM and the KDF are fixed, the AEAD is its own.
pub struct X25519Hpke {
    aead: AeadId,
}

impl fmt::Debug for X25519Hpke {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519Hpke({:?})", self.aead)
    }
}

/// A failure of this module, in words: rustls passes it on as the
/// handshake's error.
fn failed(why: &str) -> Error {
    Error::General(format!("HPKE: {why}"))
}

/// `suite_id` of the KEM: "KEM" and its identifier (section 4.1).
fn kem_suite() -> Vec<u8> {
    [&b"KEM"[..], &KEM_ID.to_be_bytes()[..]].concat()
}

/// `LabeledExtract(salt, label, ikm)` with HKDF-SHA256: the PRK.
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    // The input holds secrets (a Diffie-Hellman output, a shared secret), so
    // the buffer that joins it is wiped when it goes.
    let joined = Zeroizing::new([VERSION, suite, label, ikm].concat());
    Zeroizing::new(Hkdf::<Sha256>::extract(Some(salt), &joined).0.to_vec())
}

/// `LabeledExpand(prk, label, info, L)` with HKDF-SHA256.
fn labeled_expand(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let length = u16::try_from(len).map_err(|_| failed("an output longer than 65535 bytes"))?.to_be_bytes();
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| failed("a PRK of the wrong length"))?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    hkdf.expand_multi_info(&[&length[..], VERSION, suite, label, info], &mut out)
        .map_err(|_| failed("an output longer than HKDF gives"))?;
    Ok(out)
}

/// `DeriveKeyPair(ikm)` of section 7.1.3 for X25519: the private key and its
/// public key. The vectors' keys come from it; a key of a session comes from
/// the system's random bytes.
pub fn derive_key_pair(ikm: &[u8]) -> Result<(Zeroizing<[u8; N]>, [u8; N]), Error> {
    let suite = kem_suite();
    let prk = labeled_extract(&suite, b"", b"dkp_prk", ikm);
    let sk = labeled_expand(&suite, &prk, b"sk", b"", N)?;
    let sk: Zeroizing<[u8; N]> = Zeroizing::new(sk[..].try_into().map_err(|_| failed("a private key of 32 bytes"))?);
    let pk = PublicKey::from(&StaticSecret::from(*sk)).to_bytes();
    Ok((sk, pk))
}

/// `DH(sk, pk)` of X25519, refused when it is all zeros: a public key of
/// small order, which section 7.1.4 says to refuse.
fn dh(sk: &StaticSecret, pk: &[u8]) -> Result<Zeroizing<[u8; N]>, Error> {
    let pk: [u8; N] = pk.try_into().map_err(|_| failed("a public key of X25519 is 32 bytes"))?;
    let shared = sk.diffie_hellman(&PublicKey::from(pk));
    if !shared.was_contributory() {
        return Err(failed("a public key of small order"));
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

/// `ExtractAndExpand(dh, kem_context)` of section 4.1: the shared secret.
fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let suite = kem_suite();
    let prk = labeled_extract(&suite, b"", b"eae_prk", dh);
    labeled_expand(&suite, &prk, b"shared_secret", kem_context, N)
}

/// `Encap(pkR)` with the ephemeral key `sk_e`: the shared secret and `enc`.
fn encap(pk_r: &[u8], sk_e: &StaticSecret) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
    let enc = PublicKey::from(sk_e).to_bytes().to_vec();
    let dh = dh(sk_e, pk_r)?;
    let context = [&enc[..], pk_r].concat();
    Ok((extract_and_expand(&dh[..], &context)?, enc))
}

/// `Decap(enc, skR)`: the shared secret.
fn decap(enc: &[u8], sk_r: &StaticSecret) -> Result<Zeroizing<Vec<u8>>, Error> {
    let dh = dh(sk_r, enc)?;
    let context = [enc, &PublicKey::from(sk_r).to_bytes()[..]].concat();
    extract_and_expand(&dh[..], &context)
}

/// A private key of 32 bytes, as rustls hands one over.
fn private(key: &HpkePrivateKey) -> Result<StaticSecret, Error> {
    let bytes: [u8; N] = key.secret_bytes().try_into().map_err(|_| failed("a private key of X25519 is 32 bytes"))?;
    Ok(StaticSecret::from(bytes))
}

impl X25519Hpke {
    /// The AEAD's identifier (section 7.3).
    fn aead_id(&self) -> u16 {
        match self.aead {
            AeadId::Aes128Gcm => 0x0001,
            AeadId::Aes256Gcm => 0x0002,
            AeadId::ChaCha20Poly1305 => 0x0003,
        }
    }

    /// `suite_id` of the whole: "HPKE" and the three identifiers (section 5.1).
    fn suite_id(&self) -> Vec<u8> {
        [&b"HPKE"[..], &KEM_ID.to_be_bytes()[..], &KDF_ID.to_be_bytes()[..], &self.aead_id().to_be_bytes()[..]].concat()
    }

    /// `KeySchedule` of the base mode (section 5.1): the AEAD's key and the
    /// base nonce. No PSK, so `psk` and `psk_id` are empty.
    fn schedule(&self, shared: &[u8], info: &[u8]) -> Result<(Zeroizing<Vec<u8>>, [u8; NONCE_LEN]), Error> {
        let suite = self.suite_id();
        let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
        let context = [&[MODE_BASE][..], &psk_id_hash[..], &info_hash[..]].concat();
        let secret = labeled_extract(&suite, shared, b"secret", b"");
        let key = labeled_expand(&suite, &secret, b"key", &context, self.aead.key_len())?;
        let nonce = labeled_expand(&suite, &secret, b"base_nonce", &context, NONCE_LEN)?;
        let nonce: [u8; NONCE_LEN] = nonce[..].try_into().map_err(|_| failed("a nonce of 12 bytes"))?;
        Ok((key, nonce))
    }

    /// The context of `shared` and `info`, at sequence number 0.
    fn context(&self, shared: &[u8], info: &[u8]) -> Result<Context, Error> {
        let (key, base_nonce) = self.schedule(shared, info)?;
        let aead = Aead::new(self.aead, &key).map_err(|_| failed("an AEAD key of the wrong length"))?;
        Ok(Context { aead, base_nonce, seq: 0 })
    }

    /// `SetupBaseS` with the ephemeral key `sk_e`: the system's random bytes
    /// in a session, a vector's key in a test.
    fn sealer_with(&self, info: &[u8], pk_r: &[u8], sk_e: &StaticSecret) -> Result<(Vec<u8>, Context), Error> {
        let (shared, enc) = encap(pk_r, sk_e)?;
        Ok((enc, self.context(&shared, info)?))
    }

    /// `SetupBaseR`.
    fn opener(&self, enc: &[u8], info: &[u8], sk_r: &HpkePrivateKey) -> Result<Context, Error> {
        let shared = decap(enc, &private(sk_r)?)?;
        self.context(&shared, info)
    }
}

/// An ephemeral key from the system's random bytes: a random string of 32
/// bytes is a private key of X25519, which clamps it at each use.
fn ephemeral() -> Result<StaticSecret, Error> {
    let mut bytes = Zeroizing::new([0u8; N]);
    rustls::crypto::SecureRandom::fill(&super::random::OsRandom, &mut bytes[..])?;
    Ok(StaticSecret::from(*bytes))
}

impl Hpke for X25519Hpke {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut context) = self.sealer_with(info, &pub_key.0, &ephemeral()?)?;
        Ok((EncapsulatedSecret(enc), context.seal(aad, plaintext)?))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let (enc, context) = self.sealer_with(info, &pub_key.0, &ephemeral()?)?;
        Ok((EncapsulatedSecret(enc), Box::new(Sealer(context))))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        self.opener(&enc.0, info, secret_key)?.open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        Ok(Box::new(Opener(self.opener(&enc.0, info, secret_key)?)))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let sk = ephemeral()?;
        let pk = PublicKey::from(&sk).to_bytes().to_vec();
        Ok((HpkePublicKey(pk), HpkePrivateKey::from(sk.to_bytes().to_vec())))
    }

    fn suite(&self) -> HpkeSuite {
        let aead_id = match self.aead {
            AeadId::Aes128Gcm => HpkeAead::AES_128_GCM,
            AeadId::Aes256Gcm => HpkeAead::AES_256_GCM,
            AeadId::ChaCha20Poly1305 => HpkeAead::CHACHA20_POLY_1305,
        };
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite { kdf_id: HpkeKdf::HKDF_SHA256, aead_id },
        }
    }
}

/// A context of section 5.2: the AEAD, the base nonce and the sequence
/// number. `Debug` names the AEAD alone, never the key.
struct Context {
    aead: Aead,
    base_nonce: [u8; NONCE_LEN],
    seq: u64,
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Context({:?}, seq {})", self.aead, self.seq)
    }
}

impl Context {
    /// `ComputeNonce(seq)`: the base nonce XOR the sequence number, big
    /// endian, in its last bytes.
    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = self.base_nonce;
        for (at, byte) in self.seq.to_be_bytes().iter().enumerate() {
            nonce[NONCE_LEN - 8 + at] ^= byte;
        }
        nonce
    }

    /// `IncrementSeq()`: a context whose number would wrap seals no more, as
    /// a nonce must never come twice.
    fn next(&mut self) -> Result<(), Error> {
        self.seq = self.seq.checked_add(1).ok_or_else(|| failed("the context's sequence number is spent"))?;
        Ok(())
    }

    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buffer = plaintext.to_vec();
        self.aead.seal_in_place(&self.nonce(), aad, &mut buffer).ok_or(Error::EncryptError)?;
        self.next()?;
        Ok(buffer)
    }

    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buffer = ciphertext.to_vec();
        let len = self.aead.open_in_place(&self.nonce(), aad, &mut buffer).ok_or(Error::DecryptError)?;
        buffer.truncate(len);
        self.next()?;
        Ok(buffer)
    }
}

#[derive(Debug)]
struct Sealer(Context);

impl HpkeSealer for Sealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(aad, plaintext)
    }
}

#[derive(Debug)]
struct Opener(Context);

impl HpkeOpener for Opener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.open(aad, ciphertext)
    }
}

#[cfg(test)]
#[path = "hpke_tests.rs"]
mod tests;
