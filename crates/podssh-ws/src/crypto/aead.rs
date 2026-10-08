//! TLS 1.3 record protection, in pure Rust.
//!
//! ⛔ **Only what `suites.rs` offers is implemented.** Offering a suite whose
//! AEAD cannot be completed is worse than not offering it, because a peer that
//! selects it gets a failure deep in the record layer rather than a clean "no
//! shared cipher suite" during the handshake.

use std::fmt;

use aes_gcm::aead::{Aead as AeadTrait, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ContentType, Error, ProtocolVersion};

use rustls::ConnectionTrafficSecrets;

/// ⛔ The Poly1305 tag is 16 bytes in every AEAD here, so it is a constant
/// rather than a per-algorithm field. A `tag_len()` that could differ would
/// have to be carried through the encrypter's length calculation, and a
/// mismatch there silently truncates a record.
pub const TAG_LEN: usize = 16;

/// ⛔ The TLS nonce length, fixed by `rustls::crypto::cipher::NONCE_LEN` and
/// repeated here so the AEAD functions can be read without the rustls import.
pub const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadId {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadId {
    /// ⛔ AES-128 and AES-256 differ, and a provider that reported one key
    /// length for both would let a peer negotiate AES-128 and then fail to
    /// build the encrypter.
    pub fn key_len(self) -> usize {
        match self {
            AeadId::Aes128Gcm => 16,
            AeadId::Aes256Gcm => 32,
            AeadId::ChaCha20Poly1305 => 32,
        }
    }
}

/// ⛔ `Debug` names the algorithm and never the key. A `Debug` that prints key
/// material is a credential in a log, and this repository has a rule about
/// exactly that.
pub struct Aead {
    id: AeadId,
    inner: Inner,
}

enum Inner {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl fmt::Debug for Aead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aead({:?})", self.id)
    }
}

impl Aead {
    pub fn new(id: AeadId, key: &[u8]) -> Result<Self, UnsupportedOperationError> {
        if key.len() != id.key_len() {
            return Err(UnsupportedOperationError);
        }
        let inner = match id {
            AeadId::Aes128Gcm => Inner::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(|_| UnsupportedOperationError)?,
            )),
            AeadId::Aes256Gcm => Inner::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).map_err(|_| UnsupportedOperationError)?,
            )),
            AeadId::ChaCha20Poly1305 => Inner::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| UnsupportedOperationError)?,
            )),
        };
        Ok(Aead { id, inner })
    }

    pub fn id(&self) -> AeadId {
        self.id
    }

    /// ⛔ The nonce is a `GenericArray` of 12 bytes, and the length is fixed
    /// by `NONCE_LEN` above. The size is named explicitly rather than inferred,
    /// because `aes_gcm::Nonce` takes it as a type parameter and a wrong one
    /// would be a different nonce length rather than a compile error at the
    /// call site that uses it.
    fn nonce(n: &[u8; NONCE_LEN]) -> aes_gcm::Nonce<aes_gcm::aead::consts::U12> {
        *aes_gcm::Nonce::from_slice(n)
    }

    pub fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Option<()> {
        let payload = Payload { msg: &*buffer, aad };
        let sealed = match &self.inner {
            Inner::Aes128(k) => k.encrypt(&Self::nonce(nonce), payload).ok()?,
            Inner::Aes256(k) => k.encrypt(&Self::nonce(nonce), payload).ok()?,
            Inner::ChaCha(k) => chacha20poly1305::ChaCha20Poly1305::encrypt(
                k,
                chacha20poly1305::Nonce::from_slice(nonce),
                payload,
            )
            .ok()?,
        };
        *buffer = sealed;
        Some(())
    }

    /// ⛔ **In place, and that is not an optimisation.** `MessageDecrypter::
    /// decrypt` returns a message borrowing the caller's buffer for the
    /// lifetime `'a`. A decrypter that allocated a fresh `Vec` would have to
    /// either leak it or shorten the borrow, so the plaintext is written back
    /// over the ciphertext exactly as the reference providers do.
    pub fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Option<usize> {
        let payload = Payload { msg: buffer, aad };
        let plain = match &self.inner {
            Inner::Aes128(k) => k.decrypt(&Self::nonce(nonce), payload).ok()?,
            Inner::Aes256(k) => k.decrypt(&Self::nonce(nonce), payload).ok()?,
            Inner::ChaCha(k) => chacha20poly1305::ChaCha20Poly1305::decrypt(
                k,
                chacha20poly1305::Nonce::from_slice(nonce),
                payload,
            )
            .ok()?,
        };
        // ⛔ The AEAD crates return a `Vec` that may be a fresh allocation, so
        // it is copied back rather than returned. The length is returned
        // separately because the caller's buffer is what the borrow names.
        let len = plain.len();
        buffer[..len].copy_from_slice(&plain);
        Some(len)
    }
}

pub struct PureAead(pub AeadId);

impl fmt::Debug for PureAead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PureAead({:?})", self.0)
    }
}

impl Tls13AeadAlgorithm for PureAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        match Aead::new(self.0, key.as_ref()) {
            Ok(aead) => Box::new(Encrypter { aead, iv }),
            // ⛔ Unreachable in practice, because rustls sizes `key` from
            // `key_len()`. An encrypter that returns an error is still the right
            // answer: a panic here would lose the session over a bug that a
            // returned `Err` reports honestly.
            Err(_) => Box::new(Unsupported),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        match Aead::new(self.0, key.as_ref()) {
            Ok(aead) => Box::new(Decrypter { aead, iv }),
            Err(_) => Box::new(Unsupported),
        }
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // ⛔ QUIC is not something podssh offers: it speaks TLS over TCP to a
        // relay, not QUIC. Refusing here is what makes `quic: None` on the
        // suites consistent with this implementation rather than a claim.
        let _ = (key, iv);
        Err(UnsupportedOperationError)
    }
}

struct Encrypter {
    aead: Aead,
    iv: Iv,
}

impl MessageEncrypter for Encrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        // ⛔ RFC 8446 §5.2: the real content type is appended INSIDE the AEAD
        // plaintext and the outer record type is always `application_data`.
        // Reversing these produces a record that decrypts to a payload one byte
        // short, which reads as a framing bug in the layer above.
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);
        // ⛔ Sealed into a `Vec` and re-wrapped, because `PrefixedPayload`
        // keeps its length private and the AEAD writes in place. The length is
        // checked rather than assumed: a sealed payload of the wrong size is a
        // record that would be rejected by the peer with no local clue.
        let mut sealed = payload.as_ref().to_vec();
        self.aead
            .seal_in_place(&nonce.0, &aad, &mut sealed)
            .ok_or(Error::EncryptError)?;
        if sealed.len() != total_len {
            return Err(Error::EncryptError);
        }

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // ⛔ RFC 8446 §5.1: application data records carry TLSv1_2 as the
            // legacy record version, even in a TLS 1.3 connection.
            ProtocolVersion::TLSv1_2,
            PrefixedPayload::from(sealed.as_slice()),
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

struct Decrypter {
    aead: Aead,
    iv: Iv,
}

impl MessageDecrypter for Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let plain_len = self
            .aead
            .open_in_place(&nonce.0, &aad, payload.as_mut())
            .ok_or(Error::DecryptError)?;
        payload.truncate(plain_len);

        // ⛔ `into_tls13_unpadded_message` reads the trailing content type,
        // strips the zero padding, and REJECTS a payload whose type byte is
        // zero. Doing that by hand is how a record layer comes to accept inner
        // plaintext it should refuse.
        msg.into_tls13_unpadded_message()
    }
}

struct Unsupported;

impl MessageEncrypter for Unsupported {
    fn encrypt(
        &mut self,
        _m: OutboundPlainMessage<'_>,
        _seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

impl MessageDecrypter for Unsupported {
    fn decrypt<'a>(
        &mut self,
        _m: InboundOpaqueMessage<'a>,
        _seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}
