//! TLS 1.2 suites and their record protection, in pure Rust (T-067), for
//! the proxies that intercept TLS and speak only 1.2. Each is ECDHE with
//! AES-GCM or ChaCha20-Poly1305: no CBC, no RSA key exchange, no SHA-1.
//! The PRF is rustls's own over this provider's HMAC.
//!
//! GCM takes a 4-byte salt from the key block and an 8-byte explicit nonce
//! sent before each record (RFC 5288); ChaCha20-Poly1305 takes a 12-byte IV
//! and sends no nonce, as TLS 1.3 does (RFC 7905). Both authenticate the
//! sequence number, type, version and length of RFC 5246 section 6.2.3.3.

use std::fmt;

use rustls::crypto::cipher::{
    make_tls12_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::KeyExchangeAlgorithm;
use rustls::{CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, Error, SignatureScheme, SupportedCipherSuite};

use super::aead::{Aead, AeadId, NONCE_LEN, TAG_LEN};
use super::hmac::{HMAC_SHA256, HMAC_SHA384};

/// The largest plaintext of one record (RFC 5246 section 6.2.1).
const MAX_FRAGMENT_LEN: usize = 16384;
/// GCM's explicit nonce, sent before each record.
const EXPLICIT_LEN: usize = 8;

/// The signatures that an ECDSA or an RSA certificate makes in TLS 1.2.
static ECDSA_SCHEMES: &[SignatureScheme] =
    &[SignatureScheme::ED25519, SignatureScheme::ECDSA_NISTP384_SHA384, SignatureScheme::ECDSA_NISTP256_SHA256];
static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

static GCM_128: Gcm = Gcm(AeadId::Aes128Gcm);
static GCM_256: Gcm = Gcm(AeadId::Aes256Gcm);
static CHACHA: ChaCha = ChaCha;

/// One suite: its id, its hash and HMAC, how it signs, and its AEAD.
macro_rules! suite {
    ($name:ident, $id:ident, $hash:expr, $hmac:expr, $sign:expr, $aead:expr, $limit:expr) => {
        pub static $name: SupportedCipherSuite = SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
            common: CipherSuiteCommon { suite: CipherSuite::$id, hash_provider: $hash, confidentiality_limit: $limit },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: $sign,
            aead_alg: $aead,
            prf_provider: &PrfUsingHmac($hmac),
        });
    };
}

// `confidentiality_limit`: 2^24 records for AES-GCM, as for TLS 1.3 in
// `suites.rs`; none for ChaCha20-Poly1305, as rustls's own providers set.
suite!(
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    super::hash::SHA384,
    &HMAC_SHA384,
    ECDSA_SCHEMES,
    &GCM_256,
    1 << 24
);
suite!(
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    super::hash::SHA256,
    &HMAC_SHA256,
    ECDSA_SCHEMES,
    &GCM_128,
    1 << 24
);
suite!(
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    super::hash::SHA256,
    &HMAC_SHA256,
    ECDSA_SCHEMES,
    &CHACHA,
    u64::MAX
);
suite!(
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    super::hash::SHA384,
    &HMAC_SHA384,
    RSA_SCHEMES,
    &GCM_256,
    1 << 24
);
suite!(
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    super::hash::SHA256,
    &HMAC_SHA256,
    RSA_SCHEMES,
    &GCM_128,
    1 << 24
);
suite!(
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    super::hash::SHA256,
    &HMAC_SHA256,
    RSA_SCHEMES,
    &CHACHA,
    u64::MAX
);

/// AES-GCM as TLS 1.2 runs it.
struct Gcm(AeadId);

impl fmt::Debug for Gcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tls12Gcm({:?})", self.0)
    }
}

/// The salt and the 8 bytes of the key block that start the explicit nonce.
fn gcm_iv(salt: &[u8], explicit: &[u8]) -> Iv {
    let mut iv = [0u8; NONCE_LEN];
    iv[..4].copy_from_slice(salt);
    iv[4..].copy_from_slice(explicit);
    Iv::new(iv)
}

impl Tls12AeadAlgorithm for Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        if iv.len() != 4 || extra.len() != EXPLICIT_LEN {
            return Box::new(super::aead::Unsupported);
        }
        match Aead::new(self.0, key.as_ref()) {
            Ok(aead) => Box::new(GcmEncrypter { aead, iv: gcm_iv(iv, extra) }),
            Err(_) => Box::new(super::aead::Unsupported),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let Ok(salt) = <[u8; 4]>::try_from(iv) else { return Box::new(super::aead::Unsupported) };
        match Aead::new(self.0, key.as_ref()) {
            Ok(aead) => Box::new(GcmDecrypter { aead, salt }),
            Err(_) => Box::new(super::aead::Unsupported),
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape { enc_key_len: self.0.key_len(), fixed_iv_len: 4, explicit_nonce_len: EXPLICIT_LEN }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // Not used: podssh hands its keys to no kernel and to no QUIC stack,
        // as `PureAead::extract_keys` says for TLS 1.3.
        let _ = (key, iv, explicit);
        Err(UnsupportedOperationError)
    }
}

struct GcmEncrypter {
    aead: Aead,
    iv: Iv,
}

impl MessageEncrypter for GcmEncrypter {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        // The nonce of each record is the IV with the sequence number in its
        // last 8 bytes, which go out as the explicit nonce: unique for the key.
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let mut sealed = msg.payload.to_vec();
        self.aead.seal_in_place(&nonce.0, &aad, &mut sealed).ok_or(Error::EncryptError)?;
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&nonce.0[4..]);
        payload.extend_from_slice(&sealed);
        if EXPLICIT_LEN + sealed.len() != total_len {
            return Err(Error::EncryptError);
        }
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + EXPLICIT_LEN + TAG_LEN
    }
}

struct GcmDecrypter {
    aead: Aead,
    salt: [u8; 4],
}

impl MessageDecrypter for GcmDecrypter {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < EXPLICIT_LEN + TAG_LEN {
            return Err(Error::DecryptError);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&payload[..EXPLICIT_LEN]);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, payload.len() - EXPLICIT_LEN - TAG_LEN);
        let body = &mut payload.as_mut()[EXPLICIT_LEN..];
        let plain_len = self.aead.open_in_place(&nonce, &aad, body).ok_or(Error::DecryptError)?;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        // The plaintext moves to the front, over the explicit nonce.
        payload.as_mut().copy_within(EXPLICIT_LEN..EXPLICIT_LEN + plain_len, 0);
        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

/// ChaCha20-Poly1305 as TLS 1.2 runs it (RFC 7905).
struct ChaCha;

impl fmt::Debug for ChaCha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tls12ChaCha20Poly1305")
    }
}

impl Tls12AeadAlgorithm for ChaCha {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        match (Aead::new(AeadId::ChaCha20Poly1305, key.as_ref()), <[u8; NONCE_LEN]>::try_from(iv)) {
            (Ok(aead), Ok(iv)) => Box::new(ChaChaEncrypter { aead, iv: Iv::new(iv) }),
            _ => Box::new(super::aead::Unsupported),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        match (Aead::new(AeadId::ChaCha20Poly1305, key.as_ref()), <[u8; NONCE_LEN]>::try_from(iv)) {
            (Ok(aead), Ok(iv)) => Box::new(ChaChaDecrypter { aead, iv: Iv::new(iv) }),
            _ => Box::new(super::aead::Unsupported),
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape { enc_key_len: 32, fixed_iv_len: NONCE_LEN, explicit_nonce_len: 0 }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let _ = (key, iv, explicit);
        Err(UnsupportedOperationError)
    }
}

struct ChaChaEncrypter {
    aead: Aead,
    iv: Iv,
}

impl MessageEncrypter for ChaChaEncrypter {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let mut sealed = msg.payload.to_vec();
        self.aead.seal_in_place(&nonce.0, &aad, &mut sealed).ok_or(Error::EncryptError)?;
        if sealed.len() != total_len {
            return Err(Error::EncryptError);
        }
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, PrefixedPayload::from(sealed.as_slice())))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

struct ChaChaDecrypter {
    aead: Aead,
    iv: Iv,
}

impl MessageDecrypter for ChaChaDecrypter {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, payload.len() - TAG_LEN);
        let plain_len = self.aead.open_in_place(&nonce.0, &aad, payload.as_mut()).ok_or(Error::DecryptError)?;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}
