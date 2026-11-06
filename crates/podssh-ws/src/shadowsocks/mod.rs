//! Shadowsocks in its AEAD form (T-373, GitHub #62): a server that takes a
//! target in an address header and dials it, as the relay's forward path
//! does, with a key in place of a token. The stream is the one of
//! shadowsocks.org's `aead.html`: a salt, then chunks, each the payload's
//! length sealed on its own and then the sealed payload ([`codec`]). The
//! master key comes from the password by OpenSSL's `EVP_BytesToKey` with MD5,
//! and each stream's key from the master key and the stream's salt by
//! HKDF-SHA1 with the info `ss-subkey`.
//!
//! Three methods: `chacha20-ietf-poly1305`, `aes-256-gcm` and `aes-128-gcm`,
//! with the ciphers of podssh's own TLS (`crypto/aead.rs`); and the three of
//! Shadowsocks 2022 (SIP022, T-492, [`sip022`]): `2022-blake3-aes-128-gcm`,
//! `2022-blake3-aes-256-gcm` and `2022-blake3-chacha20-poly1305`, whose key
//! is a pre-shared key in base64, each stream's key BLAKE3's `derive_key` of
//! it and the salt, and whose request and response open with a header that
//! holds a timestamp. A key of several users (SIP023's `iPSK:uPSK`) is
//! refused by its name, and so is a plugin, another program that podssh does
//! not start. The server is reached as each road reaches its first host: TCP
//! through the proxy of the environment ([`open`]), or, for a server of an
//! Outline access key that names one, a WebSocket over TLS (T-493, [`ws`],
//! [`key`]).
//!
//! The password goes into the master key and nowhere else: no message, no
//! `Debug` and no line of a log holds it.

mod carry;
pub mod codec;
mod key;
mod list;
mod open;
pub mod sip022;
mod uri;
mod ws;
mod yaml;

pub use carry::{Carried, Ended, Status};
pub use codec::{address, parse_address, ChunkError, Decoder, Encoder, MAX_PAYLOAD};
pub use key::access_key;
pub use list::{subscription, Listed};
pub use open::{open, Dial, OpenError, Opened, ANSWER_WAIT};
pub use uri::Node;

use zeroize::Zeroizing;

use crate::crypto::aead::AeadId;

/// The tag of each sealed piece: 16 bytes in each method here.
pub const TAG_LEN: usize = crate::crypto::aead::TAG_LEN;

/// HKDF's info for each stream's key, as the specification fixes it.
const SUBKEY_INFO: &[u8] = b"ss-subkey";

/// A method of the AEAD form, or of Shadowsocks 2022.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Chacha20IetfPoly1305,
    Aes256Gcm,
    Aes128Gcm,
    /// SIP022's methods (T-492).
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3Chacha20Poly1305,
}

impl Method {
    /// Each method of the AEAD form, in the order of the messages.
    pub const ALL: [Method; 3] = [Method::Chacha20IetfPoly1305, Method::Aes256Gcm, Method::Aes128Gcm];

    /// Each method of Shadowsocks 2022: the two that SIP022 asks of each
    /// client first, then the one that it leaves to choose.
    pub const SIP022: [Method; 3] = [Method::Blake3Aes128Gcm, Method::Blake3Aes256Gcm, Method::Blake3Chacha20Poly1305];

    /// The name that a key gives it.
    pub fn name(self) -> &'static str {
        match self {
            Method::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Method::Aes256Gcm => "aes-256-gcm",
            Method::Aes128Gcm => "aes-128-gcm",
            Method::Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
            Method::Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
            Method::Blake3Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    /// The other names of a method in older clients' keys.
    fn aliases(self) -> &'static [&'static str] {
        match self {
            Method::Chacha20IetfPoly1305 => &["chacha20-poly1305", "aead_chacha20_poly1305"],
            Method::Aes256Gcm => &["aead_aes_256_gcm"],
            Method::Aes128Gcm => &["aead_aes_128_gcm"],
            Method::Blake3Aes128Gcm | Method::Blake3Aes256Gcm | Method::Blake3Chacha20Poly1305 => &[],
        }
    }

    /// Whether it is a method of Shadowsocks 2022: its key is a pre-shared
    /// key, and its streams carry SIP022's headers.
    pub fn is_2022(self) -> bool {
        Method::SIP022.contains(&self)
    }

    /// The bytes of the key, and of the salt, which is as long.
    pub fn key_len(self) -> usize {
        match self {
            Method::Aes128Gcm | Method::Blake3Aes128Gcm => 16,
            Method::Chacha20IetfPoly1305
            | Method::Aes256Gcm
            | Method::Blake3Aes256Gcm
            | Method::Blake3Chacha20Poly1305 => 32,
        }
    }

    /// The bytes of each stream's salt.
    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    fn aead_id(self) -> AeadId {
        match self {
            Method::Chacha20IetfPoly1305 | Method::Blake3Chacha20Poly1305 => AeadId::ChaCha20Poly1305,
            Method::Aes256Gcm | Method::Blake3Aes256Gcm => AeadId::Aes256Gcm,
            Method::Aes128Gcm | Method::Blake3Aes128Gcm => AeadId::Aes128Gcm,
        }
    }

    /// The methods that podssh speaks, for a message.
    pub fn names() -> &'static str {
        "chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm or \
         2022-blake3-chacha20-poly1305"
    }

    /// A method by its name, in any case. Another name is shown only when it
    /// has the shape of a method's, as a key that is read wrong could put a
    /// part of its password there.
    pub fn parse(name: &str) -> Result<Method, String> {
        let lower = name.trim().to_ascii_lowercase();
        let known = Method::ALL
            .into_iter()
            .chain(Method::SIP022)
            .find(|m| m.name() == lower || m.aliases().contains(&lower.as_str()));
        if let Some(method) = known {
            return Ok(method);
        }
        let names = Method::names();
        let shaped = (1..=40).contains(&lower.len())
            && lower.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        match shaped {
            true => Err(format!("the method {lower} is not one that podssh speaks: {names}")),
            false => Err(format!("the method is not one that podssh speaks: {names}")),
        }
    }
}

/// The master key of `password`: OpenSSL's `EVP_BytesToKey` with MD5, one
/// round and no salt. Each block is MD5 of the block before it and the
/// password; the key is the first `len` bytes of the blocks.
pub fn master_key(password: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(Vec::with_capacity(len + 16));
    let mut block = Zeroizing::new([0u8; 16]);
    let mut first = true;
    while key.len() < len {
        let mut hash = md5::Context::new();
        if !first {
            hash.consume(&block[..]);
        }
        hash.consume(password);
        *block = hash.finalize().0;
        key.extend_from_slice(&block[..]);
        first = false;
    }
    key.truncate(len);
    key
}

/// The key of one stream of `method`: [`subkey`] for the AEAD form, and
/// SIP022's derivation by BLAKE3 ([`sip022::session_key`]) for Shadowsocks
/// 2022.
pub fn stream_key(method: Method, master: &[u8], salt: &[u8]) -> Zeroizing<Vec<u8>> {
    match method.is_2022() {
        true => sip022::session_key(master, salt),
        false => subkey(master, salt),
    }
}

/// The key of one stream: HKDF-SHA1 of the master key, with the stream's
/// salt and the info `ss-subkey`, as long as the master key.
pub fn subkey(master: &[u8], salt: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; master.len()]);
    // 16 or 32 bytes, far below HKDF-SHA1's limit of 255 blocks of 20.
    let _ = hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), master).expand(SUBKEY_INFO, key.as_mut_slice());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_method_is_read_by_its_name_or_an_alias_and_another_is_refused_with_care() {
        assert_eq!(Method::parse("AES-256-GCM"), Ok(Method::Aes256Gcm));
        assert_eq!(Method::parse("chacha20-poly1305"), Ok(Method::Chacha20IetfPoly1305));
        assert_eq!(Method::parse("aead_aes_128_gcm"), Ok(Method::Aes128Gcm));
        assert_eq!(Method::parse("2022-BLAKE3-AES-256-GCM"), Ok(Method::Blake3Aes256Gcm));
        assert_eq!(Method::parse("2022-blake3-chacha20-poly1305"), Ok(Method::Blake3Chacha20Poly1305));
        let chacha8 = Method::parse("2022-blake3-chacha8-poly1305").unwrap_err();
        assert!(chacha8.starts_with("the method 2022-blake3-chacha8-poly1305 is not one"), "{chacha8}");
        let stream = Method::parse("aes-256-cfb").unwrap_err();
        assert!(stream.starts_with("the method aes-256-cfb is not one"), "{stream}");
        // A part of a password is never shown.
        let odd = Method::parse("aes-256-gcm:s3cret word").unwrap_err();
        assert!(!odd.contains("s3cret"), "{odd}");
    }

    #[test]
    fn each_method_s_key_and_salt_have_their_lengths() {
        for method in Method::ALL {
            let master = master_key(b"podssh", method.key_len());
            assert_eq!(master.len(), method.key_len());
            assert_eq!(subkey(&master, &vec![7u8; method.salt_len()]).len(), method.key_len());
        }
        for method in Method::SIP022 {
            let psk = vec![9u8; method.key_len()];
            let key = stream_key(method, &psk, &vec![7u8; method.salt_len()]);
            assert_eq!(key.len(), method.key_len(), "{method:?}");
            assert_ne!(key.as_slice(), subkey(&psk, &vec![7u8; method.salt_len()]).as_slice(), "BLAKE3's, not HKDF's");
        }
    }
}
