//! The keys of QUIC (RFC 9001, section 5), for the two TLS 1.3 suites of
//! `suites.rs` (T-301): a packet key, AES-GCM with the nonce of section 5.3,
//! and the header protection of section 5.4, AES on a sample of the
//! ciphertext. The quick tunnel's QUIC connection takes them through rustls.
//!
//! **No suite offers ChaCha20-Poly1305 for TLS 1.3 here**, so the header
//! protection of section 5.4.4 is not written: a peer can only select AES.

// One `KeyInit` serves both the block cipher and the AEAD.
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic;
use rustls::Error;

/// The sample of section 5.4.2, and the tag of each AEAD here.
const SAMPLE_LEN: usize = 16;
const TAG_LEN: usize = 16;
/// Section 6.6: the packets that one AES-GCM key may protect, and the forged
/// ones that a receiver may meet before it must stop using the key.
const CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
const INTEGRITY_LIMIT: u64 = 1 << 52;

/// Which AES: the suite's key length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    Aes128,
    Aes256,
}

/// The QUIC keys of a suite, for its `quic` field.
#[derive(Debug)]
pub struct Keys(pub Width);

pub static AES_128_GCM: Keys = Keys(Width::Aes128);
pub static AES_256_GCM: Keys = Keys(Width::Aes256);

impl quic::Algorithm for Keys {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey { aead: Gcm::new(self.0, key.as_ref()), iv })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(HeaderKey(Block::new(self.0, key.as_ref())))
    }

    fn aead_key_len(&self) -> usize {
        match self.0 {
            Width::Aes128 => 16,
            Width::Aes256 => 32,
        }
    }
}

/// AES-GCM for packets. A key of the wrong length makes one that fails each
/// call, as `aead.rs` does, rather than a panic in the record layer.
enum Gcm {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Broken,
}

impl Gcm {
    fn new(width: Width, key: &[u8]) -> Gcm {
        let made = match width {
            Width::Aes128 => Aes128Gcm::new_from_slice(key).map(|k| Gcm::Aes128(Box::new(k))),
            Width::Aes256 => Aes256Gcm::new_from_slice(key).map(|k| Gcm::Aes256(Box::new(k))),
        };
        made.unwrap_or(Gcm::Broken)
    }

    /// Seal `payload` in place; the tag, apart.
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], payload: &mut [u8]) -> Option<[u8; TAG_LEN]> {
        let nonce = (*nonce).into();
        let tag = match self {
            Gcm::Aes128(k) => k.encrypt_inout_detached(&nonce, aad, payload.into()).ok()?,
            Gcm::Aes256(k) => k.encrypt_inout_detached(&nonce, aad, payload.into()).ok()?,
            Gcm::Broken => return None,
        };
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&tag);
        Some(out)
    }

    /// Open `data` in place against `tag`.
    fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8]) -> Option<()> {
        let nonce = (*nonce).into();
        let tag: [u8; TAG_LEN] = tag.try_into().ok()?;
        let tag = tag.into();
        match self {
            Gcm::Aes128(k) => k.decrypt_inout_detached(&nonce, aad, data.into(), &tag).ok(),
            Gcm::Aes256(k) => k.decrypt_inout_detached(&nonce, aad, data.into(), &tag).ok(),
            Gcm::Broken => None,
        }
    }
}

struct PacketKey {
    aead: Gcm,
    iv: Iv,
}

impl PacketKey {
    fn sealed(&self, nonce: Nonce, header: &[u8], payload: &mut [u8]) -> Result<quic::Tag, Error> {
        let tag = self.aead.seal(&nonce.0, header, payload).ok_or(Error::EncryptError)?;
        Ok(quic::Tag::from(&tag[..]))
    }

    fn opened<'a>(&self, nonce: Nonce, header: &[u8], payload: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let len = payload.len().checked_sub(TAG_LEN).ok_or(Error::DecryptError)?;
        let (data, tag) = payload.split_at_mut(len);
        self.aead.open(&nonce.0, header, data, tag).ok_or(Error::DecryptError)?;
        Ok(&payload[..len])
    }
}

impl quic::PacketKey for PacketKey {
    fn encrypt_in_place(&self, packet_number: u64, header: &[u8], payload: &mut [u8]) -> Result<quic::Tag, Error> {
        self.sealed(Nonce::new(&self.iv, packet_number), header, payload)
    }

    fn encrypt_in_place_for_path(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        self.sealed(Nonce::for_path(path_id, &self.iv, packet_number), header, payload)
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.opened(Nonce::new(&self.iv, packet_number), header, payload)
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.opened(Nonce::for_path(path_id, &self.iv, packet_number), header, payload)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        CONFIDENTIALITY_LIMIT
    }

    fn integrity_limit(&self) -> u64 {
        INTEGRITY_LIMIT
    }
}

/// AES on one block, for the mask of section 5.4.3.
enum Block {
    Aes128(Box<aes::Aes128>),
    Aes256(Box<aes::Aes256>),
    Broken,
}

impl Block {
    fn new(width: Width, key: &[u8]) -> Block {
        let made = match width {
            Width::Aes128 => aes::Aes128::new_from_slice(key).map(|k| Block::Aes128(Box::new(k))),
            Width::Aes256 => aes::Aes256::new_from_slice(key).map(|k| Block::Aes256(Box::new(k))),
        };
        made.unwrap_or(Block::Broken)
    }

    /// The mask: the first five bytes of AES on the sample.
    fn mask(&self, sample: &[u8]) -> Option<[u8; 5]> {
        let sample: [u8; SAMPLE_LEN] = sample.try_into().ok()?;
        let mut block = aes::Block::from(sample);
        match self {
            Block::Aes128(k) => k.encrypt_block(&mut block),
            Block::Aes256(k) => k.encrypt_block(&mut block),
            Block::Broken => return None,
        }
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        Some(mask)
    }
}

struct HeaderKey(Block);

impl HeaderKey {
    /// Section 5.4.1: four bits of a long header's first byte, five of a
    /// short one's, and as many bytes of the packet number as that byte
    /// names, read before the mask when adding it and after when removing.
    fn xor(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8], removing: bool) -> Result<(), Error> {
        let mask = self.0.mask(sample).ok_or_else(|| Error::General("a sample of the wrong length".into()))?;
        let (first_mask, number_mask) = mask.split_first().expect("five bytes");
        if packet_number.len() > number_mask.len() {
            return Err(Error::General("a packet number longer than four bytes".into()));
        }
        let bits = if *first & 0x80 == 0x80 { 0x0f } else { 0x1f };
        let plain = if removing { *first ^ (first_mask & bits) } else { *first };
        let length = usize::from(plain & 0x03) + 1;
        *first ^= first_mask & bits;
        for (byte, mask) in packet_number.iter_mut().zip(number_mask).take(length) {
            *byte ^= mask;
        }
        Ok(())
    }
}

impl quic::HeaderProtectionKey for HeaderKey {
    fn encrypt_in_place(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) -> Result<(), Error> {
        self.xor(sample, first, packet_number, false)
    }

    fn decrypt_in_place(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) -> Result<(), Error> {
        self.xor(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}
