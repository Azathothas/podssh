//! The cipher of frp's control stream on its wire v1, after the login
//! (`fatedier/golib:crypto/encode.go`, with frpc's salt `frp`): AES-128 in
//! CFB mode, its key PBKDF2-HMAC-SHA1 of the token, 64 rounds, and a random
//! IV of 16 bytes that each side writes before its first byte and reads
//! before the other's. Each direction has its own IV and its own state.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

/// frpc's salt (`client/service.go`: `crypto.DefaultSalt = "frp"`).
pub const SALT: &[u8] = b"frp";
/// The rounds of the key's PBKDF2 (golib's).
pub const ROUNDS: u32 = 64;
/// The length of the key, the IV and AES's block.
pub const BLOCK: usize = 16;

/// The control stream's key of `token`: PBKDF2-HMAC-SHA1, one block, its
/// first 16 bytes.
pub fn key(token: &[u8]) -> [u8; BLOCK] {
    let prf = |data: &[u8]| -> [u8; 20] {
        let mut mac = Hmac::<Sha1>::new_from_slice(token).expect("HMAC takes a key of any length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    };
    let mut first = SALT.to_vec();
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut u = prf(&first);
    let mut t = u;
    for _ in 1..ROUNDS {
        u = prf(&u);
        for (t, u) in t.iter_mut().zip(u) {
            *t ^= u;
        }
    }
    let mut out = [0u8; BLOCK];
    out.copy_from_slice(&t[..BLOCK]);
    out
}

/// One direction of CFB-128, as Go's `cipher.NewCFBEncrypter` and
/// `NewCFBDecrypter` run it: each block's keystream is AES of the block of
/// ciphertext before it, the IV first.
pub struct Cfb {
    aes: aes::Aes128,
    keystream: [u8; BLOCK],
    /// The ciphertext of the block in progress, the next keystream's input.
    next: [u8; BLOCK],
    pos: usize,
    decrypt: bool,
}

impl Cfb {
    fn new(key: &[u8; BLOCK], iv: &[u8; BLOCK], decrypt: bool) -> Cfb {
        let aes = aes::Aes128::new(&(*key).into());
        let mut cfb = Cfb { aes, keystream: [0; BLOCK], next: [0; BLOCK], pos: 0, decrypt };
        cfb.keystream = cfb.encrypt(iv);
        cfb
    }

    /// The side that writes with `iv`.
    pub fn encrypter(key: &[u8; BLOCK], iv: &[u8; BLOCK]) -> Cfb {
        Cfb::new(key, iv, false)
    }

    /// The side that reads what was written with `iv`.
    pub fn decrypter(key: &[u8; BLOCK], iv: &[u8; BLOCK]) -> Cfb {
        Cfb::new(key, iv, true)
    }

    fn encrypt(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut b = aes::Block::from(*block);
        self.aes.encrypt_block(&mut b);
        b.into()
    }

    /// Encrypt or decrypt `data` in place, as this side does.
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.pos == BLOCK {
                self.keystream = self.encrypt(&self.next);
                self.pos = 0;
            }
            let input = *byte;
            let output = input ^ self.keystream[self.pos];
            self.next[self.pos] = if self.decrypt { input } else { output };
            *byte = output;
            self.pos += 1;
        }
    }
}

/// A fresh IV, from the operating system's random source, as the
/// WebSocket's key is drawn.
pub fn iv() -> Result<[u8; BLOCK], String> {
    use rustls::crypto::SecureRandom as _;
    let mut iv = [0u8; BLOCK];
    crate::crypto::random::OsRandom.fill(&mut iv).map_err(|_| "no random bytes for the IV".to_string())?;
    Ok(iv)
}
