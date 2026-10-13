//! The PIN protocol one of CTAP2 (CTAP 2.0, section 5.5.4), which each FIDO2
//! device speaks: podssh and the device agree on a secret over ECDH of
//! P-256, podssh sends the PIN's hash encrypted with it, and the device's
//! token, decrypted, proves the PIN in a request (an HMAC of the client
//! data's hash). The crypto is aws-lc-rs's, which the binary links already.

use aws_lc_rs::agreement::{self, UnparsedPublicKey, ECDH_P256};
use aws_lc_rs::cipher::{
    DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext, UnboundCipherKey, AES_256,
};
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;
use zeroize::Zeroizing;

use super::format::sha256;

/// The secret that podssh and a device agreed on, and podssh's half of the
/// agreement, which the device needs.
pub(crate) struct Shared {
    secret: Zeroizing<[u8; 32]>,
    /// podssh's public key: 0x04, x and y.
    public: Vec<u8>,
}

impl Shared {
    /// Agree with the device whose key of the agreement has the coordinates
    /// `x` and `y`: the secret is SHA-256 of the x of the shared point.
    pub fn agree(x: &[u8], y: &[u8]) -> Result<Shared, String> {
        let failed = |what: &str| format!("the agreement of the PIN protocol: {what}");
        let mine = agreement::PrivateKey::generate(&ECDH_P256).map_err(|_| failed("no key"))?;
        let public = mine.compute_public_key().map_err(|_| failed("no public key"))?.as_ref().to_vec();
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(x);
        point.extend_from_slice(y);
        let peer = UnparsedPublicKey::new(&ECDH_P256, &point);
        let secret = agreement::agree(&mine, peer, "the device's key is not on P-256", |shared| {
            Ok(Zeroizing::new(sha256(shared)))
        })
        .map_err(failed)?;
        Ok(Shared { secret, public })
    }

    /// podssh's half: the x and the y of its point.
    pub fn coordinates(&self) -> (&[u8], &[u8]) {
        let point = self.public.get(1..).unwrap_or_default();
        point.split_at(point.len() / 2)
    }

    /// `data`, whole blocks of 16 bytes, encrypted with AES-256-CBC and an
    /// IV of zeros, as the protocol one does.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = data.to_vec();
        let key = UnboundCipherKey::new(&AES_256, &self.secret[..]).map_err(|_| "the key of the PIN protocol")?;
        let context = EncryptionContext::Iv128(FixedLength::from([0u8; 16]));
        EncryptingKey::cbc(key)
            .and_then(|key| key.less_safe_encrypt(&mut out, context))
            .map_err(|_| "could not encrypt for the PIN protocol")?;
        Ok(out)
    }

    /// The device's side of an agreement, for a device in software.
    #[cfg(test)]
    pub fn of_secret(secret: [u8; 32]) -> Shared {
        Shared { secret: Zeroizing::new(secret), public: Vec::new() }
    }

    /// The reverse of [`Shared::encrypt`].
    pub fn decrypt(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut out = Zeroizing::new(data.to_vec());
        let key = UnboundCipherKey::new(&AES_256, &self.secret[..]).map_err(|_| "the key of the PIN protocol")?;
        let context = DecryptionContext::Iv128(FixedLength::from([0u8; 16]));
        let length = DecryptingKey::cbc(key)
            .and_then(|key| key.decrypt(&mut out, context).map(|plain| plain.len()))
            .map_err(|_| "could not decrypt the device's token")?;
        out.truncate(length);
        Ok(out)
    }
}

/// The PIN as the protocol sends it: the first 16 bytes of its SHA-256.
pub(crate) fn pin_hash(pin: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(sha256(pin.as_bytes())[..16].to_vec())
}

/// The proof of the PIN in a request: the first 16 bytes of the HMAC of the
/// client data's hash with the token.
pub(crate) fn auth(token: &[u8], client_data_hash: &[u8; 32]) -> Vec<u8> {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, token), client_data_hash);
    tag.as_ref()[..16].to_vec()
}

/// Whether CTAP2 takes `pin`: 4 characters at least, and 63 bytes at most.
pub(crate) fn check(pin: &str) -> Result<(), String> {
    if pin.chars().count() < 4 || pin.len() > 63 {
        return Err("a PIN of a security key has 4 characters at least and 63 bytes at most".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two ends that agree get one secret: what one encrypts, the other
    /// decrypts.
    #[test]
    fn two_ends_agree_on_one_secret() {
        let device = agreement::PrivateKey::generate(&ECDH_P256).unwrap();
        let point = device.compute_public_key().unwrap().as_ref().to_vec();
        let ours = Shared::agree(&point[1..33], &point[33..]).unwrap();
        let (x, y) = ours.coordinates();
        assert_eq!((x.len(), y.len()), (32, 32));
        let theirs: [u8; 32] =
            agreement::agree(&device, UnparsedPublicKey::new(&ECDH_P256, &ours.public), (), |shared| {
                Ok(sha256(shared))
            })
            .unwrap();
        assert_eq!(theirs, *ours.secret);
        let hash = pin_hash("1234");
        let sent = ours.encrypt(&hash).unwrap();
        assert_ne!(&sent[..], &hash[..]);
        assert_eq!(&ours.decrypt(&sent).unwrap()[..], &hash[..]);
        assert!(Shared::agree(&[1; 32], &[2; 32]).is_err(), "a point off the curve");
    }

    /// The cipher against bytes that podssh did not make: with an IV of
    /// zeros, the first block of AES-256-CBC is the block of AES-256-ECB,
    /// NIST SP 800-38A, F.1.5 (key 603deb10..., its first block).
    #[test]
    fn the_cipher_is_aes_256_cbc_with_an_iv_of_zeros() {
        #[rustfmt::skip] // the vector's bytes, eight to a row
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let plain: [u8; 16] =
            [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
        let want: [u8; 16] =
            [0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8];
        assert_eq!(Shared::of_secret(key).encrypt(&plain).unwrap(), want);
    }

    #[test]
    fn a_pin_is_checked_and_proved() {
        assert!(check("123").is_err());
        assert!(check("1234").is_ok());
        assert!(check(&"9".repeat(64)).is_err());
        assert_eq!(auth(&[1; 32], &[2; 32]).len(), 16);
        assert_ne!(auth(&[1; 32], &[2; 32]), auth(&[3; 32], &[2; 32]));
    }
}
