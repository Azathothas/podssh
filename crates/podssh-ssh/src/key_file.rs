//! A private key file, in each format that podssh reads (T-287): OpenSSH's,
//! PEM (an RSA key of PKCS#1, an ECDSA key of SEC1), PKCS#8 and PuTTY's,
//! plain or encrypted. russh's `decode_secret_key` reads them, but it says
//! that a key is encrypted only in OpenSSH's format and in PEM encrypted with
//! AES-128-CBC: it reads an encrypted key of PKCS#8, or a PEM key of another
//! cipher, as a plain one and fails; an encrypted PuTTY key fails with
//! ssh-key's error; and it reads a decrypted PEM key only as RSA. podssh then
//! never asked for the passphrase of such a key. Here the text says first
//! whether a key is encrypted, and a PEM key is decrypted as OpenSSL
//! encrypted it, then read as a plain one. An encrypted key of PKCS#8 is
//! opened by russh through the `pkcs5` crate, with the schemes of OpenSSH's
//! `ssh-keygen -m PKCS8` (PBKDF2 with HMAC-SHA1) and of OpenSSL's `-v2 des3`
//! (Triple DES) turned on in `Cargo.toml`; one of PBES1 or of PKCS#12 is
//! refused before the question.

use std::path::Path;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use russh::keys::{Error, PrivateKey};
use zeroize::Zeroizing;

/// The key in the file at `path`, opened with `passphrase` when it is
/// encrypted.
pub fn load(path: &Path, passphrase: Option<&str>) -> Result<PrivateKey, Error> {
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    decode(&text, passphrase)
}

/// The key in `text`. An encrypted key with no passphrase is
/// `Error::KeyIsEncrypted` in each format, so that the caller asks for one;
/// a key that no passphrase would open is refused at once, by name.
pub fn decode(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, Error> {
    match (encryption(text)?, passphrase) {
        (Encryption::Unseen, _) => russh::keys::decode_secret_key(text, passphrase),
        (Encryption::Seen | Encryption::Pem(_), None) => Err(Error::KeyIsEncrypted),
        (Encryption::Seen, Some(passphrase)) => russh::keys::decode_secret_key(text, Some(passphrase)),
        (Encryption::Pem(pem), Some(passphrase)) => open_pem(text, &pem, passphrase),
    }
}

enum Encryption {
    /// Nothing in the text says so: russh reads the key, and says itself
    /// whether a key of OpenSSH's is encrypted.
    Unseen,
    /// An encrypted key of PKCS#8 or of PuTTY, which russh opens with its
    /// passphrase.
    Seen,
    /// A PEM key that OpenSSL encrypted (`Proc-Type: 4,ENCRYPTED`).
    Pem(Pem),
}

struct Pem {
    /// What the BEGIN line names, as `RSA PRIVATE KEY` or `EC PRIVATE KEY`.
    label: String,
    cipher: Cipher,
    iv: Vec<u8>,
}

/// The ciphers of a PEM key that podssh opens: those of OpenSSH's
/// `ssh-keygen -m PEM` (AES-128-CBC) and of OpenSSL's `-aes128`, `-aes192`,
/// `-aes256` and `-des3`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cipher {
    Aes128,
    Aes192,
    Aes256,
    DesEde3,
}

impl Cipher {
    fn named(name: &str) -> Option<Cipher> {
        match name {
            "AES-128-CBC" => Some(Cipher::Aes128),
            "AES-192-CBC" => Some(Cipher::Aes192),
            "AES-256-CBC" => Some(Cipher::Aes256),
            "DES-EDE3-CBC" => Some(Cipher::DesEde3),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Cipher::Aes128 => 16,
            Cipher::Aes192 | Cipher::DesEde3 => 24,
            Cipher::Aes256 => 32,
        }
    }

    /// The IV, and the block, in bytes.
    fn iv_len(self) -> usize {
        match self {
            Cipher::DesEde3 => 8,
            _ => 16,
        }
    }
}

/// Whether `text` holds an encrypted key, read from its text alone.
fn encryption(text: &str) -> Result<Encryption, Error> {
    let start = text.trim_start();
    if start.starts_with("PuTTY-User-Key-File-") {
        let encrypted = start.lines().filter_map(|l| l.strip_prefix("Encryption:")).any(|v| v.trim() != "none");
        return Ok(if encrypted { Encryption::Seen } else { Encryption::Unseen });
    }
    let mut lines = text.lines().map(str::trim).skip_while(|l| !l.starts_with("-----BEGIN "));
    let Some(begin) = lines.next() else { return Ok(Encryption::Unseen) };
    let label = begin.trim_start_matches("-----BEGIN ").trim_end_matches('-').trim().to_string();
    if label == "ENCRYPTED PRIVATE KEY" {
        return pkcs8_scheme(text).map(|()| Encryption::Seen);
    }
    // The headers of RFC 1421 follow the BEGIN line; a line of base64 has
    // no colon.
    let (mut encrypted, mut dek) = (false, None);
    for (name, value) in lines.map_while(|l| l.split_once(':')) {
        match name.trim() {
            "Proc-Type" => encrypted = value.trim().ends_with(",ENCRYPTED"),
            "DEK-Info" => dek = Some(value.trim()),
            _ => {}
        }
    }
    if !encrypted {
        return Ok(Encryption::Unseen);
    }
    if label == "DSA PRIVATE KEY" {
        return refused("a DSA key, which podssh does not use: OpenSSH 10 removed DSA".into());
    }
    let Some(dek) = dek else { return refused("an encrypted PEM key with no DEK-Info line".into()) };
    let (name, iv) = dek.split_once(',').unwrap_or((dek, ""));
    let Some(cipher) = Cipher::named(name.trim()) else {
        return refused(format!(
            "a PEM key encrypted with {name}, which podssh does not open \
             (it opens AES-128-CBC, AES-192-CBC, AES-256-CBC and DES-EDE3-CBC)"
        ));
    };
    match hex(iv.trim()) {
        Some(iv) if iv.len() == cipher.iv_len() => Ok(Encryption::Pem(Pem { label, cipher, iv })),
        _ => refused(format!("the DEK-Info line of an encrypted PEM key has no IV of {} bytes", cipher.iv_len())),
    }
}

fn refused<T>(why: String) -> Result<T, Error> {
    Err(Error::IO(std::io::Error::new(std::io::ErrorKind::Unsupported, why)))
}

/// The bytes of the first PEM block of `text`, its headers left out.
fn der(text: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let body: String = text
        .lines()
        .map(str::trim)
        .skip_while(|l| !l.starts_with("-----BEGIN "))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END "))
        .filter(|l| !l.is_empty() && !l.contains(':'))
        .collect();
    STANDARD.decode(body.as_bytes()).map(Zeroizing::new).map_err(|_| Error::CouldNotReadKey)
}

/// Whether podssh opens the scheme of an encrypted key of PKCS#8: PBES2,
/// with PBKDF2 or scrypt, and a cipher that `pkcs5` reads (an unknown one
/// fails to parse). PBES1, and the schemes of PKCS#12 (as OpenSSL's
/// `-v1 PBE-SHA1-3DES`), are refused before the question.
fn pkcs8_scheme(text: &str) -> Result<(), Error> {
    use pkcs8::der::Decode;
    let der = der(text)?;
    match pkcs8::EncryptedPrivateKeyInfoRef::from_der(&der) {
        Ok(info) => match info.encryption_algorithm {
            pkcs5::EncryptionScheme::Pbes2(_) => Ok(()),
            _ => refused("an encrypted PKCS#8 key of PBES1, which podssh does not open: it opens PBES2".into()),
        },
        Err(e) => match scheme_oid(&der) {
            Some(oid) if oid.starts_with("1.2.840.113549.1.12.1.") => refused(format!(
                "an encrypted PKCS#8 key of a scheme of PKCS#12 ({oid}), which podssh does not open: it opens PBES2"
            )),
            Some(oid) => refused(format!("an encrypted PKCS#8 key of the scheme {oid}, which podssh does not open")),
            None => refused(format!("an encrypted PKCS#8 key that podssh cannot read ({e})")),
        },
    }
}

/// The identifier of the scheme of an encrypted key of PKCS#8, which
/// `pkcs5` could not read.
fn scheme_oid(der: &[u8]) -> Option<String> {
    use pkcs8::der::{Decode, Reader, SliceReader};
    let mut reader = SliceReader::new(der).ok()?;
    let algorithm = reader
        .sequence(|r| {
            let algorithm = pkcs8::spki::AlgorithmIdentifierRef::decode(r)?;
            <&pkcs8::der::asn1::OctetStringRef>::decode(r)?;
            Ok::<_, pkcs8::der::Error>(algorithm)
        })
        .ok()?;
    Some(algorithm.oid.to_string())
}

/// The key of an encrypted PEM key: decrypted with the key that the
/// passphrase gives, then read by russh as the plain key of the same label.
/// A wrong passphrase fails at the padding, or at the key that it reads.
fn open_pem(text: &str, pem: &Pem, passphrase: &str) -> Result<PrivateKey, Error> {
    let mut data = der(text)?;
    let key = bytes_to_key(passphrase.as_bytes(), &pem.iv[..8], pem.cipher.key_len());
    let len = decrypt(pem.cipher, &key, &pem.iv, &mut data)?;
    data.truncate(len);
    let encoded = Zeroizing::new(STANDARD.encode(&data[..]));
    let plain = Zeroizing::new(format!("-----BEGIN {0}-----\n{1}\n-----END {0}-----\n", pem.label, *encoded));
    russh::keys::decode_secret_key(&plain, None)
}

/// `data` decrypted in place; the length of the plain text, its padding
/// taken off.
fn decrypt(cipher: Cipher, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<usize, Error> {
    // The lengths were checked, so a key or an IV of a wrong length cannot
    // come here.
    let length = |_| Error::CouldNotReadKey;
    let plain = match cipher {
        Cipher::Aes128 => {
            cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv).map_err(length)?.decrypt_padded::<Pkcs7>(data)?
        }
        Cipher::Aes192 => {
            cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv).map_err(length)?.decrypt_padded::<Pkcs7>(data)?
        }
        Cipher::Aes256 => {
            cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(length)?.decrypt_padded::<Pkcs7>(data)?
        }
        Cipher::DesEde3 => {
            cbc::Decryptor::<des::TdesEde3>::new_from_slices(key, iv).map_err(length)?.decrypt_padded::<Pkcs7>(data)?
        }
    };
    Ok(plain.len())
}

/// The key that OpenSSL's `EVP_BytesToKey` makes for a PEM key, with MD5
/// and one round: the digest of the passphrase and the salt (the first 8
/// bytes of the IV), then of the last digest, the passphrase and the salt,
/// until there are `len` bytes.
fn bytes_to_key(passphrase: &[u8], salt: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    // Room for the last digest, so that the buffer never moves.
    let mut out = Zeroizing::new(Vec::with_capacity(len + 16));
    let mut last = Zeroizing::new([0u8; 16]);
    while out.len() < len {
        let mut md5 = md5::Context::new();
        if !out.is_empty() {
            md5.consume(&last[..]);
        }
        md5.consume(passphrase);
        md5.consume(salt);
        *last = md5.finalize().0;
        out.extend_from_slice(&last[..]);
    }
    out.truncate(len);
    out
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

#[cfg(test)]
#[path = "key_file_tests.rs"]
mod tests;
