use aes::cipher::BlockModeEncrypt;
use russh::keys::ssh_key::private::{EcdsaKeypair, KeypairData};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, EcdsaCurve};

use super::*;

/// OpenSSL 3.5.7's `EVP_BytesToKey` with MD5, the passphrase "password" and
/// the salt 0102030405060708, as `openssl enc -md md5 -S 0102030405060708
/// -pass pass:password -P` prints it for AES-128, AES-192 and AES-256.
#[test]
fn the_key_of_a_passphrase_is_openssls() {
    let salt = [1, 2, 3, 4, 5, 6, 7, 8];
    let full = "E7B0971E52CA5CC8D0539FB3412F6316F7BA2E6EE293D9F3457B99436B51CE02";
    for len in [16, 24, 32] {
        let key = bytes_to_key(b"password", &salt, len);
        assert_eq!(hex(&full[..len * 2]).unwrap(), *key, "{len} bytes");
    }
}

/// A PEM key as OpenSSL encrypts it: `der` under `label`, encrypted with
/// `cipher` and the key of `passphrase`, with a random IV.
fn encrypt_pem(label: &str, der: &[u8], cipher: Cipher, name: &str, passphrase: &str) -> String {
    let iv: Vec<u8> = (0..cipher.iv_len()).map(|_| rand::random::<u8>()).collect();
    let key = bytes_to_key(passphrase.as_bytes(), &iv[..8], cipher.key_len());
    let block = cipher.iv_len();
    let mut buf = der.to_vec();
    buf.resize(der.len() + block - der.len() % block, 0);
    let len = match cipher {
        Cipher::Aes128 => cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<Pkcs7>(&mut buf, der.len())
            .unwrap()
            .len(),
        Cipher::Aes192 => cbc::Encryptor::<aes::Aes192>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<Pkcs7>(&mut buf, der.len())
            .unwrap()
            .len(),
        Cipher::Aes256 => cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<Pkcs7>(&mut buf, der.len())
            .unwrap()
            .len(),
        Cipher::DesEde3 => cbc::Encryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<Pkcs7>(&mut buf, der.len())
            .unwrap()
            .len(),
    };
    buf.truncate(len);
    let iv: String = iv.iter().map(|b| format!("{b:02X}")).collect();
    let body = STANDARD.encode(&buf);
    let lines: Vec<&str> = body.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!(
        "-----BEGIN {label}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: {name},{iv}\n\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// The SEC1 form of a P-256 key, as OpenSSL writes it: version 1, the
/// scalar, the named curve and the public point.
fn sec1_p256(key: &PrivateKey) -> Vec<u8> {
    let KeypairData::Ecdsa(EcdsaKeypair::NistP256 { public, private }) = key.key_data() else {
        panic!("not a P-256 key")
    };
    let mut der = vec![0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20];
    der.extend_from_slice(private.as_slice());
    der.extend_from_slice(&[0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    der.extend_from_slice(&[0xa1, 0x44, 0x03, 0x42, 0x00]);
    der.extend_from_slice(public.as_bytes());
    der
}

/// Each encrypted key with no passphrase is "encrypted", so that podssh
/// asks; it opens with its passphrase, and a wrong one fails as no
/// "encrypted".
fn asked_then_opened(text: &str, key: &PrivateKey, passphrase: &str, what: &str) {
    assert!(matches!(decode(text, None), Err(Error::KeyIsEncrypted)), "{what}: not asked for");
    let opened = decode(text, Some(passphrase)).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(opened.public_key().key_data(), key.public_key().key_data(), "{what}: another key");
    let wrong = decode(text, Some("not the passphrase"));
    assert!(wrong.is_err() && !matches!(wrong, Err(Error::KeyIsEncrypted)), "{what}: a wrong passphrase");
}

#[test]
fn an_encrypted_ecdsa_key_in_pem_opens_with_each_cipher() {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).unwrap();
    let der = sec1_p256(&key);
    for (cipher, name) in [
        (Cipher::Aes128, "AES-128-CBC"),
        (Cipher::Aes192, "AES-192-CBC"),
        (Cipher::Aes256, "AES-256-CBC"),
        (Cipher::DesEde3, "DES-EDE3-CBC"),
    ] {
        let text = encrypt_pem("EC PRIVATE KEY", &der, cipher, name, "pem words");
        asked_then_opened(&text, &key, "pem words", name);
    }
}

#[test]
fn an_encrypted_rsa_key_in_pem_opens() {
    let pair = crate::rsa_key::generate(2048).unwrap();
    let der = crate::rsa_key::pkcs1(&pair).unwrap();
    let key = PrivateKey::from(pair);
    let text = encrypt_pem("RSA PRIVATE KEY", &der, Cipher::Aes128, "AES-128-CBC", "pem words");
    asked_then_opened(&text, &key, "pem words", "RSA, AES-128-CBC");
    let text = encrypt_pem("RSA PRIVATE KEY", &der, Cipher::DesEde3, "DES-EDE3-CBC", "pem words");
    asked_then_opened(&text, &key, "pem words", "RSA, DES-EDE3-CBC");
}

#[test]
fn an_encrypted_pkcs8_key_is_asked_for() {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let mut text = Vec::new();
    russh::keys::encode_pkcs8_pem_encrypted(&key, b"pkcs8 words", 100, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    asked_then_opened(&text, &key, "pkcs8 words", "PKCS#8");
}

/// An encrypted PuTTY key is "encrypted" by its `Encryption` line; ssh-key
/// opens it (its own tests hold keys of each kind), and a plain one goes to
/// russh as it is.
#[test]
fn an_encrypted_putty_key_is_asked_for() {
    let encrypted = "PuTTY-User-Key-File-3: ssh-ed25519\r\nEncryption: aes256-cbc\r\nComment: k\r\n";
    assert!(matches!(decode(encrypted, None), Err(Error::KeyIsEncrypted)));
    let plain = "PuTTY-User-Key-File-3: ssh-ed25519\r\nEncryption: none\r\nComment: k\r\n";
    assert!(!matches!(decode(plain, None), Err(Error::KeyIsEncrypted)));
}

/// A key that no passphrase would open is refused before the question, by
/// name; a plain key and a key of OpenSSH's go to russh as before.
#[test]
fn what_cannot_be_opened_is_refused_at_once() {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).unwrap();
    let der = sec1_p256(&key);
    let des = encrypt_pem("EC PRIVATE KEY", &der, Cipher::DesEde3, "DES-CBC", "pem words");
    let why = decode(&des, None).unwrap_err().to_string();
    assert!(why.contains("DES-CBC") && why.contains("does not open"), "{why}");
    let dsa = des.replace("EC PRIVATE KEY", "DSA PRIVATE KEY").replace("DES-CBC", "AES-128-CBC");
    let why = decode(&dsa, None).unwrap_err().to_string();
    assert!(why.contains("DSA"), "{why}");
    let plain = key.to_openssh(LineEnding::LF).unwrap();
    assert_eq!(decode(&plain, None).unwrap().public_key(), key.public_key());
    let locked = key.encrypt(&mut rand::rng(), "openssh words").unwrap().to_openssh(LineEnding::LF).unwrap();
    asked_then_opened(&locked, &key, "openssh words", "OpenSSH");
}

/// The DER of a plain PKCS#8 key, as russh writes it.
fn pkcs8_der(key: &PrivateKey) -> Zeroizing<Vec<u8>> {
    let mut pem = Vec::new();
    russh::keys::encode_pkcs8_pem(key, &mut pem).unwrap();
    der(&String::from_utf8(pem).unwrap()).unwrap()
}

/// `der` encrypted as an encrypted key of PKCS#8 with PBES2: PBKDF2 with
/// `prf` and 2048 rounds, and `encryption`.
fn encrypt_pkcs8(
    der: &[u8],
    prf: pkcs5::pbes2::Pbkdf2Prf,
    encryption: pkcs5::pbes2::EncryptionScheme,
    passphrase: &str,
) -> String {
    use pkcs8::der::Encode;
    let salt: [u8; 8] = rand::random();
    let mut kdf = pkcs5::pbes2::Pbkdf2Params::hmac_sha256(2048, &salt).unwrap();
    kdf.prf = prf;
    let params = pkcs5::pbes2::Parameters { kdf: kdf.into(), encryption };
    let encrypted = params.encrypt(passphrase, der).unwrap();
    let info = pkcs8::EncryptedPrivateKeyInfoRef {
        encryption_algorithm: pkcs5::EncryptionScheme::Pbes2(params),
        encrypted_data: pkcs8::der::asn1::OctetStringRef::new(&encrypted).unwrap(),
    };
    pem_of("ENCRYPTED PRIVATE KEY", &info.to_der().unwrap())
}

fn pem_of(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// The scheme of OpenSSH's `ssh-keygen -m PKCS8` (PBKDF2 with HMAC-SHA1,
/// AES-128-CBC; measured with OpenSSH for Windows 10.0p2) and that of
/// OpenSSL's `-v2 des3` (HMAC-SHA256, Triple DES) open, as they need the
/// features of `pkcs5` that `Cargo.toml` turns on.
#[test]
fn the_pkcs8_schemes_of_openssh_and_openssl_open() {
    use pkcs5::pbes2::{EncryptionScheme, Pbkdf2Prf};
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).unwrap();
    let der = pkcs8_der(&key);
    let openssh =
        encrypt_pkcs8(&der, Pbkdf2Prf::HmacWithSha1, EncryptionScheme::Aes128Cbc { iv: rand::random() }, "p8");
    asked_then_opened(&openssh, &key, "p8", "PKCS#8 of OpenSSH: HMAC-SHA1, AES-128-CBC");
    let des3 =
        encrypt_pkcs8(&der, Pbkdf2Prf::HmacWithSha256, EncryptionScheme::DesEde3Cbc { iv: rand::random() }, "p8");
    asked_then_opened(&des3, &key, "p8", "PKCS#8 of OpenSSL's -v2 des3");
}

/// A scheme of PKCS#12, as OpenSSL's `-v1 PBE-SHA1-3DES` writes it
/// (pbeWithSHA1And3-KeyTripleDES-CBC), is refused before the question.
#[test]
fn a_pkcs12_scheme_is_refused_at_once() {
    let mut der = vec![0x30, 0x30, 0x30, 0x1c, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03];
    der.extend_from_slice(&[0x30, 0x0e, 0x04, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x02, 0x02, 0x08, 0x00]);
    der.extend_from_slice(&[0x04, 0x10]);
    der.extend_from_slice(&[0u8; 16]);
    let text = pem_of("ENCRYPTED PRIVATE KEY", &der);
    let why = decode(&text, None).unwrap_err().to_string();
    assert!(why.contains("PKCS#12 (1.2.840.113549.1.12.1.3)") && why.contains("does not open"), "{why}");
}
