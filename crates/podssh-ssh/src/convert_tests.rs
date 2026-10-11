use russh::keys::{Algorithm, EcdsaCurve};

use super::*;

/// What the `ssh-keygen -e` of OpenSSH for Windows 10.0p2 wrote for its own
/// keys (2026-10-11); the comment of RFC 4716 names `user@example` here in
/// place of the host's user and name.
macro_rules! data {
    ($name:literal) => {
        include_str!(concat!("convert_testdata/", $name))
    };
}

const BY: &str = "user@example";

fn key(text: &str) -> PublicKey {
    PublicKey::from_openssh(text.trim()).unwrap()
}

fn bare(key: &PublicKey) -> String {
    PublicKey::new(key.key_data().clone(), "").to_openssh().unwrap()
}

/// `-e` writes what OpenSSH wrote, byte for byte, and `-i` reads it back.
#[test]
fn export_and_import_as_openssh() {
    let cases: [(&str, Format, &str); 10] = [
        (data!("ed25519.pub"), Format::Rfc4716, data!("ed25519.RFC4716")),
        (data!("ecdsa.pub"), Format::Rfc4716, data!("ecdsa.RFC4716")),
        (data!("ecdsa.pub"), Format::Pkcs8, data!("ecdsa.PKCS8")),
        (data!("ecdsa.pub"), Format::Pem, data!("ecdsa.PEM")),
        (data!("rsa.pub"), Format::Rfc4716, data!("rsa.RFC4716")),
        (data!("rsa.pub"), Format::Pkcs8, data!("rsa.PKCS8")),
        (data!("rsa.pub"), Format::Pem, data!("rsa.PEM")),
        (data!("ec384.pub"), Format::Pkcs8, data!("ec384.PKCS8")),
        (data!("ec521.pub"), Format::Pkcs8, data!("ec521.PKCS8")),
        (data!("rsa.pub"), Format::Pem, data!("rsa.PEM")),
    ];
    for (public, format, theirs) in cases {
        let public = key(public);
        assert_eq!(export(&public, format, BY).unwrap(), theirs, "{format:?} of {}", public.algorithm());
        assert_eq!(bare(&import(theirs, Some(format)).unwrap()), bare(&public), "{format:?} read back");
    }
    // RFC 4716 is the default of -i, and its headers may go on over lines.
    let continued = data!("ed25519.RFC4716").replace(
        "Comment: \"256-bit ED25519, converted by user@example from OpenSSH\"",
        "Comment: \"a long comment that \\\n goes on\"\nx-other: value",
    );
    assert_eq!(bare(&import(&continued, None).unwrap()), bare(&key(data!("ed25519.pub"))));
}

/// What a key type lacks, and a private key given to `-i`, are refused by
/// name; `-m` takes OpenSSH's names, in any case.
#[test]
fn refusals_name_the_reason() {
    let ed25519 = key(data!("ed25519.pub"));
    for format in [Format::Pkcs8, Format::Pem] {
        let why = export(&ed25519, format, BY).unwrap_err();
        assert!(why.starts_with("an ED25519 key has no ") && why.contains("-e -m RFC4716"), "{why}");
    }
    let private = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
    assert!(import(private, Some(Format::Pem)).unwrap_err().contains("imports public keys only"));
    assert!(import(data!("ed25519.pub"), None).unwrap_err().contains("---- BEGIN SSH2 PUBLIC KEY ----"));
    assert_eq!(Format::parse("pkcs8"), Ok(Format::Pkcs8));
    assert_eq!(Format::parse("bogus").unwrap_err(), "Unsupported conversion format \"bogus\"");
}

/// `-m PEM` and `-m PKCS8` write a private key that reads back, plain and
/// encrypted, for RSA and each curve; an Ed25519 key keeps OpenSSH's format.
#[test]
fn private_forms_read_back() {
    let keys = [
        PrivateKey::from(crate::rsa_key::generate(2048).unwrap()),
        PrivateKey::random(&mut rand::rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).unwrap(),
        PrivateKey::random(&mut rand::rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }).unwrap(),
        PrivateKey::random(&mut rand::rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 }).unwrap(),
    ];
    for key in &keys {
        for (format, plain, locked) in [
            (Format::Pem, "-----BEGIN ", "Proc-Type: 4,ENCRYPTED"),
            (Format::Pkcs8, "-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----"),
        ] {
            let text = private_text(key, format, "").unwrap().unwrap();
            assert!(text.starts_with(plain), "{}", *text);
            let read = crate::key_file::decode(&text, None).unwrap();
            assert_eq!(read.public_key().key_data(), key.public_key().key_data(), "{format:?}");
            let text = private_text(key, format, "pw words").unwrap().unwrap();
            assert!(text.contains(locked), "{}", *text);
            assert!(matches!(crate::key_file::decode(&text, None), Err(russh::keys::Error::KeyIsEncrypted)));
            let read = crate::key_file::decode(&text, Some("pw words")).unwrap();
            assert_eq!(read.public_key().key_data(), key.public_key().key_data(), "{format:?}, encrypted");
        }
    }
    let rsa = private_text(&keys[0], Format::Pem, "").unwrap().unwrap();
    assert!(rsa.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
    let ec = private_text(&keys[1], Format::Pem, "").unwrap().unwrap();
    assert!(ec.starts_with("-----BEGIN EC PRIVATE KEY-----\n"));
    let ed25519 = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    assert!(private_text(&ed25519, Format::Pem, "").unwrap().is_none());
    assert!(private_text(&keys[0], Format::Rfc4716, "").unwrap().is_none());
}
