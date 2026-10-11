//! Key formats of other systems, for `podssh keygen -e`, `-i` and `-m`
//! (T-022): a public key in RFC 4716, PKCS#8 (a SubjectPublicKeyInfo) or PEM
//! (PKCS#1 for RSA), both ways, and a private key in PEM (PKCS#1, SEC1) or
//! PKCS#8, as the `ssh-keygen` of OpenSSH for Windows 10.0p2 writes them
//! (measured on 2026-10-11). An Ed25519 key has a form of RFC 4716 only, as
//! in OpenSSH. Each of these private forms is read back through
//! [`crate::key_file`].

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use russh::keys::ssh_key::encoding::Encode;
use russh::keys::ssh_key::private::{EcdsaKeypair, KeypairData};
use russh::keys::ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey};
use russh::keys::ssh_key::Mpint;
use russh::keys::{PrivateKey, PublicKey};
use zeroize::Zeroizing;

/// `-m`: a format of `ssh-keygen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// RFC 4716 for a public key; for a private key, OpenSSH's own format.
    Rfc4716,
    Pkcs8,
    Pem,
}

impl Format {
    /// `-m NAME`, in any case, as OpenSSH compares it.
    pub fn parse(name: &str) -> Result<Format, String> {
        match name.to_ascii_uppercase().as_str() {
            "RFC4716" | "SSH2" => Ok(Format::Rfc4716),
            "PKCS8" => Ok(Format::Pkcs8),
            "PEM" => Ok(Format::Pem),
            _ => Err(format!("Unsupported conversion format \"{name}\"")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Format::Rfc4716 => "RFC4716",
            Format::Pkcs8 => "PKCS8",
            Format::Pem => "PEM",
        }
    }
}

// The identifiers of the algorithms, as DER contents.
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

/// `-e`: `key` in `format`, as `ssh-keygen -e` writes it; `by` is the
/// `user@host` of the comment of RFC 4716.
pub fn export(key: &PublicKey, format: Format, by: &str) -> Result<String, String> {
    match format {
        Format::Rfc4716 => {
            let blob = key.key_data().encode_vec().map_err(|e| e.to_string())?;
            let body = STANDARD.encode(blob);
            let mut out = String::from("---- BEGIN SSH2 PUBLIC KEY ----\n");
            let kind = crate::known_hosts::key_type(key);
            out.push_str(&format!(
                "Comment: \"{}-bit {kind}, converted by {by} from OpenSSH\"\n",
                crate::keygen::bits(key)
            ));
            for line in body.as_bytes().chunks(70) {
                out.push_str(std::str::from_utf8(line).unwrap_or_default());
                out.push('\n');
            }
            out.push_str("---- END SSH2 PUBLIC KEY ----\n");
            Ok(out)
        }
        Format::Pem if matches!(key.key_data(), KeyData::Rsa(_)) => {
            let KeyData::Rsa(rsa) = key.key_data() else { unreachable!() };
            Ok(armour("RSA PUBLIC KEY", &rsa_public(rsa)?))
        }
        Format::Pkcs8 | Format::Pem => {
            let spki = match key.key_data() {
                KeyData::Rsa(rsa) => seq(&[seq(&[oid(RSA_ENCRYPTION), null()]), bits(&rsa_public(rsa)?)]),
                KeyData::Ecdsa(ec) => seq(&[seq(&[oid(EC_PUBLIC_KEY), oid(curve_of(ec))]), bits(ec.as_sec1_bytes())]),
                _ => {
                    return Err(format!(
                        "an {} key has no {} form: -e -m RFC4716 exports it",
                        crate::known_hosts::key_type(key),
                        format.name()
                    ))
                }
            };
            Ok(armour("PUBLIC KEY", &spki))
        }
    }
}

fn curve_of(ec: &EcdsaPublicKey) -> &'static [u8] {
    match ec {
        EcdsaPublicKey::NistP256(_) => P256,
        EcdsaPublicKey::NistP384(_) => P384,
        EcdsaPublicKey::NistP521(_) => P521,
    }
}

/// PKCS#1's RSAPublicKey: the modulus and the exponent.
fn rsa_public(rsa: &RsaPublicKey) -> Result<Vec<u8>, String> {
    let positive = |m: &Mpint| m.as_positive_bytes().map(<[u8]>::to_vec).ok_or("an RSA key with a negative number");
    Ok(seq(&[integer(&positive(rsa.n())?), integer(&positive(rsa.e())?)]))
}

/// `-i`: the public key of `text` in `format` (RFC 4716 when none is
/// given). A private key is refused by name: `-i` imports public keys
/// only, and podssh never prints a private key.
pub fn import(text: &str, format: Option<Format>) -> Result<PublicKey, String> {
    let begin = text.lines().map(str::trim).find(|l| l.starts_with("----"));
    if begin.is_some_and(|l| l.contains("PRIVATE KEY")) {
        return Err(
            "a private key: podssh keygen -i imports public keys only (-y prints the public key of a private key)"
                .into(),
        );
    }
    match format.unwrap_or(Format::Rfc4716) {
        Format::Rfc4716 => rfc4716(text),
        Format::Pkcs8 | Format::Pem => pem_public(text),
    }
}

/// The key of RFC 4716: its header lines (`Name: value`, continued with `\`
/// at the end) passed over, its base64 body decoded.
fn rfc4716(text: &str) -> Result<PublicKey, String> {
    let mut lines = text.lines().map(str::trim).skip_while(|l| *l != "---- BEGIN SSH2 PUBLIC KEY ----");
    if lines.next().is_none() {
        return Err("not a public key of RFC 4716: no line ---- BEGIN SSH2 PUBLIC KEY ----".into());
    }
    let (mut body, mut continued) = (String::new(), false);
    for line in lines {
        if line == "---- END SSH2 PUBLIC KEY ----" {
            let blob = STANDARD.decode(body.as_bytes()).map_err(|e| format!("its base64: {e}"))?;
            return PublicKey::from_bytes(&blob).map_err(|e| format!("not a public key: {e}"));
        }
        if continued || line.contains(':') {
            continued = line.ends_with('\\');
            continue;
        }
        body.push_str(line);
    }
    Err("a public key of RFC 4716 with no line ---- END SSH2 PUBLIC KEY ----".into())
}

/// The key of a PEM block: `PUBLIC KEY` (a SubjectPublicKeyInfo) or `RSA
/// PUBLIC KEY` (PKCS#1).
fn pem_public(text: &str) -> Result<PublicKey, String> {
    use pkcs8::der::{Decode, Reader, SliceReader};
    let label =
        text.lines().map(str::trim).find_map(|l| l.strip_prefix("-----BEGIN ")).map(|l| l.trim_end_matches('-'));
    let der = crate::key_file::der(text).map_err(|_| "its base64 does not decode".to_string())?;
    let rsa = |der: &[u8]| -> Result<PublicKey, String> {
        let mut reader = SliceReader::new(der).map_err(|e| e.to_string())?;
        let (n, e) = reader
            .sequence(|r| {
                let n = pkcs8::der::asn1::UintRef::decode(r)?;
                let e = pkcs8::der::asn1::UintRef::decode(r)?;
                Ok::<_, pkcs8::der::Error>((n.as_bytes().to_vec(), e.as_bytes().to_vec()))
            })
            .map_err(|e| format!("not an RSA public key: {e}"))?;
        let key = RsaPublicKey::new(Mpint::from_positive_bytes(&e), Mpint::from_positive_bytes(&n))
            .map_err(|e| format!("not an RSA public key: {e}"))?;
        Ok(PublicKey::new(KeyData::Rsa(key), ""))
    };
    match label {
        Some("RSA PUBLIC KEY") => rsa(&der),
        Some("PUBLIC KEY") => {
            let spki =
                pkcs8::spki::SubjectPublicKeyInfoRef::from_der(&der).map_err(|e| format!("not a public key: {e}"))?;
            let raw = spki.subject_public_key.raw_bytes();
            let algorithm = spki.algorithm.oid.as_bytes();
            if algorithm == RSA_ENCRYPTION {
                rsa(raw)
            } else if algorithm == EC_PUBLIC_KEY {
                let key = EcdsaPublicKey::from_sec1_bytes(raw).map_err(|e| format!("not an ECDSA public key: {e}"))?;
                Ok(PublicKey::new(KeyData::Ecdsa(key), ""))
            } else if algorithm == ED25519 {
                let key = Ed25519PublicKey::try_from(raw).map_err(|e| format!("not an Ed25519 public key: {e}"))?;
                Ok(PublicKey::new(KeyData::Ed25519(key), ""))
            } else {
                Err(format!("a public key of the algorithm {}, which podssh does not read", spki.algorithm.oid))
            }
        }
        Some(other) => Err(format!("a PEM block of {other}, not a public key")),
        None => Err("no PEM block: no line -----BEGIN PUBLIC KEY-----".into()),
    }
}

/// `-m` with a new key or `-p`: the private key in `format`, encrypted with
/// `passphrase` unless it is empty. `None` for an Ed25519 key, which OpenSSH
/// writes in its own format whatever `-m` says; and for RFC 4716, which is
/// OpenSSH's own format for a private key.
pub fn private_text(key: &PrivateKey, format: Format, passphrase: &str) -> Result<Option<Zeroizing<String>>, String> {
    let (label, der): (&str, Zeroizing<Vec<u8>>) = match (format, key.key_data()) {
        (Format::Rfc4716, _) | (_, KeypairData::Ed25519(_)) => return Ok(None),
        (Format::Pem, KeypairData::Rsa(_)) => ("RSA PRIVATE KEY", crate::rsa_key::pkcs1_der(key)?),
        (Format::Pem, KeypairData::Ecdsa(ec)) => ("EC PRIVATE KEY", Zeroizing::new(sec1(ec, true))),
        (Format::Pkcs8, KeypairData::Rsa(_)) => {
            let inner = crate::rsa_key::pkcs1_der(key)?;
            ("PRIVATE KEY", Zeroizing::new(pkcs8(seq(&[oid(RSA_ENCRYPTION), null()]), &inner)))
        }
        (Format::Pkcs8, KeypairData::Ecdsa(ec)) => {
            let inner = Zeroizing::new(sec1(ec, false));
            let curve = curve_of(&EcdsaPublicKey::from(ec));
            ("PRIVATE KEY", Zeroizing::new(pkcs8(seq(&[oid(EC_PUBLIC_KEY), oid(curve)]), &inner)))
        }
        _ => return Err(format!("a key of {} has no form of {}", key.algorithm(), format.name())),
    };
    if passphrase.is_empty() {
        return Ok(Some(Zeroizing::new(armour(label, &der))));
    }
    match format {
        Format::Pem => crate::key_file::encrypt_pem(label, &der, passphrase).map(Some),
        _ => encrypt_pkcs8(&der, passphrase).map(|text| Some(Zeroizing::new(text))),
    }
}

/// SEC1's ECPrivateKey: version 1, the scalar, the curve (left out inside
/// PKCS#8, whose algorithm names it), and the public point.
fn sec1(ec: &EcdsaKeypair, with_curve: bool) -> Vec<u8> {
    let public = EcdsaPublicKey::from(ec);
    let scalar = match ec {
        EcdsaKeypair::NistP256 { private, .. } => private.as_slice().to_vec(),
        EcdsaKeypair::NistP384 { private, .. } => private.as_slice().to_vec(),
        EcdsaKeypair::NistP521 { private, .. } => private.as_slice().to_vec(),
    };
    let scalar = Zeroizing::new(scalar);
    let mut parts = vec![integer(&[1]), tlv(0x04, &scalar)];
    if with_curve {
        parts.push(tlv(0xa0, &oid(curve_of(&public))));
    }
    parts.push(tlv(0xa1, &bits(public.as_sec1_bytes())));
    seq(&parts)
}

/// PKCS#8's PrivateKeyInfo: version 0, the algorithm, the key.
fn pkcs8(algorithm: Vec<u8>, key: &[u8]) -> Vec<u8> {
    seq(&[integer(&[0]), algorithm, tlv(0x04, key)])
}

/// An encrypted key of PKCS#8: PBES2 with PBKDF2 (HMAC-SHA256, 100 000
/// rounds) and AES-256-CBC, which OpenSSL, OpenSSH and podssh read.
fn encrypt_pkcs8(der: &[u8], passphrase: &str) -> Result<String, String> {
    use pkcs8::der::Encode;
    let salt: [u8; 16] = rand::random();
    let kdf = pkcs5::pbes2::Pbkdf2Params::hmac_sha256(100_000, &salt).map_err(|e| e.to_string())?;
    let params = pkcs5::pbes2::Parameters {
        kdf: kdf.into(),
        encryption: pkcs5::pbes2::EncryptionScheme::Aes256Cbc { iv: rand::random() },
    };
    let encrypted = Zeroizing::new(params.encrypt(passphrase, der).map_err(|e| e.to_string())?);
    let info = pkcs8::EncryptedPrivateKeyInfoRef {
        encryption_algorithm: pkcs5::EncryptionScheme::Pbes2(params),
        encrypted_data: pkcs8::der::asn1::OctetStringRef::new(&encrypted).map_err(|e| e.to_string())?,
    };
    Ok(armour("ENCRYPTED PRIVATE KEY", &info.to_der().map_err(|e| e.to_string())?))
}

/// `der` as a PEM block of `label`, its base64 in lines of 64.
pub(crate) fn armour(label: &str, der: &[u8]) -> String {
    let body = Zeroizing::new(STANDARD.encode(der));
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

// A writer of DER, enough for the structures above.

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(contents);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// A positive INTEGER: its leading zeros dropped, and one put back when the
/// first bit would read as a sign.
fn integer(bytes: &[u8]) -> Vec<u8> {
    let mut digits: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    if digits.first().is_none_or(|b| b & 0x80 != 0) {
        digits.insert(0, 0);
    }
    tlv(0x02, &digits)
}

fn oid(contents: &[u8]) -> Vec<u8> {
    tlv(0x06, contents)
}

fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// A BIT STRING with no unused bits.
fn bits(bytes: &[u8]) -> Vec<u8> {
    let mut contents = vec![0];
    contents.extend_from_slice(bytes);
    tlv(0x03, &contents)
}

#[cfg(test)]
#[path = "convert_tests.rs"]
mod tests;
