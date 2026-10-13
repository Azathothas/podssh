//! The formats on each side of a security key: what a FIDO2 device answers
//! (the authenticator data of WebAuthn, a COSE key, an X9.62 signature of
//! ECDSA), and what OpenSSH keeps and sends (PROTOCOL.u2f): the key file of
//! an `sk-` key, which holds the device's key handle and no private key, and
//! a signature, which carries the device's flags and counter after it.

use russh::keys::ssh_key::private::{
    KeypairData, SkEcdsaSha2NistP256 as SkEcdsaKeypair, SkEd25519 as SkEd25519Keypair,
};
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{PrivateKey, PublicKey};
use sha2::{Digest, Sha256};

use super::cbor::{self, Value};
use super::{Alg, Enrolled, Signed, USER_PRESENCE_REQUIRED, USER_VERIFICATION_REQUIRED};

/// The flags of the authenticator data: the device made a key (AT), and
/// extensions follow (ED).
const ATTESTED: u8 = 0x40;
const EXTENSIONS: u8 = 0x80;

/// The longest key handle that a key file of OpenSSH's holds.
const MAX_KEY_HANDLE: usize = 255;

/// The parts of an `sk-` private key that a signature needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkKey {
    pub alg: Alg,
    /// The FIDO application, `ssh:` by default: the device's relying party.
    pub application: String,
    /// OpenSSH's flags of the key: a touch, a PIN.
    pub flags: u8,
    pub key_handle: Vec<u8>,
}

impl SkKey {
    /// The security key that `key` names, if it is one (and not encrypted).
    pub fn of(key: &KeypairData) -> Option<SkKey> {
        match key {
            KeypairData::SkEd25519(sk) => Some(SkKey {
                alg: Alg::Ed25519,
                application: sk.public().application().to_string(),
                flags: sk.flags(),
                key_handle: sk.key_handle().to_vec(),
            }),
            KeypairData::SkEcdsaSha2NistP256(sk) => Some(SkKey {
                alg: Alg::EcdsaP256,
                application: sk.public().application().to_string(),
                flags: sk.flags(),
                key_handle: sk.key_handle().to_vec(),
            }),
            _ => None,
        }
    }

    /// Whether each signature needs a touch.
    pub fn touch(&self) -> bool {
        self.flags & USER_PRESENCE_REQUIRED != 0
    }

    /// Whether each signature needs the device's PIN.
    pub fn verify(&self) -> bool {
        self.flags & USER_VERIFICATION_REQUIRED != 0
    }
}

/// Whether `key` is a security key: its algorithm, whether or not the file
/// is encrypted.
pub fn is_sk(key: &PublicKey) -> bool {
    matches!(key.key_data(), KeyData::SkEd25519(_) | KeyData::SkEcdsaSha2NistP256(_))
}

/// The public key of a security key in SSH's wire format: its name, the
/// curve of ECDSA, the point, and the application.
pub fn public_blob(alg: Alg, point: &[u8], application: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(point.len() + application.len() + 64);
    put_string(&mut out, alg.ssh_name().as_bytes());
    if alg == Alg::EcdsaP256 {
        put_string(&mut out, b"nistp256");
    }
    put_string(&mut out, point);
    put_string(&mut out, application.as_bytes());
    out
}

/// The key file of a new key in a device: OpenSSH's private key of the type,
/// which holds the public key, the application, the flags and the key
/// handle.
pub fn private_key(
    alg: Alg,
    enrolled: &Enrolled,
    application: &str,
    flags: u8,
    comment: &str,
) -> Result<PrivateKey, String> {
    if enrolled.key_handle.len() > MAX_KEY_HANDLE {
        return Err(format!(
            "the device gave a key handle of {} bytes; a key file of OpenSSH holds {MAX_KEY_HANDLE} at most",
            enrolled.key_handle.len()
        ));
    }
    let blob = public_blob(alg, &enrolled.public, application);
    let public = PublicKey::from_bytes(&blob).map_err(|e| format!("the device's public key: {e}"))?;
    let bad = |e: russh::keys::ssh_key::Error| format!("the key file: {e}");
    let keypair = match public.key_data() {
        KeyData::SkEd25519(sk) => {
            KeypairData::SkEd25519(SkEd25519Keypair::new(sk.clone(), flags, enrolled.key_handle.clone()).map_err(bad)?)
        }
        KeyData::SkEcdsaSha2NistP256(sk) => KeypairData::SkEcdsaSha2NistP256(
            SkEcdsaKeypair::new(sk.clone(), flags, enrolled.key_handle.clone()).map_err(bad)?,
        ),
        _ => return Err("the device's public key is not one of a security key".into()),
    };
    PrivateKey::new(keypair, comment).map_err(bad)
}

/// A device's signature as SSH carries it: the name, the signature (Ed25519's
/// 64 bytes, or ECDSA's r and s as two mpints), then the device's flags and
/// counter, outside the string, as PROTOCOL.u2f gives it.
pub fn signature_blob(alg: Alg, signed: &Signed) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(signed.signature.len() + 64);
    put_string(&mut out, alg.ssh_name().as_bytes());
    match alg {
        Alg::Ed25519 => {
            if signed.signature.len() != 64 {
                return Err(format!("the device's Ed25519 signature has {} bytes, not 64", signed.signature.len()));
            }
            put_string(&mut out, &signed.signature);
        }
        Alg::EcdsaP256 => {
            let (r, s) = der_ecdsa(&signed.signature)?;
            let mut inner = Vec::with_capacity(72);
            put_mpint(&mut inner, &r);
            put_mpint(&mut inner, &s);
            put_string(&mut out, &inner);
        }
    }
    out.push(signed.flags);
    out.extend_from_slice(&signed.counter.to_be_bytes());
    Ok(out)
}

/// What a device signed or made: the authenticator data of WebAuthn.
#[derive(Debug)]
pub(crate) struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub counter: u32,
    /// The new key's id (the key handle) and its COSE key, when the device
    /// made one.
    pub credential: Option<(Vec<u8>, Value)>,
    /// Extensions after the rest, which an SSH signature cannot carry.
    pub extensions: bool,
}

/// Read the authenticator data: the hash of the relying party, the flags,
/// the counter, and the attested key when the flags announce one.
pub(crate) fn auth_data(bytes: &[u8]) -> Result<AuthData, String> {
    let short = || "the device's authenticator data is short".to_string();
    let (rp_id_hash, rest) = bytes.split_first_chunk::<32>().ok_or_else(short)?;
    let (&flags, rest) = rest.split_first().ok_or_else(short)?;
    let (counter, mut rest) = rest.split_first_chunk::<4>().ok_or_else(short)?;
    let credential = if flags & ATTESTED != 0 {
        // The AAGUID of the model, then the id's length and the id.
        let (_aaguid, after) = rest.split_first_chunk::<16>().ok_or_else(short)?;
        let (length, after) = after.split_first_chunk::<2>().ok_or_else(short)?;
        let length = usize::from(u16::from_be_bytes(*length));
        if after.len() < length {
            return Err(short());
        }
        let (id, after) = after.split_at(length);
        let (key, after) = cbor::decode(after).map_err(|e| format!("the device's new key: {e}"))?;
        rest = after;
        Some((id.to_vec(), key))
    } else {
        None
    };
    Ok(AuthData {
        rp_id_hash: *rp_id_hash,
        flags,
        counter: u32::from_be_bytes(*counter),
        credential,
        extensions: flags & EXTENSIONS != 0 || !rest.is_empty(),
    })
}

/// The new key of a device's answer to the request to make one: its public
/// key and its handle. `credential_id` is the id that the system gave
/// beside the data (Windows), which must be the same.
pub(crate) fn enrolled(
    alg: Alg,
    application: &str,
    data: &[u8],
    credential_id: Option<&[u8]>,
) -> Result<Enrolled, String> {
    let data = auth_data(data)?;
    if data.rp_id_hash != sha256(application.as_bytes()) {
        return Err(format!("the device made a key for another application than {application}"));
    }
    let (key_handle, key) = data.credential.ok_or("the device's answer holds no new key")?;
    if credential_id.is_some_and(|id| id != key_handle.as_slice()) {
        return Err("the system and the device name two different keys".into());
    }
    let public = cose_point(alg, &key)?;
    Ok(Enrolled { public, key_handle })
}

/// A device's answer to a request to sign, for `application`: its flags and
/// counter, read from its authenticator data, and its signature.
pub(crate) fn signed(application: &str, data: &[u8], signature: Vec<u8>) -> Result<Signed, String> {
    let data = auth_data(data)?;
    if data.rp_id_hash != sha256(application.as_bytes()) {
        return Err(format!("the device signed for another application than {application}"));
    }
    if data.extensions || data.credential.is_some() {
        return Err("the device's signature carries extensions, which an SSH signature cannot carry".into());
    }
    Ok(Signed { flags: data.flags, counter: data.counter, signature })
}

/// COSE's labels of a key (RFC 9052, RFC 9053): the type, the algorithm, the
/// curve, and the coordinates.
const KTY: i64 = 1;
const ALG: i64 = 3;
const CRV: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;

/// The public key of a COSE key, as SSH holds it: Ed25519's 32 bytes, or a
/// P-256 point uncompressed (0x04, x and y).
pub(crate) fn cose_point(alg: Alg, key: &Value) -> Result<Vec<u8>, String> {
    let int = |label| key.at(label).and_then(Value::as_int);
    let coordinate = |label| key.at(label).and_then(Value::as_bytes).filter(|c| c.len() == 32);
    if int(ALG).is_some_and(|a| a != alg.cose()) {
        return Err(format!("the device made a key of the COSE algorithm {:?}, not {}", int(ALG), alg.cose()));
    }
    match alg {
        // OKP, Ed25519.
        Alg::Ed25519 if int(KTY) == Some(1) && int(CRV) == Some(6) => {
            coordinate(X).map(<[u8]>::to_vec).ok_or_else(|| "the device's Ed25519 key has no x of 32 bytes".into())
        }
        // EC2, P-256.
        Alg::EcdsaP256 if int(KTY) == Some(2) && int(CRV) == Some(1) => {
            let (Some(x), Some(y)) = (coordinate(X), coordinate(Y)) else {
                return Err("the device's P-256 key has no x and y of 32 bytes".into());
            };
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            Ok(point)
        }
        _ => Err(format!("the device made a key of the COSE type {:?} and curve {:?}", int(KTY), int(CRV))),
    }
}

/// The r and s of an ECDSA signature in X9.62's DER, each without its
/// leading zeros.
pub(crate) fn der_ecdsa(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let bad = || "the device's ECDSA signature is not one of DER".to_string();
    let (body, rest) = der_element(der, 0x30).ok_or_else(bad)?;
    let (r, after) = der_element(body, 0x02).ok_or_else(bad)?;
    let (s, after) = der_element(after, 0x02).ok_or_else(bad)?;
    if !rest.is_empty() || !after.is_empty() {
        return Err(bad());
    }
    let strip = |n: &[u8]| n.iter().position(|b| *b != 0).map_or_else(Vec::new, |i| n[i..].to_vec());
    let (r, s) = (strip(r), strip(s));
    if r.len() > 32 || s.len() > 32 || r.is_empty() || s.is_empty() {
        return Err("the device's ECDSA signature is not one of P-256".into());
    }
    Ok((r, s))
}

/// The contents of the DER element of `tag` at the start of `input`, and
/// what follows it; a length of one byte, or of 0x81 and one byte.
fn der_element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&length, rest) = rest.split_first()?;
            (usize::from(length), rest)
        }
        _ => return None,
    };
    (found == tag && rest.len() >= length).then(|| rest.split_at(length))
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// An mpint of SSH (RFC 4251) of a positive number with no leading zeros:
/// a byte of zero first when the high bit is set.
fn put_mpint(out: &mut Vec<u8>, n: &[u8]) {
    let pad = n.first().is_some_and(|b| b & 0x80 != 0);
    out.extend_from_slice(&((n.len() + usize::from(pad)) as u32).to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(n);
}

#[cfg(test)]
#[path = "format_tests.rs"]
mod tests;
