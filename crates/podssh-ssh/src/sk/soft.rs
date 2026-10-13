//! A key of a security key in software, for the tests: it signs as a FIDO2
//! device signs (the authenticator data, then the hash of the client's
//! data), through aws-lc-rs, and ssh-key, which podssh's code does not use
//! for this, checks what podssh makes of its answers.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use super::cbor::Value;
use super::format::sha256;
use super::Alg;

pub(crate) enum SoftKey {
    Ed25519(Ed25519KeyPair),
    Ecdsa(EcdsaKeyPair),
}

impl SoftKey {
    pub fn new(alg: Alg) -> SoftKey {
        match alg {
            Alg::Ed25519 => SoftKey::Ed25519(Ed25519KeyPair::generate().expect("an Ed25519 key")),
            Alg::EcdsaP256 => {
                SoftKey::Ecdsa(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("a P-256 key"))
            }
        }
    }

    /// The public key as SSH holds it: 32 bytes, or a point of 65.
    pub fn point(&self) -> Vec<u8> {
        match self {
            SoftKey::Ed25519(pair) => pair.public_key().as_ref().to_vec(),
            SoftKey::Ecdsa(pair) => pair.public_key().as_ref().to_vec(),
        }
    }

    /// The public key as a device gives it: a COSE key.
    pub fn cose(&self) -> Value {
        let point = self.point();
        match self {
            SoftKey::Ed25519(_) => Value::Map(vec![
                (Value::Int(1), Value::Int(1)),
                (Value::Int(3), Value::Int(-8)),
                (Value::Int(-1), Value::Int(6)),
                (Value::Int(-2), Value::Bytes(point)),
            ]),
            SoftKey::Ecdsa(_) => Value::Map(vec![
                (Value::Int(1), Value::Int(2)),
                (Value::Int(3), Value::Int(-7)),
                (Value::Int(-1), Value::Int(1)),
                (Value::Int(-2), Value::Bytes(point[1..33].to_vec())),
                (Value::Int(-3), Value::Bytes(point[33..].to_vec())),
            ]),
        }
    }

    /// The signature of `message`: Ed25519's 64 bytes, or ECDSA's DER over
    /// its SHA-256, as a device signs.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SoftKey::Ed25519(pair) => pair.sign(message).as_ref().to_vec(),
            SoftKey::Ecdsa(pair) => {
                pair.sign(&SystemRandom::new(), message).expect("an ECDSA signature").as_ref().to_vec()
            }
        }
    }

    /// A device's answer to a request to sign `data` for `application`:
    /// its authenticator data and its signature.
    pub fn assert(&self, application: &str, flags: u8, counter: u32, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let auth = auth_data(application, flags, counter);
        let mut signed = auth.clone();
        signed.extend_from_slice(&sha256(data));
        (auth, self.sign(&signed))
    }
}

/// Authenticator data with no new key: the hash of the application, the
/// flags and the counter.
pub(crate) fn auth_data(application: &str, flags: u8, counter: u32) -> Vec<u8> {
    let mut out = sha256(application.as_bytes()).to_vec();
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    out
}

/// Authenticator data with a new key: the flag AT, an AAGUID of zeros, the
/// key's id and its COSE key.
pub(crate) fn attested(application: &str, flags: u8, id: &[u8], cose: &Value) -> Vec<u8> {
    let mut out = auth_data(application, flags | 0x40, 0);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&(id.len() as u16).to_be_bytes());
    out.extend_from_slice(id);
    cose.encode(&mut out);
    out
}

/// The bytes of a text of hex digits.
pub(crate) fn unhex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect()
}
