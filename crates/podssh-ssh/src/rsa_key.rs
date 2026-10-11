//! RSA user keys through aws-lc-rs, whose RSA is constant-time (T-257). The
//! `rsa` crate, which russh and ssh-key use for RSA, is not (the Marvin
//! attack, RUSTSEC-2023-0071), so podssh signs no login and makes no key
//! with it: an OpenSSH RSA key is read once into an aws-lc-rs key pair,
//! which signs each login as an agent would, and `podssh keygen -t rsa`
//! makes its key in aws-lc-rs. aws-lc-rs takes keys of 2048 to 8192 bits.

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::{RsaEncoding, RSA_PKCS1_SHA256, RSA_PKCS1_SHA512};
use crypto_bigint::{BoxedUint, NonZero};
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::private::{KeypairData, RsaKeypair, RsaPrivateKey};
use russh::keys::ssh_key::public::RsaPublicKey;
use russh::keys::ssh_key::Mpint;
use std::sync::Arc;

use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use zeroize::Zeroizing;

/// `key` for russh to sign with, as russh signs each key that is not RSA
/// (Ed25519 and ECDSA): the one way to russh's own signing in podssh. An RSA
/// key comes back, for [`RsaSigner`].
pub(crate) fn russh_key(key: PrivateKey, hash: Option<HashAlg>) -> Result<PrivateKeyWithHashAlg, Box<PrivateKey>> {
    if key.algorithm().is_rsa() {
        return Err(Box::new(key));
    }
    Ok(PrivateKeyWithHashAlg::new(Arc::new(key), hash))
}

/// Whether an agent's request adds an RSA key (`SSH_AGENTC_ADD_IDENTITY`,
/// 17, or with constraints, 25). russh's agent server would sign with it
/// through the `rsa` crate, so `podssh agent` refuses it.
pub(crate) fn adds_rsa_key(request: &[u8]) -> bool {
    let Some((&(17 | 25), rest)) = request.split_first() else { return false };
    let Some((len, rest)) = rest.split_first_chunk::<4>() else { return false };
    let len = u32::from_be_bytes(*len) as usize;
    matches!(rest.get(..len), Some(b"ssh-rsa" | b"ssh-rsa-cert-v01@openssh.com"))
}

/// The RSA key of a key file in aws-lc-rs: it signs, and nothing else reads
/// it.
pub(crate) struct RsaSigner {
    pair: KeyPair,
}

impl RsaSigner {
    /// `key`, an RSA key, as an aws-lc-rs key pair.
    pub(crate) fn of(key: &PrivateKey) -> Result<RsaSigner, String> {
        let KeypairData::Rsa(rsa) = key.key_data() else { return Err("it is not an RSA key".into()) };
        let bits = rsa.key_size();
        if !(2048..=8192).contains(&bits) {
            return Err(format!("it is an RSA key of {bits} bits; podssh signs with RSA keys of 2048 to 8192 bits"));
        }
        let der = pkcs1(rsa)?;
        let pair = KeyPair::from_der(&der).map_err(|e| format!("aws-lc-rs refused the RSA key: {e}"))?;
        Ok(RsaSigner { pair })
    }
}

/// Why an RSA key did not sign.
#[derive(Debug)]
pub(crate) enum SignError {
    /// The session ended before the signature went.
    Send,
    /// The server takes RSA keys only with SHA-1 (`ssh-rsa`), which podssh
    /// does not sign.
    Sha1,
    /// aws-lc-rs did not sign.
    Failed,
}

impl From<russh::SendError> for SignError {
    fn from(_: russh::SendError) -> Self {
        SignError::Send
    }
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignError::Send => "the session ended",
            SignError::Sha1 => "the server takes only ssh-rsa (SHA-1) signatures, which podssh does not make",
            SignError::Failed => "aws-lc-rs did not sign",
        })
    }
}

impl russh::Signer for RsaSigner {
    type Error = SignError;

    /// `to_sign`, then its signature as an agent gives it: the length, the
    /// name of the algorithm, and the signature.
    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, SignError> {
        let (encoding, name): (&'static dyn RsaEncoding, &str) = match hash_alg {
            Some(HashAlg::Sha256) => (&RSA_PKCS1_SHA256, "rsa-sha2-256"),
            Some(HashAlg::Sha512) => (&RSA_PKCS1_SHA512, "rsa-sha2-512"),
            _ => return Err(SignError::Sha1),
        };
        let mut signature = vec![0u8; self.pair.public_modulus_len()];
        self.pair.sign(encoding, &SystemRandom::new(), &to_sign, &mut signature).map_err(|_| SignError::Failed)?;
        let blob = 4 + name.len() + 4 + signature.len();
        to_sign.extend_from_slice(&(blob as u32).to_be_bytes());
        put_string(&mut to_sign, name.as_bytes());
        put_string(&mut to_sign, &signature);
        Ok(to_sign)
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A new RSA key of `bits`, made by aws-lc-rs: 2048, 3072, 4096 or 8192.
pub fn generate(bits: usize) -> Result<RsaKeypair, String> {
    let size = match bits {
        2048 => KeySize::Rsa2048,
        3072 => KeySize::Rsa3072,
        4096 => KeySize::Rsa4096,
        8192 => KeySize::Rsa8192,
        other => return Err(format!("aws-lc-rs makes RSA keys of 2048, 3072, 4096 or 8192 bits, not {other}")),
    };
    let pair = KeyPair::generate(size).map_err(|_| "aws-lc-rs could not make the key".to_string())?;
    let pkcs8: Pkcs8V1Der<'static> = pair.as_der().map_err(|_| "aws-lc-rs could not encode the key".to_string())?;
    from_pkcs8(pkcs8.as_ref())
}

/// The RSA key of a PKCS#8 document (RFC 5208), as ssh-key holds one.
fn from_pkcs8(der: &[u8]) -> Result<RsaKeypair, String> {
    let bad = |what: &str| format!("the key that aws-lc-rs made could not be read: {what}");
    let [n, e, d, p, q, _, _, iqmp] = pkcs8_integers(der).map_err(|e| bad(&e))?;
    let public = RsaPublicKey::new(e, n).map_err(|e| bad(&e.to_string()))?;
    let private = RsaPrivateKey::new(d, iqmp, p, q).map_err(|e| bad(&e.to_string()))?;
    RsaKeypair::new(public, private).map_err(|e| bad(&e.to_string()))
}

/// The integers of the RSAPrivateKey in a PKCS#8 document, after its
/// version, which is 0 for two primes: n, e, d, p, q, d mod (p - 1),
/// d mod (q - 1) and (inverse of q) mod p.
fn pkcs8_integers(der: &[u8]) -> Result<[Mpint; 8], String> {
    let (info, _) = take(der, SEQUENCE)?;
    let (_version, rest) = take(info, INTEGER)?;
    let (_algorithm, rest) = take(rest, SEQUENCE)?;
    let (private, _) = take(rest, OCTET_STRING)?;
    let (fields, _) = take(private, SEQUENCE)?;
    let (version, mut fields) = take(fields, INTEGER)?;
    if version != [0] {
        return Err("a key of more than two primes".into());
    }
    let mut parts = Vec::with_capacity(8);
    for _ in 0..8 {
        let (value, rest) = take(fields, INTEGER)?;
        parts.push(Mpint::from_bytes(value).map_err(|e| e.to_string())?);
        fields = rest;
    }
    <[Mpint; 8]>::try_from(parts).map_err(|_| "eight integers".to_string())
}

const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const SEQUENCE: u8 = 0x30;

/// PKCS#1's RSAPrivateKey of `key` (RFC 8017, appendix A.1.2), in DER. An
/// mpint of SSH is the contents of a DER INTEGER: the same minimal two's
/// complement.
pub(crate) fn pkcs1(key: &RsaKeypair) -> Result<Zeroizing<Vec<u8>>, String> {
    let (public, private) = (key.public(), key.private());
    let dp = crt_exponent(private.d(), private.p())?;
    let dq = crt_exponent(private.d(), private.q())?;
    let version = Mpint::from_positive_bytes(&[]);
    let parts = [&version, public.n(), public.e(), private.d(), private.p(), private.q(), &dp, &dq, private.iqmp()];
    // Sized once, so that no copy of the key is left in a freed buffer.
    let size: usize = parts.iter().map(|m| m.as_bytes().len() + 6).sum();
    let mut body = Zeroizing::new(Vec::with_capacity(size));
    for part in parts {
        let bytes = part.as_bytes();
        put_der(&mut body, INTEGER, if bytes.is_empty() { &[0] } else { bytes });
    }
    let mut der = Zeroizing::new(Vec::with_capacity(body.len() + 6));
    put_der(&mut der, SEQUENCE, &body);
    Ok(der)
}

/// `d mod (prime - 1)`, in constant time.
fn crt_exponent(d: &Mpint, prime: &Mpint) -> Result<Mpint, String> {
    let bad = || "the RSA key has a negative part".to_string();
    let d = d.as_positive_bytes().ok_or_else(bad)?;
    let prime = prime.as_positive_bytes().ok_or_else(bad)?;
    let bits = (d.len().max(prime.len()) * 8) as u32;
    let wide = |bytes: &[u8]| BoxedUint::from_be_slice(bytes, bits).map(Zeroizing::new);
    let d = wide(d).map_err(|e| format!("the RSA key could not be read: {e}"))?;
    let prime = wide(prime).map_err(|e| format!("the RSA key could not be read: {e}"))?;
    let less = prime.wrapping_sub(BoxedUint::one_with_precision(bits));
    let modulus = NonZero::new(less).into_option().ok_or("the RSA key has a prime of 1")?;
    let exponent = Zeroizing::new(d.rem(&modulus));
    let bytes = Zeroizing::new(exponent.to_be_bytes());
    Ok(Mpint::from_positive_bytes(&bytes))
}

/// A DER element: its tag, its length and its contents.
fn put_der(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(contents);
}

/// The contents of the DER element at the start of `input`, which must have
/// `tag`, and what follows it.
fn take(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), String> {
    let Some((&found, rest)) = input.split_first() else { return Err("the input ended".into()) };
    if found != tag {
        return Err(format!("tag {found:#04x} where {tag:#04x} was due"));
    }
    let Some((&first, rest)) = rest.split_first() else { return Err("no length".into()) };
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return Err("a bad length".into());
        }
        let (digits, rest) = rest.split_at(count);
        (digits.iter().fold(0usize, |len, b| len << 8 | usize::from(*b)), rest)
    };
    if rest.len() < len {
        return Err("a length past the end".into());
    }
    Ok(rest.split_at(len))
}

#[cfg(test)]
#[path = "rsa_key_tests.rs"]
mod tests;
