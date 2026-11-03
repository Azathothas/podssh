//! The reader and the writer of an OpenSSH certificate of an Ed25519 key,
//! signed by an Ed25519 key, as OpenSSH's PROTOCOL.certkeys gives it: the
//! type, a nonce, the key, a serial, user or host, a key id, the
//! principals, a window, the critical options and the extensions, a field
//! reserved, the issuer's key, then the issuer's signature of each field
//! before it. Only this kind: the keys of podssh's ends are Ed25519 (T-087),
//! and so are the issuers that a node names. Pure Rust, with the crates of
//! `crate::identity`.

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::identity::{Identity, PublicKey};

/// The type of a certificate of an Ed25519 key.
pub const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";
/// The type of an Ed25519 key, and of its signature.
const KEY_TYPE: &str = "ssh-ed25519";
/// A user certificate, the one kind that is a grant.
pub const USER: u32 = 1;
/// A host certificate.
pub const HOST: u32 = 2;

/// A certificate, read: each field, and the bytes that its issuer signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    pub nonce: Vec<u8>,
    /// The key that the certificate is for: the grantee's.
    pub key: PublicKey,
    pub serial: u64,
    /// [`USER`] or [`HOST`].
    pub kind: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    /// Seconds since the epoch; 0 is "always".
    pub valid_after: u64,
    /// Seconds since the epoch; `u64::MAX` is "forever".
    pub valid_before: u64,
    /// Each critical option: its name and its data, as they came.
    pub critical: Vec<(String, Vec<u8>)>,
    pub extensions: Vec<(String, Vec<u8>)>,
    /// The key that signed it.
    pub issuer: PublicKey,
    signature: [u8; 64],
    /// Each field before the signature, as they came: what the issuer signed.
    signed: Vec<u8>,
}

impl Cert {
    /// The certificate in `text`: its first line that is no comment, `TYPE
    /// BASE64 [COMMENT]`, as `ssh-keygen -s` writes `KEY-cert.pub`.
    pub fn from_text(text: &str) -> Result<Cert, String> {
        let line =
            text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).ok_or("no certificate in it")?;
        let mut words = line.split_whitespace();
        let kind = words.next().unwrap_or_default();
        if kind != CERT_TYPE {
            return Err(format!("{kind:?} is not {CERT_TYPE}, the certificate of an Ed25519 key"));
        }
        let encoded = words.next().unwrap_or_default();
        let blob =
            base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|_| "it is not base64".to_string())?;
        Cert::from_blob(&blob)
    }

    /// The certificate in its wire form: each field checked for its shape,
    /// and nothing after the signature. The signature is checked by
    /// [`Cert::signed_by_issuer`].
    pub fn from_blob(blob: &[u8]) -> Result<Cert, String> {
        if blob.len() > super::MAX_GRANT {
            return Err(format!("a certificate of {} bytes, more than a grant can be", blob.len()));
        }
        let mut r = Reader(blob);
        if r.bytes()? != CERT_TYPE.as_bytes() {
            return Err(format!("not {CERT_TYPE}, the certificate of an Ed25519 key"));
        }
        let nonce = r.bytes()?.to_vec();
        let key = PublicKey(key32(r.bytes()?)?);
        let serial = r.u64()?;
        let kind = r.u32()?;
        let key_id = String::from_utf8_lossy(r.bytes()?).into_owned();
        let principals = strings(r.bytes()?)?;
        let valid_after = r.u64()?;
        let valid_before = r.u64()?;
        let critical = options(r.bytes()?)?;
        let extensions = options(r.bytes()?)?;
        let _reserved = r.bytes()?;
        let issuer = PublicKey(issuer_key(r.bytes()?)?);
        let signed = blob[..blob.len() - r.0.len()].to_vec();
        let signature = signature_of(r.bytes()?)?;
        if !r.0.is_empty() {
            return Err("bytes after its signature".into());
        }
        Ok(Cert {
            nonce,
            key,
            serial,
            kind,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical,
            extensions,
            issuer,
            signature,
            signed,
        })
    }

    /// Whether the issuer's key signed each field, by the strict rules of
    /// Ed25519 that refuse a weak key and a malleable signature.
    pub fn signed_by_issuer(&self) -> bool {
        self.issuer.verifies(&self.signed, &self.signature)
    }

    /// The SHA-256 of what the issuer signed, the nonce among it: the name of
    /// this one grant, which two certificates of one serial do not share.
    pub fn digest(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(&self.signed));
        out
    }

    /// The wire form.
    pub fn blob(&self) -> Vec<u8> {
        let mut out = self.signed.clone();
        let mut signature = Vec::with_capacity(83);
        put(&mut signature, KEY_TYPE.as_bytes());
        put(&mut signature, &self.signature);
        put(&mut out, &signature);
        out
    }

    /// The line of `KEY-cert.pub`, with `comment` after it when one is given.
    pub fn to_line(&self, comment: &str) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(self.blob());
        match comment.trim() {
            "" => format!("{CERT_TYPE} {encoded}"),
            comment => format!("{CERT_TYPE} {encoded} {comment}"),
        }
    }
}

/// A new grant's fields, which [`Mint::sign`] signs with an issuer's key:
/// the order and the form of `ssh-keygen -s`, so that the same fields and
/// nonce give the same bytes.
#[derive(Debug, Clone)]
pub struct Mint<'a> {
    pub nonce: [u8; 32],
    pub key: PublicKey,
    pub serial: u64,
    pub key_id: &'a str,
    pub principals: &'a [String],
    pub valid_after: u64,
    pub valid_before: u64,
    pub critical: &'a [(&'a str, &'a [u8])],
}

impl Mint<'_> {
    /// The user certificate of these fields, signed by `issuer`, with no
    /// extension, as `ssh-keygen -O clear` makes it.
    pub fn sign(&self, issuer: &Identity) -> Cert {
        let mut signed = Vec::with_capacity(512);
        put(&mut signed, CERT_TYPE.as_bytes());
        put(&mut signed, &self.nonce);
        put(&mut signed, &self.key.0);
        signed.extend_from_slice(&self.serial.to_be_bytes());
        signed.extend_from_slice(&USER.to_be_bytes());
        put(&mut signed, self.key_id.as_bytes());
        let mut list = Vec::new();
        for principal in self.principals {
            put(&mut list, principal.as_bytes());
        }
        put(&mut signed, &list);
        signed.extend_from_slice(&self.valid_after.to_be_bytes());
        signed.extend_from_slice(&self.valid_before.to_be_bytes());
        // OpenSSH writes the options in the order of their names.
        let mut critical: Vec<(&str, &[u8])> = self.critical.to_vec();
        critical.sort_by(|a, b| a.0.cmp(b.0));
        let mut options = Vec::new();
        for (name, data) in &critical {
            put(&mut options, name.as_bytes());
            put(&mut options, data);
        }
        put(&mut signed, &options);
        // No extension, and the field reserved, empty.
        put(&mut signed, &[]);
        put(&mut signed, &[]);
        put(&mut signed, &key_blob(&issuer.public()));
        let signature = issuer.sign(&signed);
        Cert {
            nonce: self.nonce.to_vec(),
            key: self.key,
            serial: self.serial,
            kind: USER,
            key_id: self.key_id.to_string(),
            principals: self.principals.to_vec(),
            valid_after: self.valid_after,
            valid_before: self.valid_before,
            critical: critical.iter().map(|(name, data)| (name.to_string(), data.to_vec())).collect(),
            extensions: Vec::new(),
            issuer: issuer.public(),
            signature,
            signed,
        }
    }
}

/// The key as OpenSSH writes a public key: `ssh-ed25519 BASE64`, the line
/// that `ssh-keygen -s` signs.
pub fn openssh_public(key: &PublicKey) -> String {
    format!("{KEY_TYPE} {}", base64::engine::general_purpose::STANDARD.encode(key_blob(key)))
}

/// A key as a person gives it: OpenSSH's line `ssh-ed25519 BASE64 [COMMENT]`,
/// or the key as [`PublicKey::parse`] reads it. A fingerprint names a key
/// but is none, so it is refused here.
pub fn parse_public(text: &str) -> Option<PublicKey> {
    let mut words = text.split_whitespace();
    let first = words.next()?;
    if first != KEY_TYPE {
        return PublicKey::parse(first);
    }
    let blob = base64::engine::general_purpose::STANDARD.decode(words.next()?).ok()?;
    let mut r = Reader(&blob);
    if r.bytes().ok()? != KEY_TYPE.as_bytes() {
        return None;
    }
    let key = key32(r.bytes().ok()?).ok()?;
    r.0.is_empty().then_some(PublicKey(key))
}

/// The SSH encoding of an Ed25519 key: its type, then its 32 bytes.
fn key_blob(key: &PublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(51);
    put(&mut out, KEY_TYPE.as_bytes());
    put(&mut out, &key.0);
    out
}

/// `bytes` after its length, in four bytes.
fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The fields of the wire, one after another.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let data: &'a [u8] = self.0;
        let (taken, rest) = data.split_at_checked(n).ok_or_else(|| "the certificate ends too soon".to_string())?;
        self.0 = rest;
        Ok(taken)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| "a number cut short".to_string())?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| "a number cut short".to_string())?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// A string of the wire: its length, then its bytes.
    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

fn key32(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes.try_into().map_err(|_| format!("a key of {} bytes, not Ed25519's 32", bytes.len()))
}

/// The principals: strings of UTF-8, as a grant names a node by one.
fn strings(blob: &[u8]) -> Result<Vec<String>, String> {
    let mut r = Reader(blob);
    let mut out = Vec::new();
    while !r.0.is_empty() {
        let word = std::str::from_utf8(r.bytes()?).map_err(|_| "a principal that is not UTF-8".to_string())?;
        out.push(word.to_string());
    }
    Ok(out)
}

/// The options: each a name and its data, each name once.
fn options(blob: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut r = Reader(blob);
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    while !r.0.is_empty() {
        let name = std::str::from_utf8(r.bytes()?).map_err(|_| "an option whose name is not UTF-8".to_string())?;
        let data = r.bytes()?.to_vec();
        if out.iter().any(|(seen, _)| seen == name) {
            return Err(format!("the option {name} twice"));
        }
        out.push((name.to_string(), data));
    }
    Ok(out)
}

/// The issuer's key: an Ed25519 key, and nothing after it.
fn issuer_key(blob: &[u8]) -> Result<[u8; 32], String> {
    let mut r = Reader(blob);
    if r.bytes()? != KEY_TYPE.as_bytes() {
        return Err("its issuer's key is not an Ed25519 key".into());
    }
    let key = key32(r.bytes()?)?;
    if !r.0.is_empty() {
        return Err("bytes after its issuer's key".into());
    }
    Ok(key)
}

/// The issuer's signature: `ssh-ed25519`, then its 64 bytes.
fn signature_of(blob: &[u8]) -> Result<[u8; 64], String> {
    let mut r = Reader(blob);
    if r.bytes()? != KEY_TYPE.as_bytes() {
        return Err("its signature is not ssh-ed25519".into());
    }
    let signature: [u8; 64] =
        r.bytes()?.try_into().map_err(|_| "a signature that is not Ed25519's 64 bytes".to_string())?;
    if !r.0.is_empty() {
        return Err("bytes after its signature".into());
    }
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minted(nonce: u8) -> Cert {
        let issuer = Identity::from_seed(&[0x22; 32]);
        let principals = vec!["node:SHA256:x".to_string()];
        Mint {
            nonce: [nonce; 32],
            key: Identity::from_seed(&[0x11; 32]).public(),
            serial: 7,
            key_id: "a test",
            principals: &principals,
            valid_after: 10,
            valid_before: 20,
            critical: &[(super::super::ONCE, &b""[..]), ("b@example.com", &b"x"[..])],
        }
        .sign(&issuer)
    }

    #[test]
    fn a_minted_certificate_reads_back_whole_and_verifies() {
        let cert = minted(1);
        let read = Cert::from_text(&cert.to_line("lab")).unwrap();
        assert_eq!(read, cert);
        assert!(read.signed_by_issuer());
        let names: Vec<&str> = read.critical.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["b@example.com", "once@podssh"], "in the order of their names, as OpenSSH writes them");
        assert_ne!(minted(2).digest(), cert.digest(), "another nonce is another grant");
    }

    #[test]
    fn a_changed_byte_fails_the_signature_and_a_cut_one_the_form() {
        let blob = minted(1).blob();
        // The serial's last byte, inside what the issuer signed.
        let at = 4 + CERT_TYPE.len() + 4 + 32 + 4 + 32 + 7;
        let mut changed = blob.clone();
        changed[at] ^= 1;
        let read = Cert::from_blob(&changed).unwrap();
        assert_eq!(read.serial, 7 ^ 1);
        assert!(!read.signed_by_issuer(), "a changed serial");
        assert!(Cert::from_blob(&blob[..blob.len() - 1]).is_err(), "a cut signature");
        let mut longer = blob.clone();
        longer.push(0);
        assert!(Cert::from_blob(&longer).is_err(), "a byte after the signature");
        assert!(Cert::from_text("ssh-ed25519 AAAA").is_err(), "a key is no certificate");
    }

    #[test]
    fn a_public_key_reads_in_openssh_s_form_and_in_podssh_s() {
        let key = Identity::from_seed(&[0x11; 32]).public();
        assert_eq!(parse_public(&format!("{} a comment", openssh_public(&key))), Some(key));
        assert_eq!(parse_public(&key.hex()), Some(key));
        assert_eq!(parse_public(&key.fingerprint()), None, "a fingerprint names a key, but is none");
        // The test vector of the key of seed 0x11, as OpenSSL derives it.
        assert_eq!(key.hex(), "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737");
    }
}
