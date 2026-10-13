//! SSH signatures made with a certificate, and the `cert-authority` lines of
//! an allowed-signers file that allow them (T-289), as the `ssh-keygen -Y` of
//! OpenSSH reads them. ssh-key reads the key of a signature as a plain key
//! only, so the blob of PROTOCOL.sshsig is read and written here when its key
//! is a certificate (PROTOCOL.certkeys); the signature is then checked with
//! the certificate's key, as each other.
//!
//! A `cert-authority` line allows such a signature when its key is the
//! certificate's CA, and the certificate is a user certificate, valid at the
//! time, that lists the principal: the checks and the words of OpenSSH's
//! `sshkey_cert_check_authority`. As there, the critical options of the
//! certificate are not read: they restrict a login, not a signature.

use base64::Engine;
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::ssh_key::{Certificate, HashAlg, Signature, SshSig};

use crate::sshsig::Signed;

/// The first bytes of each signature's blob.
const MAGIC: &[u8] = b"SSHSIG";
/// The armour, as OpenSSH writes it: the blob in base64, 70 characters to a
/// line, between these two lines.
const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const END: &str = "-----END SSH SIGNATURE-----";
const WIDTH: usize = 70;

/// The fields of an SSH blob in their order: a string is its bytes after
/// their length in 32 bits.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)?.try_into().ok().map(u32::from_be_bytes)
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// The blob inside an armoured signature, when its base64 decodes.
fn dearmour(text: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(text);
    let body: String = text.lines().map(str::trim).filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

/// Whether the key inside an armoured signature is a certificate: its name
/// ends in `-cert-v01@openssh.com`.
pub fn certificate_inside(text: &[u8]) -> bool {
    let Some(blob) = dearmour(text) else { return false };
    let mut fields = Fields(&blob);
    if fields.take(MAGIC.len()).is_none() || fields.u32().is_none() {
        return false;
    }
    let Some(key) = fields.string() else { return false };
    Fields(key).string().is_some_and(|name| name.ends_with(b"-cert-v01@openssh.com"))
}

/// A signature whose key is a certificate, read: the signature with the
/// certificate's key as its key, and the certificate; or why it is none.
pub fn read(text: &[u8]) -> Result<Signed, String> {
    let blob = dearmour(text).ok_or("invalid format")?;
    let mut fields = Fields(&blob);
    if fields.take(MAGIC.len()) != Some(MAGIC) {
        return Err("invalid format".into());
    }
    let version = fields.u32().ok_or("invalid format")?;
    if version > SshSig::VERSION {
        return Err(format!("unsupported signature version {version}"));
    }
    let short = || "invalid format".to_string();
    let certificate =
        Certificate::from_bytes(fields.string().ok_or_else(short)?).map_err(|e| format!("the certificate: {e}"))?;
    let namespace = fields.string().and_then(|n| std::str::from_utf8(n).ok()).ok_or_else(short)?;
    // The reserved field, which OpenSSH reads and passes over.
    fields.string().ok_or_else(short)?;
    let hash = fields.string().and_then(|h| std::str::from_utf8(h).ok()).ok_or_else(short)?;
    let hash = HashAlg::new(hash).map_err(|_| format!("unsupported hash algorithm \"{hash}\""))?;
    let signature = Signature::try_from(fields.string().ok_or_else(short)?).map_err(|e| e.to_string())?;
    if !fields.0.is_empty() {
        return Err("trailing data after the signature".into());
    }
    // The CA's signature over the certificate, as OpenSSH checks it when it
    // reads one. Whether that CA is trusted is the allowed signers' question
    // (`not_authorized`).
    certificate
        .verify_signature()
        .map_err(|_| "the certificate's signature does not verify against its CA".to_string())?;
    let signature =
        SshSig::new(certificate.public_key().clone(), namespace, hash, signature).map_err(|e| e.to_string())?;
    Ok(Signed { signature, certificate: Some(certificate) })
}

/// The armoured text of `signature` with `certificate` as its key, as
/// `ssh-keygen -Y sign -f KEY-cert.pub` writes it.
pub fn armour(signature: &SshSig, certificate: &Certificate) -> Result<String, String> {
    if certificate.public_key() != signature.public_key() {
        return Err("the certificate is not of the key that signed".into());
    }
    let encoding = |e: russh::keys::ssh_key::Error| e.to_string();
    let mut blob = MAGIC.to_vec();
    blob.extend_from_slice(&SshSig::VERSION.to_be_bytes());
    put(&mut blob, &certificate.to_bytes().map_err(encoding)?);
    put(&mut blob, signature.namespace().as_bytes());
    put(&mut blob, signature.reserved());
    put(&mut blob, signature.hash_alg().as_str().as_bytes());
    put(&mut blob, &Vec::<u8>::try_from(signature.signature().clone()).map_err(encoding)?);
    let text = base64::engine::general_purpose::STANDARD.encode(blob);
    let mut out = format!("{BEGIN}\n");
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let (line, after) = rest.split_at(rest.len().min(WIDTH));
        out.push_str(line);
        out.push('\n');
        rest = after;
    }
    out.push_str(END);
    out.push('\n');
    Ok(out)
}

/// A string field: its length, then its bytes.
fn put(blob: &mut Vec<u8>, field: &[u8]) {
    blob.extend_from_slice(&(field.len() as u32).to_be_bytes());
    blob.extend_from_slice(field);
}

/// Why `certificate` does not allow a signature at `now` by the line of the
/// CA `ca`, in the words of OpenSSH's `sshkey_cert_check_authority`: it must
/// be a user certificate, valid at the time, with principals, `principal`
/// among them when one is asked for (`verify`); `None` when it allows it.
pub fn not_authorized(
    certificate: &Certificate,
    ca: &KeyData,
    principal: Option<&str>,
    now: i64,
) -> Option<&'static str> {
    let now = u64::try_from(now).unwrap_or(0);
    if certificate.cert_type() != CertType::User {
        return Some("Certificate invalid: not a user certificate");
    }
    if now < certificate.valid_after() {
        return Some("Certificate invalid: not yet valid");
    }
    if now >= certificate.valid_before() {
        return Some("Certificate invalid: expired");
    }
    if certificate.valid_principals().is_empty() {
        return Some("Certificate lacks principal list");
    }
    if principal.is_some_and(|p| !certificate.valid_principals().iter().any(|listed| listed == p)) {
        return Some("Certificate invalid: name is not a listed principal");
    }
    // The CA's signature and its key again, through the check that ssh-key
    // documents: the line that named the CA is the one that trusts it.
    if certificate.validate_at(now, [&ca.fingerprint(HashAlg::Sha256)]).is_err() {
        return Some("Certificate invalid: not signed by the CA of the line");
    }
    None
}

/// The principals of `certificate` that the patterns of a `cert-authority`
/// line allow at `now`, as OpenSSH's `cert_filter_principals` finds them for
/// `find-principals`; else why there are none.
pub fn principals(certificate: &Certificate, ca: &KeyData, patterns: &str, now: i64) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    if not_authorized(certificate, ca, None, now).is_none() {
        for pattern in patterns.split(',').filter(|p| !p.is_empty()) {
            for listed in certificate.valid_principals() {
                if crate::known_hosts::wildcard(pattern.as_bytes(), listed.as_bytes()) {
                    found.push(listed.clone());
                }
            }
        }
    }
    if found.is_empty() {
        return Err("no valid principals found".into());
    }
    Ok(found)
}

#[cfg(test)]
#[path = "sshsig_cert_tests.rs"]
mod tests;
