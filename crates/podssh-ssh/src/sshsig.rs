//! SSH signatures (PROTOCOL.sshsig) and the allowed-signers files of
//! ssh-keygen(1), for `podssh keygen -Y` (T-020): the signatures that
//! `ssh-keygen -Y sign` writes, which git makes and checks, and the checks of
//! `-Y verify`, `check-novalidate`, `find-principals` and `match-principals`,
//! with the messages of the `ssh-keygen` of OpenSSH for Windows 10.0p2
//! (measured on 2026-10-11).
//!
//! The data is hashed as it is read, so a file of any size is signed. An RSA
//! key signs through aws-lc-rs with SHA-512 (`rsa-sha2-512`, as OpenSSH
//! signs), never through the `rsa` crate (T-257); each other key through
//! ssh-key. A signature made with a certificate, and the `cert-authority`
//! lines that would allow it, are not read yet (T-289).

use std::io::Read;

use chrono::{Local, NaiveDate, NaiveDateTime, TimeZone, Utc};
use russh::keys::ssh_key::{Algorithm, HashAlg, LineEnding, Signature, SshSig};
use russh::keys::{PrivateKey, PublicKey};
use sha2::Digest;

use crate::options::Agent;

/// The digest of what `reader` gives, with `hash`, read in pieces.
pub fn digest(reader: &mut dyn Read, hash: HashAlg) -> std::io::Result<Vec<u8>> {
    fn run<D: Digest>(reader: &mut dyn Read, mut hasher: D) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                return Ok(hasher.finalize().to_vec());
            }
            hasher.update(&buf[..n]);
        }
    }
    match hash {
        HashAlg::Sha256 => run(reader, sha2::Sha256::new()),
        _ => run(reader, sha2::Sha512::new()),
    }
}

/// `-O hashalg=`: `sha256` or `sha512` (the default).
pub fn hash_alg(name: &str) -> Option<HashAlg> {
    match name {
        "sha256" => Some(HashAlg::Sha256),
        "sha512" => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// An SSH signature of the digest `prehash` with `key`.
pub fn sign(key: &PrivateKey, namespace: &str, hash: HashAlg, prehash: &[u8]) -> Result<SshSig, String> {
    if namespace.is_empty() {
        return Err("the namespace is empty".into());
    }
    if key.algorithm().is_rsa() {
        let data = SshSig::signed_data_for_prehash(namespace, hash, prehash).map_err(|e| e.to_string())?;
        let bytes = crate::rsa_key::RsaSigner::of(key)?.sign_sha512(&data).map_err(|e| e.to_string())?;
        let signature =
            Signature::new(Algorithm::Rsa { hash: Some(HashAlg::Sha512) }, bytes).map_err(|e| e.to_string())?;
        return SshSig::new(key.public_key().key_data().clone(), namespace, hash, signature).map_err(|e| e.to_string());
    }
    key.sign_prehash(namespace, hash, prehash).map_err(|e| format!("could not sign: {e}"))
}

/// An SSH signature of the digest `prehash` by the agent of `choice` with
/// its key `public` (`-U`, and `-f` with a public key, as git asks).
pub async fn sign_with_agent(
    choice: &Agent,
    public: &PublicKey,
    namespace: &str,
    hash: HashAlg,
    prehash: &[u8],
) -> Result<SshSig, String> {
    let Some(mut agent) = crate::keys::connect_agent(choice).await? else {
        return Err("no agent runs: SSH_AUTH_SOCK names none".into());
    };
    let held = agent.request_identities().await.map_err(|e| format!("the agent: {e}"))?;
    if !held.iter().any(|id| id.public_key().key_data() == public.key_data()) {
        return Err("the agent does not hold the key".into());
    }
    let data = SshSig::signed_data_for_prehash(namespace, hash, prehash).map_err(|e| e.to_string())?;
    let rsa = public.algorithm().is_rsa().then_some(HashAlg::Sha512);
    let signature =
        agent.sign_request_signature(public, rsa, &data).await.map_err(|e| format!("the agent did not sign: {e}"))?;
    SshSig::new(public.key_data().clone(), namespace, hash, signature).map_err(|e| e.to_string())
}

/// The armoured text of a signature, as `ssh-keygen` writes it.
pub fn armour(signature: &SshSig) -> Result<String, String> {
    signature.to_pem(LineEnding::LF).map_err(|e| e.to_string())
}

/// A signature file, read: its signature, or why it is none. A signature
/// made with a certificate is named (T-289).
pub fn read_signature(text: &[u8]) -> Result<SshSig, String> {
    SshSig::from_pem(text).map_err(|e| {
        if certificate_inside(text) {
            "the signature was made with a certificate, which podssh does not read yet".to_string()
        } else {
            format!("Couldn't parse signature: {e}")
        }
    })
}

/// Whether the key inside an armoured signature is a certificate: its name
/// ends in `-cert-v01@openssh.com`.
fn certificate_inside(text: &[u8]) -> bool {
    use base64::Engine;
    let text = String::from_utf8_lossy(text);
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
    let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(body) else { return false };
    // "SSHSIG", the version, then the key's blob, whose first string is its name.
    let Some(rest) = blob.get(6 + 4 + 4..) else { return false };
    let Some(len) = rest.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize) else { return false };
    rest.get(4..4 + len).is_some_and(|name| name.ends_with(b"-cert-v01@openssh.com"))
}

/// Why a signature does not hold, as `ssh-keygen` says it on stderr.
pub fn check(signature: &SshSig, namespace: &str, prehash: &[u8]) -> Result<(), String> {
    if signature.namespace() != namespace {
        return Err("Couldn't verify signature: namespace does not match".into());
    }
    let key = PublicKey::new(signature.public_key().clone(), "");
    key.verify_prehash(namespace, prehash, signature)
        .map_err(|_| "Signature verification failed: incorrect signature".to_string())
}

/// One line of an allowed-signers file that parsed.
#[derive(Debug, Clone)]
pub struct Signer {
    pub line: usize,
    /// The principals, a list of patterns as the file has it.
    pub principals: String,
    /// `namespaces="..."`: patterns of the namespaces the key may sign.
    pub namespaces: Option<String>,
    pub valid_after: Option<i64>,
    pub valid_before: Option<i64>,
    /// `cert-authority`: the key signs certificates, which podssh does not
    /// read yet (T-289), so the line allows no signature here.
    pub cert_authority: bool,
    pub key: PublicKey,
}

/// A line of an allowed-signers file: one that parsed, or why not, with its
/// principals when it has them.
#[derive(Debug, Clone)]
pub enum Line {
    Signer(Signer),
    Bad { line: usize, principals: String, why: String },
}

/// The lines of an allowed-signers file, as ssh-keygen(1) describes it:
/// `principals [options] keytype base64 [comment]`.
pub fn allowed_signers(text: &str) -> Vec<Line> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (principals, rest) = split_field(trimmed);
        let bad = |why: &str| Line::Bad { line, principals: principals.to_string(), why: why.into() };
        if rest.is_empty() {
            out.push(bad("invalid line"));
            continue;
        }
        let (options, key_text) = match PublicKey::from_openssh(rest) {
            Ok(_) => (None, rest),
            Err(_) => {
                let (options, after) = split_options(rest);
                if after.is_empty() {
                    out.push(bad("missing key"));
                    continue;
                }
                (Some(options), after)
            }
        };
        let Ok(key) = PublicKey::from_openssh(key_text) else {
            out.push(bad("invalid key"));
            continue;
        };
        let mut signer = Signer {
            line,
            principals: principals.to_string(),
            namespaces: None,
            valid_after: None,
            valid_before: None,
            cert_authority: false,
            key,
        };
        if let Err(why) = options.map_or(Ok(()), |o| apply_options(o, &mut signer)) {
            out.push(bad(&format!("bad options: {why}")));
            continue;
        }
        out.push(Line::Signer(signer));
    }
    out
}

/// The first field of `text`, and the rest with its leading space gone.
fn split_field(text: &str) -> (&str, &str) {
    match text.find([' ', '\t']) {
        Some(at) => (&text[..at], text[at..].trim_start()),
        None => (text, ""),
    }
}

/// The options of a line, up to the first space outside quotes, and the
/// rest.
fn split_options(text: &str) -> (&str, &str) {
    let mut quoted = false;
    for (at, c) in text.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => return (&text[..at], text[at..].trim_start()),
            _ => {}
        }
    }
    (text, "")
}

fn apply_options(options: &str, signer: &mut Signer) -> Result<(), String> {
    for option in split_commas(options) {
        let (name, value) = match option.split_once('=') {
            Some((name, value)) => (name, Some(value.trim_matches('"'))),
            None => (option, None),
        };
        match (name.to_ascii_lowercase().as_str(), value) {
            ("cert-authority", None) => signer.cert_authority = true,
            ("namespaces", Some(value)) => signer.namespaces = Some(value.to_string()),
            ("valid-after", Some(value)) => {
                signer.valid_after = Some(parse_time(value).ok_or("invalid \"valid-after\" time")?)
            }
            ("valid-before", Some(value)) => {
                signer.valid_before = Some(parse_time(value).ok_or("invalid \"valid-before\" time")?)
            }
            _ => return Err(format!("unsupported option \"{name}\"")),
        }
    }
    Ok(())
}

/// The options split at the commas outside quotes.
fn split_commas(text: &str) -> Vec<&str> {
    let (mut out, mut quoted, mut from) = (Vec::new(), false, 0);
    for (at, c) in text.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&text[from..at]);
                from = at + 1;
            }
            _ => {}
        }
    }
    out.push(&text[from..]);
    out.into_iter().filter(|o| !o.is_empty()).collect()
}

/// A time of ssh-keygen(1): `YYYYMMDD[HHMM[SS]]`, local time, or UTC with
/// `Z` at its end; seconds since 1970.
pub fn parse_time(text: &str) -> Option<i64> {
    let (digits, utc) = match text.strip_suffix(['Z', 'z']) {
        Some(digits) => (digits, true),
        None => (text, false),
    };
    if !matches!(digits.len(), 8 | 12 | 14) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |range: std::ops::Range<usize>| digits.get(range).and_then(|d| d.parse::<u32>().ok());
    let date = NaiveDate::from_ymd_opt(n(0..4)? as i32, n(4..6)?, n(6..8)?)?;
    let time = date.and_hms_opt(n(8..10).unwrap_or(0), n(10..12).unwrap_or(0), n(12..14).unwrap_or(0))?;
    if utc {
        Some(Utc.from_utc_datetime(&time).timestamp())
    } else {
        Local.from_local_datetime(&time).earliest().map(|t| t.timestamp())
    }
}

/// A time as `ssh-keygen` prints it: local time, `YYYY-MM-DDTHH:MM:SS`.
pub fn format_time(seconds: i64) -> String {
    match Local.timestamp_opt(seconds, 0).earliest() {
        Some(t) => t.format("%Y-%m-%dT%H:%M:%S").to_string(),
        None => NaiveDateTime::default().format("%Y-%m-%dT%H:%M:%S").to_string(),
    }
}

/// Whether `name` matches a comma-separated list of patterns, as OpenSSH's
/// `match_pattern_list` with case kept: `*` and `?` wildcards, and a
/// negated pattern (`!`) that matches rejects the name whatever else did.
pub fn pattern_list(patterns: &str, name: &str) -> bool {
    let mut matched = false;
    for pattern in patterns.split(',').filter(|p| !p.is_empty()) {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        if crate::known_hosts::wildcard(pattern.as_bytes(), name.as_bytes()) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// Why a line that names the key does not allow the signature: its
/// namespaces, or its times against `now`; `None` when it allows it.
pub fn refuses(signer: &Signer, namespace: &str, now: i64) -> Option<String> {
    if signer.namespaces.as_deref().is_some_and(|n| !pattern_list(n, namespace)) {
        return Some(format!("key is not permitted for use in signature namespace \"{namespace}\""));
    }
    if let Some(after) = signer.valid_after.filter(|after| now < *after) {
        return Some(format!(
            "key is not yet valid: verify time {} < valid-after {}",
            format_time(now),
            format_time(after)
        ));
    }
    if let Some(before) = signer.valid_before.filter(|before| now > *before) {
        return Some(format!(
            "key has expired: verify time {} > valid-before {}",
            format_time(now),
            format_time(before)
        ));
    }
    None
}

/// Whether the line names the key of `signature`: a plain key, the same.
pub fn names_key(signer: &Signer, signature: &SshSig) -> bool {
    !signer.cert_authority && signer.key.key_data() == signature.public_key()
}

#[cfg(test)]
#[path = "sshsig_tests.rs"]
mod tests;
