//! OpenSSH `known_hosts` files: reading, matching and appending, following
//! sshd(8) "SSH_KNOWN_HOSTS FILE FORMAT".
//!
//! russh ships a reader, but it splits fields on single spaces, does not know
//! the `@revoked` and `@cert-authority` markers (a revoked key would then count
//! as known), has no wildcard or negated patterns, and fails the whole lookup
//! on one malformed key. This one skips what it cannot parse, line by line,
//! and keeps line numbers so a message can point at the line that matched.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use hmac::{Hmac, Mac};
use russh::keys::ssh_key::PublicKey;
use sha1::Sha1;

/// A marker at the start of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// `@cert-authority`: a CA key for host certificates. podssh does not
    /// verify host certificates, so these never make a plain key known.
    CertAuthority,
    /// `@revoked`: this key must never be accepted.
    Revoked,
}

/// One parsed line whose host patterns matched.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: PathBuf,
    pub line: usize,
    pub marker: Option<Marker>,
    pub key: PublicKey,
}

/// What the files say about a host and the key it presented.
#[derive(Debug, Clone)]
pub enum Lookup {
    /// The key is recorded for this host.
    Known { path: PathBuf, line: usize },
    /// The key is marked `@revoked`.
    Revoked { path: PathBuf, line: usize },
    /// A different key of the same type is recorded: the key changed.
    Changed { path: PathBuf, line: usize, recorded: PublicKey },
    /// The host is known, but only with keys of other types (their names).
    OtherTypes(Vec<String>),
    /// Nothing is recorded for this host.
    Unknown,
}

/// The name a host is filed under: `host` on port 22, `[host]:port` otherwise.
pub fn host_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Look `key` up for `name` (see [`host_name`]) across `files`, in order.
/// Missing or unreadable files are skipped: having no `known_hosts` is normal.
pub fn lookup(files: &[PathBuf], name: &str, key: &PublicKey) -> Lookup {
    let entries = entries_for(files, name);
    if let Some(e) = entries
        .iter()
        .find(|e| e.marker == Some(Marker::Revoked) && e.key.key_data() == key.key_data())
    {
        return Lookup::Revoked { path: e.path.clone(), line: e.line };
    }
    let plain: Vec<&Entry> = entries.iter().filter(|e| e.marker.is_none()).collect();
    if let Some(e) = plain.iter().find(|e| e.key.key_data() == key.key_data()) {
        return Lookup::Known { path: e.path.clone(), line: e.line };
    }
    if let Some(e) = plain.iter().find(|e| e.key.algorithm() == key.algorithm()) {
        return Lookup::Changed { path: e.path.clone(), line: e.line, recorded: e.key.clone() };
    }
    if plain.is_empty() {
        return Lookup::Unknown;
    }
    let mut types: Vec<String> = plain.iter().map(|e| key_type(&e.key)).collect();
    types.dedup();
    Lookup::OtherTypes(types)
}

/// The algorithms of the plain keys recorded for `name`, for ordering the
/// host-key algorithms offered to the server (as OpenSSH does, so a host
/// with a recorded RSA key is not asked for an unknown Ed25519 one).
pub fn recorded_algorithms(files: &[PathBuf], name: &str) -> Vec<russh::keys::Algorithm> {
    let mut out = Vec::new();
    for e in entries_for(files, name) {
        if e.marker.is_none() && !out.contains(&e.key.algorithm()) {
            out.push(e.key.algorithm());
        }
    }
    out
}

/// Every parsable entry in `files` whose host patterns match `name`.
pub fn entries_for(files: &[PathBuf], name: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for path in files {
        let Ok(mut file) = std::fs::File::open(path) else { continue };
        let mut raw = Vec::new();
        if file.read_to_end(&mut raw).is_err() {
            continue;
        }
        let text = String::from_utf8_lossy(&raw);
        for (index, line) in text.lines().enumerate() {
            if let Some((marker, patterns, key)) = parse_line(line) {
                if matches(patterns, name) {
                    out.push(Entry { path: path.clone(), line: index + 1, marker, key });
                }
            }
        }
    }
    out
}

/// One line: `[marker] patterns keytype base64 [comment]`. `None` for blank
/// lines, comments, unknown markers and anything that does not parse.
fn parse_line(line: &str) -> Option<(Option<Marker>, &str, PublicKey)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let mut first = fields.next()?;
    let marker = match first {
        "@cert-authority" => Some(Marker::CertAuthority),
        "@revoked" => Some(Marker::Revoked),
        m if m.starts_with('@') => return None,
        _ => None,
    };
    if marker.is_some() {
        first = fields.next()?;
    }
    let key_type = fields.next()?;
    let blob = fields.next()?;
    let key = PublicKey::from_openssh(&format!("{key_type} {blob}")).ok()?;
    Some((marker, first, key))
}

/// Whether `name` matches a comma-separated pattern list: hashed entries
/// (`|1|salt|hash`), `*` and `?` wildcards, and `!` negation (a negated match
/// rejects the line whatever else matched). Case-insensitive.
pub fn matches(patterns: &str, name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let mut matched = false;
    for pattern in patterns.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some(hashed) = pattern.strip_prefix("|1|") {
            matched |= hashed_matches(hashed, &name);
            continue;
        }
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        if wildcard(pattern.to_ascii_lowercase().as_bytes(), name.as_bytes()) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// `salt|hash`, both base64: HMAC-SHA1 keyed with the decoded salt, over the
/// name. (SHA-256 matches no entry; OpenSSH uses SHA-1 here.)
fn hashed_matches(salt_and_hash: &str, name: &str) -> bool {
    let Some((salt, hash)) = salt_and_hash.split_once('|') else { return false };
    let engine = base64::engine::general_purpose::STANDARD;
    let (Ok(salt), Ok(hash)) = (engine.decode(salt), engine.decode(hash)) else { return false };
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&salt) else { return false };
    mac.update(name.as_bytes());
    mac.verify_slice(&hash).is_ok()
}

/// `*` matches any run (including dots), `?` one character. Case-sensitive.
pub fn wildcard(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            backtrack = Some((p, t));
            p += 1;
        } else if let Some((star, from)) = backtrack {
            p = star + 1;
            t = from + 1;
            backtrack = Some((star, from + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Append `name keytype base64` to `path`. The directory is created (mode
/// 0700) and the file too (0600) when missing. Existing content is never
/// rewritten: comments and lines podssh cannot parse stay exactly as they are.
pub fn append(path: &Path, name: &str, key: &PublicKey) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    let bare = PublicKey::new(key.key_data().clone(), "");
    let encoded = bare
        .to_openssh()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut line = String::new();
    if file.seek(SeekFrom::End(0))? > 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0u8; 1];
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            line.push('\n');
        }
    }
    line.push_str(name);
    line.push(' ');
    line.push_str(encoded.trim());
    line.push('\n');
    file.write_all(line.as_bytes())?;
    file.flush()
}

/// The short type name OpenSSH prints: `ED25519`, `ECDSA`, `RSA`.
pub fn key_type(key: &PublicKey) -> String {
    use russh::keys::Algorithm;
    match key.algorithm() {
        Algorithm::Ed25519 => "ED25519".into(),
        Algorithm::Ecdsa { .. } => "ECDSA".into(),
        Algorithm::Rsa { .. } => "RSA".into(),
        Algorithm::Dsa => "DSA".into(),
        Algorithm::SkEd25519 => "ED25519-SK".into(),
        Algorithm::SkEcdsaSha2NistP256 => "ECDSA-SK".into(),
        other => other.as_str().to_ascii_uppercase(),
    }
}

/// `SHA256:…`, as `ssh-keygen -l` prints it.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(russh::keys::HashAlg::Sha256).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_negation_and_ports() {
        assert!(matches("example.org", "example.org"));
        assert!(matches("EXAMPLE.org", "example.ORG"));
        assert!(matches("*.example.org", "a.b.example.org"), "* crosses dots");
        assert!(matches("host?", "host1"));
        assert!(!matches("host?", "host12"));
        assert!(matches("a,b,*.c", "x.c"));
        assert!(!matches("*.example.org,!bad.example.org", "bad.example.org"));
        assert!(matches("*.example.org,!bad.example.org", "good.example.org"));
        assert!(matches("[h]:2222", &host_name("h", 2222)));
        assert!(!matches("h", &host_name("h", 2222)), "a port-22 entry is not a port-2222 one");
        assert!(wildcard(b"*", b""));
        assert!(wildcard(b"a*b*c", b"aXXbYYc"));
        assert!(!wildcard(b"a*b*c", b"aXXbYY"));
    }

    #[test]
    fn hashed_entries_use_hmac_sha1() {
        // `ssh-keygen -H` format for "localhost", computed with a fixed salt.
        let salt = [7u8; 20];
        let mut mac = Hmac::<Sha1>::new_from_slice(&salt).unwrap();
        mac.update(b"localhost");
        let hash = mac.finalize().into_bytes();
        let engine = base64::engine::general_purpose::STANDARD;
        let entry = format!("|1|{}|{}", engine.encode(salt), engine.encode(hash));
        assert!(matches(&entry, "localhost"));
        assert!(!matches(&entry, "otherhost"));
    }
}
