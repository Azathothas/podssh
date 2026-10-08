//! E13: OpenSSH's `known_hosts` file, in OpenSSH's format.
//!
//! ⛔ **The format is not a choice.** `E13`'s `Prove` block's third command is
//! `ssh-keygen -F github.com -f ~/.ssh/known_hosts`, and the entry says ⛔ *"a
//! `known_hosts` file only podssh can read is a private trust store; the
//! operator's existing tooling must be able to revoke a key with `ssh-keygen
//! -R`"*. ⛔ So every byte of this file is OpenSSH's, and the tests parse and
//! write the *same* strings `ssh-keygen` does.
//!
//! ⛔ **A malformed line must not fail the load.** `E13`'s Approach: *"One bad
//! line loses every other trust decision in the file if the parser is strict,
//! and that is a denial of service on the security path."* ⛔ So a bad line is
//! **recorded and skipped**, with its number kept ⛔ — because a rejection has to
//! name a line, and a line number is only available if the line was counted
//! while it was being read rather than after the parse.

use std::fmt;

use hmac::{Hmac, Mac};
use sha1::Sha1;

use super::fingerprint::{parse_field, KeyError, PublicKey};

/// ⛔ **The two markers `E13`'s Approach names.** ⛔ `@revoked` is ⛔ **not
/// honoured as a revocation** and that is a decision worth stating rather than
/// a gap: ⛔ a file that can *revoke* a key needs somewhere to put the
/// revocation, and podssh has no entry for it, so ⛔ a key marked `@revoked` is
/// loaded and ⛔ **never matches** ⛔ — which refuses the connection, which is
/// the outcome `@revoked` asks for, and does it without podssh ever writing to
/// the file. ⛔ `@cert-authority` is the opposite: it is *not* a host key, it is
/// a CA that may certify one, and podssh does not implement certificate
/// validation, so ⛔ a `@cert-authority` line is recorded and skipped rather
/// than mistaken for a host key that would then mismatch.
pub const MARKER_CERT_AUTHORITY: &str = "@cert-authority";
pub const MARKER_REVOKED: &str = "@revoked";

/// ⛔ **The hashed-host prefix.** OpenSSH's `known_hosts` hashes a host name as
/// `|1|<base64 salt>|<base64 HMAC-SHA1 of the name>`.
pub const HASH_PREFIX: &str = "|1|";

/// ⛔ **A marker is never a host key, and this is the whole reason
/// `@cert-authority` and `@revoked` can be recognised at all.**
///
/// ⛔ **The first version of this parser decided whether a key type was
/// known with `PublicKey::is_known_algorithm`, whose list is the six SSH host-key
/// types, and neither marker is one of them.** ⛔ So both marker lines were
/// silently dropped. ⛔ MEASURED 2026-10-02: a file whose only entry was
/// `@revoked evil.example …` parsed to **zero entries** — the revocation was
/// erased by opening the file. ⛔ **A marker that is dropped is a
/// revocation that is dropped**, and the file is the only record of it.
///
/// ⛔ The predicate lives here and not in `fingerprint.rs` because this is
/// `known_hosts` syntax rather than key syntax: an `authorized_keys` file has
/// no markers, and a shared "is this a key type" test would be right for one
/// and wrong for the other.
fn is_marker(token: &str) -> bool {
    token.starts_with('@')
}

/// One host pattern, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// ⛔ A name written in the file, matched exactly. ⛔ `E13`'s Approach names
    /// both forms: `hostname` and `hostname:port`.
    Plain(String),
    /// ⛔ A comma-separated list, OpenSSH's own spelling.
    CommaList(Vec<String>),
    /// ⛔ `|1|salt|mac`. ⛔ **The salt is public and the MAC is a lookup key, not
    /// a signature** ⛔ — a hashed entry is not tamper-evident, and the entry
    /// says nothing depends on it being so. ⛔ It exists so the file does not
    /// name the host in the clear.
    Hashed { salt: Vec<u8>, mac: Vec<u8> },
}

impl HostPattern {
    pub fn is_hashed(&self) -> bool {
        matches!(self, HostPattern::Hashed { .. })
    }

    /// ⛔ **Every literal name this pattern covers, for a report.** ⛔ A hashed
    /// pattern has no name to report, which is exactly why the entry says
    /// *"Report which one is in use"* about the file and not about the entries.
    pub fn literals(&self) -> Vec<&str> {
        match self {
            HostPattern::Plain(s) => vec![s.as_str()],
            HostPattern::CommaList(v) => v.iter().map(String::as_str).collect(),
            HostPattern::Hashed { .. } => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// ⛔ No marker: a plain host key.
    None,
    CertAuthority,
    Revoked,
}

/// ⛔ **One line, with the number it came from.** ⛔ **The line number is not
/// decoration**: `E13`'s `Prove` block requires that a changed key be rejected
/// *"with a message naming the file and the line"*, and ⛔ a rejection that
/// cannot name a line is a rejection the operator has to go and find by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub line: usize,
    pub patterns: Vec<HostPattern>,
    pub marker: Marker,
    pub key: PublicKey,
}

/// ⛔ **A line that would not parse, and why.** ⛔ Kept rather than dropped:
/// ⛔ a `known_hosts` file with a corrupt line and one good entry must load the
/// good entry *and* say which line it skipped, because ⛔ "your trust store has
/// a typo in it" is a sentence nobody can act on without a number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub line: usize,
    pub text: String,
    pub why: String,
}

/// The whole file, and what it took to read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHosts {
    pub entries: Vec<Entry>,
    pub skipped: Vec<Skipped>,
}

/// ⛔ **A line that is a comment, blank, or a `#`-prefixed marker.** ⛔ OpenSSH
/// writes `@revoked` and `@cert-authority` on the *same* line as the key, but a
/// file written by `ssh-keygen -R` and by hand carries a bare `@revoked` line
/// too, and ⛔ a parser that treats one as a key type silently loses the
/// revocation.
fn is_noise(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

/// ⛔ **Parse a whole file.** ⛔ **Never returns an `Err`.** ⛔ Every failure
/// mode is a [`Skipped`] entry, and the reason is the entry's own: ⛔ *"One bad
/// line loses every other trust decision in the file if the parser is strict,
/// and that is a denial of service on the security path."*
pub fn parse(text: &str) -> KnownHosts {
    let mut out = KnownHosts::default();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        if is_noise(raw) {
            continue;
        }
        let line = raw.trim_end_matches(['\r']);
        let mut fields: Vec<&str> = line.split_whitespace().collect();
        let mut marker = Marker::None;
        if fields.first().is_some_and(|f| is_marker(f)) {
            let head = fields.remove(0);
            marker = match head {
                MARKER_CERT_AUTHORITY => Marker::CertAuthority,
                MARKER_REVOKED => Marker::Revoked,
                other => {
                    out.skipped.push(Skipped {
                        line: n,
                        text: line.to_string(),
                        why: format!("unknown marker {other}"),
                    });
                    continue;
                }
            };
        }
        if fields.is_empty() {
            out.skipped.push(Skipped {
                line: n,
                text: line.to_string(),
                why: "a marker with no host on the line".into(),
            });
            continue;
        }
        let host_field = fields.remove(0);
        let patterns = match parse_patterns(host_field) {
            Ok(p) => p,
            Err(why) => {
                out.skipped.push(Skipped {
                    line: n,
                    text: line.to_string(),
                    why,
                });
                continue;
            }
        };
        let key = match parse_field(&fields.join(" ")) {
            Ok(k) => k,
            Err(e) => {
                out.skipped.push(Skipped {
                    line: n,
                    text: line.to_string(),
                    why: e.to_string(),
                });
                continue;
            }
        };
        if marker == Marker::None && !key.is_known_algorithm() {
            // ⛔ `E13`'s Approach: *"skip unknown key types rather than failing
            // the whole file."* ⛔ Skipped, **not stored and not matched** ⛔ —
            // a key type podssh cannot interpret is a key it must not trust.
            // ⛔ **A marked line skips this check entirely.** ⛔ `@cert-authority` and
            // `@revoked` are `known_hosts` markers, not key types, and routing
            // them through the key-type list deleted every marker line in the
            // file — see [`is_marker`].
            out.skipped.push(Skipped {
                line: n,
                text: line.to_string(),
                why: format!("key type {} is not in podssh's host-key set", key.algorithm),
            });
            continue;
        }
        out.entries.push(Entry {
            line: n,
            patterns,
            marker,
            key,
        });
    }
    out
}

fn parse_patterns(field: &str) -> Result<Vec<HostPattern>, String> {
    if let Some(rest) = field.strip_prefix(HASH_PREFIX) {
        let mut it = rest.split('|');
        let salt = it
            .next()
            .ok_or_else(|| "a hashed host with no salt".to_string())?;
        let mac = it
            .next()
            .ok_or_else(|| "a hashed host with no MAC".to_string())?;
        if it.next().is_some() {
            return Err("a hashed host with more than two fields".into());
        }
        return Ok(vec![HostPattern::Hashed {
            salt: decode_b64(salt)?,
            mac: decode_b64(mac)?,
        }]);
    }
    if field.is_empty() {
        return Err("a line with no host".into());
    }
    if field.contains(',') {
        let parts: Vec<String> = field
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if parts.is_empty() {
            return Err("a comma list with no host in it".into());
        }
        return Ok(parts
            .into_iter()
            .map(HostPattern::Plain)
            .collect::<Vec<_>>());
    }
    Ok(vec![HostPattern::Plain(field.to_string())])
}

fn decode_b64(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| format!("{s:?} is not base64"))
}

/// ⛔ **The hashed-host check, exactly as OpenSSH computes it.**
///
/// ⛔ **HMAC-SHA1 with the salt as the key and the host name as the message.**
/// ⛔ MEASURED against `ssh-keygen -H` on this machine, and the measurement is
/// in `docs/TODO/security/host-keys.md`: for salt
/// `7VxMAYCtkkfcxLDU4i9dktuD4hM=` and the name `github.com`, `openssl dgst
/// -sha1 -hmac` and OpenSSH's own file both give
/// `vWs7gM52cv1zvZLddNKcOSlslOQ=`, and SHA-256 over the same input gives
/// something else, so ⛔ **the hash is SHA-1 and not SHA-256**, and a reader
/// that "improved" it would match nothing in the file.
pub fn hashed_host_matches(pattern: &HostPattern, host: &str) -> bool {
    let HostPattern::Hashed { salt, mac } = pattern else {
        return false;
    };
    type HmacSha1 = Hmac<Sha1>;
    // ⛔ `new_from_slice` is infallible for HMAC at any key length, which the
    // trait's own contract states; the `expect` names the case rather than
    // hiding it behind an `unwrap`.
    let mut h = HmacSha1::new_from_slice(salt).expect("HMAC accepts any key length");
    h.update(host.as_bytes());
    // ⛔ Constant-time, and ⛔ **over the whole MAC**: a length-dependent early
    // return would leak the length of a match, which is not much, and costs
    // nothing to not leak.
    h.verify_slice(mac).is_ok()
}

/// ⛔ **Does any pattern in this entry name this host?**
pub fn entry_matches(entry: &Entry, host: &str) -> bool {
    if entry.marker == Marker::CertAuthority {
        // ⛔ See the module note: a CA is not a host key and podssh does not
        // validate certificates, so this entry is never a match.
        return false;
    }
    entry.patterns.iter().any(|p| match p {
        HostPattern::Plain(s) => s == host,
        HostPattern::CommaList(v) => v.iter().any(|s| s == host),
        HostPattern::Hashed { .. } => hashed_host_matches(p, host),
    })
}

/// ⛔ **Render one entry the way OpenSSH writes it.** ⛔ A hashed pattern is
/// written back **with its salt and MAC intact and never re-hashed** ⛔ —
/// podssh has no reason to change a host's salt, and re-hashing on every write
/// would make the file churn for no gain.
pub fn format_entry(entry: &Entry) -> String {
    let hosts = entry
        .patterns
        .iter()
        .map(|p| match p {
            HostPattern::Plain(s) => s.clone(),
            HostPattern::CommaList(v) => v.join(","),
            HostPattern::Hashed { salt, mac } => format!(
                "{HASH_PREFIX}{}|{}",
                b64enc(salt),
                b64enc(mac)
            ),
        })
        .collect::<Vec<_>>()
        .join(",");
    let marker_text = match entry.marker {
        Marker::None => String::new(),
        Marker::CertAuthority => format!("{MARKER_CERT_AUTHORITY} "),
        Marker::Revoked => format!("{MARKER_REVOKED} "),
    };
    format!("{marker_text}{hosts} {}", entry.key.to_known_hosts_field())
}

pub fn b64enc(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// ⛔ **Build a hashed pattern for a host, the way `ssh-keygen -H` would.** ⛔
/// Used by the write path when an operator asks for a hashed file, and ⛔
/// asserted against a file `ssh-keygen -H` actually produced.
pub fn hash_host(salt: &[u8], host: &str) -> HostPattern {
    type HmacSha1 = Hmac<Sha1>;
    let mut h = HmacSha1::new_from_slice(salt).expect("HMAC accepts any key length");
    h.update(host.as_bytes());
    HostPattern::Hashed {
        salt: salt.to_vec(),
        mac: h.finalize().into_bytes().to_vec(),
    }
}

impl fmt::Display for KnownHosts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for e in &self.entries {
            writeln!(f, "{}", format_entry(e))?;
        }
        Ok(())
    }
}

impl KnownHosts {
    /// ⛔ Every entry that could apply to `host`, with its line number ⛔ — the
    /// inputs to the three verdicts in [`super::store`].
    pub fn candidates(&self, host: &str) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| entry_matches(e, host))
            .collect()
    }

    /// ⛔ **Append one entry and return the new file text.** ⛔ **It never
    /// rewrites the lines already in the file**, and that is the property
    /// `E13`'s `Prove` block names as *"Plant: a `known_hosts` file with one
    /// corrupt line and one good entry"* ⛔ — a write that normalised the file
    /// would quietly delete the corrupt line the operator needed to see.
    pub fn append(&self, entry: &Entry) -> String {
        let mut text = self.to_string();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format_entry(entry));
        text.push('\n');
        text
    }
}

impl From<KeyError> for String {
    fn from(e: KeyError) -> String {
        e.to_string()
    }
}
