//! `podssh keygen -F`, `-R` and `-H` (T-019): find, remove and hash the
//! lines of a `known_hosts` file, as OpenSSH's `ssh-keygen` does (measured
//! with OpenSSH for Windows 10.0p2). These work on the file's bytes: a line
//! that is not changed stays byte for byte, its spacing, comment and line end
//! included. [`rewrite`] puts a new text in the file's place.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use super::{lock, matches, parse_line, too_large, Marker, MAX_FILE};

/// One line of the file: its number (from 1), its text without the line
/// end, and the line end (`\n`, `\r\n`, or nothing at the end of the file).
struct Line<'a> {
    number: usize,
    text: &'a [u8],
    end: &'a [u8],
}

fn lines(raw: &[u8]) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let (line, end, next) = match rest.iter().position(|b| *b == b'\n') {
            Some(at) if at > 0 && rest[at - 1] == b'\r' => (&rest[..at - 1], &rest[at - 1..=at], &rest[at + 1..]),
            Some(at) => (&rest[..at], &rest[at..=at], &rest[at + 1..]),
            None => (rest, &rest[rest.len()..], &rest[rest.len()..]),
        };
        out.push(Line { number: out.len() + 1, text: line, end });
        rest = next;
    }
    out
}

/// A line of a host key: its marker, its host patterns, and its text from
/// the key type on. `None` for a blank line or a comment.
enum Kind<'a> {
    Blank,
    Key {
        marker: Option<Marker>,
        patterns: &'a str,
        from_key: &'a str,
    },
    /// Not a line of a host key: no key, an unknown marker, or text that is
    /// not UTF-8.
    Other,
}

fn kind(text: &[u8]) -> Kind<'_> {
    let Ok(text) = std::str::from_utf8(text) else { return Kind::Other };
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Kind::Blank;
    }
    match parse_line(text) {
        Some(parsed) => Kind::Key { marker: parsed.marker, patterns: parsed.patterns, from_key: parsed.from_key },
        None => Kind::Other,
    }
}

/// Whether a pattern list holds a name that stands for more than one host
/// (`*`, `?`) or one that is negated (`!`): such a line is not hashed, as
/// OpenSSH does not hash it, and `-R` does not remove it.
pub fn has_wildcard(patterns: &str) -> bool {
    patterns.split(',').any(|p| !p.starts_with("|1|") && (p.starts_with('!') || p.contains(['*', '?'])))
}

/// A line that names the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub line: usize,
    pub marker: Option<Marker>,
    /// The line as the file has it, with no line end.
    pub text: String,
    /// The same line with each name hashed, as `-F -H` prints it: one line
    /// for each name; the line itself when it is not hashed (a wildcard, a
    /// marker, or names hashed already).
    pub hashed: Vec<String>,
}

/// Each line whose patterns match `host`, as `ssh-keygen -F` finds them:
/// plain, hashed and wildcard lines, and marked ones. `salt` gives the salt
/// of each name hashed.
pub fn find(raw: &[u8], host: &str, salt: &mut dyn FnMut() -> [u8; 20]) -> Vec<Found> {
    let mut out = Vec::new();
    for line in lines(raw) {
        if let Kind::Key { marker, patterns, from_key } = kind(line.text) {
            if matches(patterns, host) {
                let text = String::from_utf8_lossy(line.text).into_owned();
                let hashed = match hashed_lines(marker, patterns, from_key, salt) {
                    Some(hashed) => hashed,
                    None => vec![text.clone()],
                };
                out.push(Found { line: line.number, marker, text, hashed });
            }
        }
    }
    out
}

/// What [`remove`] did.
#[derive(Debug, Default)]
pub struct Removed {
    /// The new text: `None` when no line was removed.
    pub text: Option<Vec<u8>>,
    /// The numbers of the lines removed.
    pub removed: Vec<usize>,
    /// The lines that name the host through a wildcard or a negated
    /// pattern, kept: their key stands for other hosts too.
    pub kept: Vec<(usize, String)>,
    /// The lines that are no line of a host key, kept as they are.
    pub other: Vec<usize>,
}

/// The text without the lines of `host`, as `ssh-keygen -R` removes them;
/// `@revoked` and `@cert-authority` lines stay, as in OpenSSH. Unlike
/// OpenSSH, a line that names the host through a wildcard stays too, as it
/// stands for other hosts, and a line that does not parse stays as it is,
/// where OpenSSH refuses the whole file.
pub fn remove(raw: &[u8], host: &str) -> Removed {
    let mut out = Removed::default();
    let mut text = Vec::with_capacity(raw.len());
    for line in lines(raw) {
        match kind(line.text) {
            Kind::Key { marker: None, patterns, .. } if matches(patterns, host) => {
                if has_wildcard(patterns) {
                    out.kept.push((line.number, patterns.to_string()));
                } else {
                    out.removed.push(line.number);
                    continue;
                }
            }
            Kind::Other => out.other.push(line.number),
            _ => {}
        }
        text.extend_from_slice(line.text);
        text.extend_from_slice(line.end);
    }
    if !out.removed.is_empty() {
        out.text = Some(text);
    }
    out
}

/// What [`hash`] did.
#[derive(Debug, Default)]
pub struct Hashed {
    /// The new text: `None` when no name was hashed.
    pub text: Option<Vec<u8>>,
    /// How many names were hashed.
    pub names: usize,
    /// The lines with a wildcard or a negated pattern, which are not
    /// hashed: their patterns.
    pub wildcard: Vec<(usize, String)>,
    /// The lines that are no line of a host key, kept as they are.
    pub other: Vec<usize>,
}

/// The text with each host name hashed, as `ssh-keygen -H` hashes it: each
/// name of a line on a line of its own, `|1|SALT|HASH` (HMAC-SHA1 of the
/// name in lower case, keyed with a random salt of 20 bytes), then the line's
/// text from its key type on. A line with a wildcard, a marked line and a
/// name hashed already stay as they are.
pub fn hash(raw: &[u8], salt: &mut dyn FnMut() -> [u8; 20]) -> Hashed {
    let mut out = Hashed::default();
    let mut text = Vec::with_capacity(raw.len() * 2);
    for line in lines(raw) {
        match kind(line.text) {
            Kind::Key { marker, patterns, from_key } => {
                if has_wildcard(patterns) {
                    out.wildcard.push((line.number, patterns.to_string()));
                } else if let Some(hashed) = hashed_lines(marker, patterns, from_key, salt) {
                    out.names += patterns.split(',').filter(|p| !p.is_empty() && !p.starts_with("|1|")).count();
                    for one in hashed {
                        text.extend_from_slice(one.as_bytes());
                        text.extend_from_slice(if line.end.is_empty() { b"\n" } else { line.end });
                    }
                    continue;
                }
            }
            Kind::Other => out.other.push(line.number),
            Kind::Blank => {}
        }
        text.extend_from_slice(line.text);
        text.extend_from_slice(line.end);
    }
    if out.names > 0 {
        out.text = Some(text);
    }
    out
}

/// The lines that hash a line of a host key, one for each name; `None` when
/// the line is not hashed: a wildcard, a marker, or only names hashed
/// already.
fn hashed_lines(
    marker: Option<Marker>,
    patterns: &str,
    from_key: &str,
    salt: &mut dyn FnMut() -> [u8; 20],
) -> Option<Vec<String>> {
    if marker.is_some() || has_wildcard(patterns) {
        return None;
    }
    let names: Vec<&str> = patterns.split(',').filter(|p| !p.is_empty()).collect();
    if names.iter().all(|n| n.starts_with("|1|")) {
        return None;
    }
    let lines = names
        .iter()
        .map(|name| {
            let name = if name.starts_with("|1|") { name.to_string() } else { hash_name(name, &salt()) };
            format!("{name} {from_key}")
        })
        .collect();
    Some(lines)
}

/// `|1|SALT|HASH` for `name`, as OpenSSH hashes a host name: HMAC-SHA1 of
/// the name in lower case, keyed with the salt, both in base64.
pub fn hash_name(name: &str, salt: &[u8; 20]) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut mac = Hmac::<Sha1>::new_from_slice(salt).expect("HMAC takes a key of any length");
    mac.update(name.to_ascii_lowercase().as_bytes());
    format!("|1|{}|{}", engine.encode(salt), engine.encode(mac.finalize().into_bytes()))
}

/// The files of a rewrite.
#[derive(Debug)]
pub struct Rewritten {
    /// The file that was rewritten (the target of a symbolic link).
    pub path: PathBuf,
    /// `FILE.old`, which keeps the text as it was.
    pub old: PathBuf,
}

/// Put a new text in the place of the `known_hosts` file at `path`, whole
/// or not at all. Under the lock that [`super::append`] takes, the file is
/// read and `change` gives the new text, or `None` to leave the file as it
/// is; the old text goes to `FILE.old`, and the new one to a new file beside
/// the file, which then takes its place by a rename. `create` makes a new
/// file that only its owner may open (podssh-relay's, which this crate does
/// not depend on). A symbolic link stays, and its target is rewritten.
///
/// A writer that waited for the lock meanwhile holds the old file: `append`
/// looks again, after its lock, at which file the path names, so that its
/// line goes to the new one.
pub fn rewrite<T>(
    path: &Path,
    create: fn(&Path) -> std::io::Result<File>,
    change: impl FnOnce(&[u8]) -> (Option<Vec<u8>>, T),
) -> std::io::Result<(Option<Rewritten>, T)> {
    let path = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    let file = File::open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(ErrorKind::InvalidInput, "it is not a regular file"));
    }
    let _held = lock::hold(&file, lock::WAIT)?;
    let mut raw = Vec::new();
    (&file).take(MAX_FILE + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_FILE {
        return Err(std::io::Error::new(ErrorKind::InvalidData, too_large()));
    }
    let (text, out) = change(&raw);
    let Some(text) = text else { return Ok((None, out)) };
    let old = with_suffix(&path, ".old");
    match std::fs::remove_file(&old) {
        Err(e) if e.kind() != ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    write_new(&old, &raw, create)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let new = path.with_file_name(format!(".{name}.podssh-new-{}", std::process::id()));
    write_new(&new, &text, create)?;
    if let Err(e) = std::fs::rename(&new, &path) {
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }
    Ok((Some(Rewritten { path, old }), out))
}

fn write_new(path: &Path, bytes: &[u8], create: fn(&Path) -> std::io::Result<File>) -> std::io::Result<()> {
    let mut file = create(path)?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
#[path = "edit_tests.rs"]
mod tests;
