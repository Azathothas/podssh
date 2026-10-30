//! The saved sessions of a terminal program (T-292), as one model for each
//! format to fill, and the `Host` blocks that `podssh config import` prints
//! for them: a session's label becomes the block's name, made fit for a
//! `Host` line, and the label itself is said in a comment. What has no
//! keyword, or could hold a secret, is a comment with no value. A password
//! is counted, never imported and never printed.

use std::collections::BTreeSet;

use super::{setting, Blocks};

/// One saved session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    /// Its label in the program.
    pub label: String,
    /// Its folder, as the program shows it (`A/B`).
    pub folder: Option<String>,
    /// Its protocol, when it is not SSH: a comment, and no block.
    pub not_ssh: Option<String>,
    /// Why it has no block though it is SSH: a template, a placeholder.
    pub skipped: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub user: Option<String>,
    pub identity: Option<String>,
    pub jump: Option<String>,
    /// What was not imported, with no value of a secret.
    pub notes: Vec<String>,
}

/// What a reader found: the sessions, and the passwords it counted.
#[derive(Debug, Default)]
pub struct Read {
    pub sessions: Vec<Session>,
    pub secrets: usize,
}

/// A name that a `Host` line can hold, from a label: each run of other
/// characters is one `-`.
fn alias(label: &str) -> String {
    let mut name = String::new();
    for c in label.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            name.push(c);
        } else if !name.ends_with('-') {
            name.push('-');
        }
    }
    let name = name.trim_matches('-');
    if name.is_empty() {
        "session".to_string()
    } else {
        name.to_string()
    }
}

/// One line of text for a comment.
fn line(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// The `Host` blocks of `read`, the sessions of `program` in `file`.
pub fn write(read: &Read, program: &str, file: &str) -> Blocks {
    let mut b = Blocks { secrets: read.secrets, ..Blocks::default() };
    b.text.push_str(&format!("# The sessions of {program} in {file}, as podssh config import read them.\n"));
    let mut taken = BTreeSet::new();
    for s in &read.sessions {
        let label = line(&s.label);
        let place = s.folder.as_deref().map(|f| format!(" (in {})", line(f))).unwrap_or_default();
        if let Some(protocol) = &s.not_ssh {
            b.not_ssh += 1;
            b.text.push_str(&format!("\n# {label}{place}: {}, no SSH; no Host block\n", line(protocol)));
            continue;
        }
        let Some(host) = s.host.as_deref().filter(|h| !h.is_empty()) else {
            let why = s.skipped.as_deref().unwrap_or("no host");
            b.text.push_str(&format!("\n# {label}{place}: {}; no Host block\n", line(why)));
            continue;
        };
        if let Some(why) = &s.skipped {
            b.text.push_str(&format!("\n# {label}{place}: {}; no Host block\n", line(why)));
            continue;
        }
        let mut name = alias(&s.label);
        let base = name.clone();
        let mut n = 1;
        while !taken.insert(name.clone()) {
            n += 1;
            name = format!("{base}-{n}");
        }
        b.hosts += 1;
        b.text.push_str(&format!("\n# {label}{place}\nHost {name}\n"));
        let settings = [
            ("HostName", Some(host)),
            ("Port", s.port.as_deref().filter(|p| *p != "22")),
            ("User", s.user.as_deref()),
            ("IdentityFile", s.identity.as_deref()),
            ("ProxyJump", s.jump.as_deref()),
        ];
        for (keyword, value) in settings {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                setting(&mut b.text, keyword, value);
            }
        }
        for note in &s.notes {
            b.text.push_str(&format!("  # {}\n", line(note)));
        }
    }
    b
}

/// The text of a file of another program: UTF-16LE after its byte order
/// mark, UTF-8 (a mark dropped), else Windows-1252, as Windows programs
/// write it.
pub fn decode(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = (0..rest.len() / 2).map(|i| u16::from_le_bytes([rest[2 * i], rest[2 * i + 1]])).collect();
        return String::from_utf16_lossy(&units);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes.iter().map(|&b| windows_1252(b)).collect(),
    }
}

/// A byte of Windows-1252: Latin-1 but for 0x80 to 0x9F.
fn windows_1252(b: u8) -> char {
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž', '\u{8f}', '\u{90}', '‘',
        '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9d}', 'ž', 'Ÿ',
    ];
    match b {
        0x80..=0x9F => HIGH[(b - 0x80) as usize],
        _ => b as char,
    }
}

/// `%XX` decoded, as PuTTY escapes a session's name; the bytes as UTF-8.
pub fn unescape_percent(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        match (bytes[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A value that is the placeholder of a template: `%Host%`.
pub fn placeholder(value: &str) -> bool {
    value.len() > 2 && value.starts_with('%') && value.ends_with('%') && !value[1..value.len() - 1].contains('%')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_becomes_a_name_that_a_host_line_holds() {
        assert_eq!(alias("John Doe"), "John-Doe");
        assert_eq!(alias("MONGODB-ACCOUNT (DEV)"), "MONGODB-ACCOUNT-DEV");
        assert_eq!(alias("  *?  "), "session");
        assert_eq!(alias("web.example.org"), "web.example.org");
    }

    #[test]
    fn each_encoding_of_a_windows_export_reads() {
        let utf16: Vec<u8> =
            [0xFF, 0xFE].into_iter().chain("Ab\r\n".encode_utf16().flat_map(u16::to_le_bytes)).collect();
        assert_eq!(decode(&utf16), "Ab\r\n");
        assert_eq!(decode(b"\xEF\xBB\xBFAb"), "Ab");
        assert_eq!(decode(b"caf\xe9 \x80"), "café €");
        assert_eq!(unescape_percent("John%20Doe%2"), "John Doe%2");
        assert_eq!(unescape_percent("%E2%82%AC"), "€");
        assert!(placeholder("%Host%") && !placeholder("%") && !placeholder("50%") && !placeholder("%a%b%"));
    }
}
