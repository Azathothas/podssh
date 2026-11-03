//! The values of the `-o` keywords, as OpenSSH reads them: yes and no, a
//! port, seconds, words with their quotes, and the nearest keyword to an
//! unknown one (out of `options.rs`, for its length).

use crate::ssh::keywords;

pub fn yes_no(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

pub fn parse_port(value: &str) -> Option<u16> {
    value.trim().parse::<u16>().ok().filter(|p| *p != 0)
}

/// Whole seconds; the whole string must be a number (no `30x`).
pub(super) fn parse_seconds(value: &str) -> Option<u64> {
    let v = value.trim();
    let v = v.strip_suffix('s').unwrap_or(v);
    v.parse::<u64>().ok()
}

/// Space-separated values, as OpenSSH splits them: a space inside double
/// quotes belongs to its value, and the quotes go.
pub fn words(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word: Option<String> = None;
    let mut quoted = false;
    for c in value.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                word.get_or_insert_with(String::new);
            }
            c if c.is_whitespace() && !quoted => out.extend(word.take()),
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    out.extend(word);
    out
}

pub(super) fn unquote(value: &str) -> String {
    let v = value.trim();
    v.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(v).to_string()
}

/// "unknown option", naming the nearest known keyword when one is close.
pub(super) fn unknown(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let best = keywords::known_names()
        .map(|k| (distance(&lower, &k.to_ascii_lowercase()), k))
        .min_by_key(|(d, _)| *d)
        .filter(|(d, _)| *d <= 3);
    match best {
        Some((_, k)) => format!("-o {name}: unknown option; did you mean {k}?"),
        None => format!("-o {name}: unknown option"),
    }
}

/// Levenshtein distance, for suggestions only.
fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = (prev + usize::from(ca != *cb)).min(row[j] + 1).min(cur + 1);
            prev = cur;
        }
    }
    row[b.len()]
}
