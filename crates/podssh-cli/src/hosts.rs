//! The hosts of a word (T-184): a comma list whose items take the braces of
//! bash, `PREFIX{A..B}SUFFIX` (a zero padding kept: `{01..12}`), with a step
//! as `{A..B..N}`, `{a,b,c}`, and each nested, in bash's order; and
//! `@NAME`, a group of the `[groups]` table of the settings file (T-048),
//! whose hosts are a word of the same kind and can name groups. Square
//! brackets stay an IPv6 literal (T-007): no pattern uses them.
//!
//! A word is expanded before anything connects, and each host it gives is
//! then checked as a destination is. More than [`MOST`] hosts, none, an
//! empty host, a range that runs backwards, or a group that the settings
//! do not have is a usage error (64). A fault in a group of the file is the
//! file's (78), with its line: a group that names itself, through others or
//! not, is one, and the file is refused as it is read.

use std::collections::BTreeMap;

use crate::relay_settings::Refusal;
use crate::settings::Value;

/// The most hosts that a word gives.
pub const MOST: usize = 1000;

/// The groups of the settings file: each name, and its hosts as written,
/// with the line `FILE:LINE` that gives them.
pub type Groups = BTreeMap<String, Value>;

/// Whether `word` is a pattern of hosts rather than one host: a comma, a
/// brace, or a group. No host name holds one of them.
pub fn is_pattern(word: &str) -> bool {
    word.contains([',', '{', '}']) || word.starts_with('@')
}

/// Where a fault is: in the word of the command line (64), or in a group
/// of the settings file (78).
enum Fault {
    Word(String),
    File(String),
}

/// Each host of `word`, in its order, each once.
pub fn expand(word: &str, groups: &Groups) -> Result<Vec<String>, Refusal> {
    let mut hosts = Vec::new();
    match add(word, groups, &mut Vec::new(), &mut hosts) {
        Ok(()) if hosts.is_empty() => Err(Refusal::usage(format!("{word:?} gives no host"))),
        Ok(()) => Ok(hosts),
        Err(Fault::Word(why)) => Err(Refusal::usage(format!("{word:?}: {why}"))),
        Err(Fault::File(why)) => Err(Refusal::config(why)),
    }
}

/// The one host of `word` for a command that logs in to one: the word
/// itself when it is no pattern; else the host that it gives, and a word
/// that gives more is refused (64), naming `podssh each`.
pub fn one(word: &str, groups: &Groups) -> Result<String, Refusal> {
    if !is_pattern(word) {
        return Ok(word.to_string());
    }
    let mut hosts = expand(word, groups)?;
    match hosts.len() {
        1 => Ok(hosts.remove(0)),
        n => Err(Refusal::usage(format!(
            "{word} gives {n} hosts, and this command takes one; podssh each runs a command on each: \
             podssh each '{word}' -- COMMAND"
        ))),
    }
}

/// The line `NAME HOSTS` of the `[groups]` table, read at `at`, into
/// `groups`. A name is letters, digits, `.`, `_` and `-`, not first a `.`
/// or a `-`; a name given twice, or one that is a setting, is refused.
pub fn group_line(groups: &mut Groups, name: &str, hosts: &str, at: &str) -> Result<(), String> {
    if !is_group_name(name) {
        return Err(format!("{at}: {name} is not the name of a group: letters, digits, ., _ and -"));
    }
    if crate::settings::KEYWORDS.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)) {
        return Err(format!("{at}: {name} is a setting: put the settings before [groups]"));
    }
    if let Some(first) = groups.get(name) {
        return Err(format!("{at}: the group {name} is given at {} already", first.at));
    }
    groups.insert(name.to_string(), Value { text: hosts.to_string(), at: at.to_string() });
    Ok(())
}

/// Each group of the file, expanded as a word would expand it: the first
/// fault, as the file's.
pub fn check_groups(groups: &Groups) -> Result<(), String> {
    for (name, value) in groups {
        match add(&format!("@{name}"), groups, &mut Vec::new(), &mut Vec::new()) {
            Ok(()) => {}
            Err(Fault::File(why)) => return Err(why),
            Err(Fault::Word(why)) => return Err(format!("{}: the group {name}: {why}", value.at)),
        }
    }
    Ok(())
}

fn is_group_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['.', '-'])
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Add the hosts of `word` to `hosts`, once each. `within` holds the groups
/// that this word is in, the outer first, to find a cycle.
fn add(word: &str, groups: &Groups, within: &mut Vec<String>, hosts: &mut Vec<String>) -> Result<(), Fault> {
    // A fault of this word: the command line's, or that of the group that
    // holds it, the last of `within`, which is the same until this returns.
    let holder = within.last().and_then(|name| groups.get(name).map(|v| (name.clone(), v.at.clone())));
    let fault = |why: String| match &holder {
        Some((name, at)) => Fault::File(format!("{at}: the group {name}: {why}")),
        None => Fault::Word(why),
    };
    for item in items(word).map_err(&fault)? {
        if let Some(name) = item.strip_prefix('@') {
            if within.iter().any(|n| n == name) {
                let mut cycle = within.clone();
                cycle.push(name.to_string());
                let at = groups.get(name).map(|v| v.at.clone()).unwrap_or_default();
                return Err(Fault::File(format!("{at}: the groups {} make a cycle", cycle.join(", "))));
            }
            if !groups.contains_key(name) {
                let known: Vec<&str> = groups.keys().map(String::as_str).collect();
                let have = if known.is_empty() { "none".to_string() } else { known.join(", ") };
                return Err(fault(format!("@{name}: no group of that name in the settings file, which has {have}")));
            }
            within.push(name.to_string());
            let added = add(&groups[name].text, groups, within, hosts);
            within.pop();
            added?;
            continue;
        }
        let mut words = Vec::new();
        braces(&item, &mut words).map_err(&fault)?;
        for host in words {
            if host.is_empty() {
                return Err(fault(format!("{item}: an empty host")));
            }
            if !hosts.contains(&host) {
                if hosts.len() == MOST {
                    return Err(Fault::Word(format!("more than {MOST} hosts")));
                }
                hosts.push(host);
            }
        }
    }
    Ok(())
}

/// The items of a word: split at each comma outside braces, and at blanks
/// as a group's line may have them; an empty item is refused.
fn items(word: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, c) in word.char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth == 0 => return Err("a } with no {".into()),
            '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&word[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth > 0 {
        return Err("a { with no }".into());
    }
    out.push(&word[start..]);
    let mut items = Vec::new();
    for item in out {
        if item.trim().is_empty() {
            return Err("an empty host; give HOST,HOST,...".into());
        }
        // Blanks outside braces part hosts too: `web1 web2` in a group.
        items.extend(split_blanks(item.trim())?);
    }
    Ok(items)
}

/// `text` split at blanks outside braces; a blank inside braces is refused.
fn split_blanks(text: &str) -> Result<Vec<String>, String> {
    let mut out = vec![String::new()];
    let mut depth = 0usize;
    for c in text.chars() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            c if c.is_whitespace() && depth > 0 => return Err(format!("{text}: a blank inside braces")),
            c if c.is_whitespace() => {
                if !out.last().is_some_and(String::is_empty) {
                    out.push(String::new());
                }
                continue;
            }
            _ => {}
        }
        out.last_mut().expect("one word at least").push(c);
    }
    out.retain(|w| !w.is_empty());
    Ok(out)
}

/// The words that the braces of `item` give, in bash's order, into `out`:
/// the first brace's alternatives, each with the rest of the item, each
/// expanded again. [`MOST`] words at most.
fn braces(item: &str, out: &mut Vec<String>) -> Result<(), String> {
    let Some(open) = item.find('{') else {
        if item.contains('}') {
            return Err(format!("{item}: a }} with no {{"));
        }
        out.push(item.to_string());
        return Ok(());
    };
    let close = matching(item, open).ok_or_else(|| format!("{item}: a {{ with no }}"))?;
    let (prefix, inner, suffix) = (&item[..open], &item[open + 1..close], &item[close + 1..]);
    for part in alternatives(inner)? {
        braces(&format!("{prefix}{part}{suffix}"), out)?;
        if out.len() > MOST {
            return Err(format!("{item} gives more than {MOST} hosts"));
        }
    }
    Ok(())
}

/// The place of the `}` that closes the `{` at `open`.
fn matching(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth == 1 => return Some(open + i),
            '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// What one pair of braces holds: a list `a,b,...` (at a comma outside
/// inner braces; an empty one gives the rest alone, as in bash), or a range.
fn alternatives(inner: &str) -> Result<Vec<String>, String> {
    if inner.is_empty() {
        return Err("{} holds nothing: give a list a,b or a range A..B".into());
    }
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, c) in inner.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(inner[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if !parts.is_empty() {
        parts.push(inner[start..].to_string());
        return Ok(parts);
    }
    range(inner).ok_or_else(|| format!("{{{inner}}} is neither a list a,b nor a range A..B"))?
}

/// `A..B` or `A..B..N`: of numbers, padded with zeros to the longer of A
/// and B when either starts with a 0, as bash pads them; or of letters.
/// `None` for anything else.
fn range(inner: &str) -> Option<Result<Vec<String>, String>> {
    let words: Vec<&str> = inner.split("..").collect();
    let (from, to, step) = match words[..] {
        [from, to] => (from, to, 1),
        [from, to, step] => (from, to, step.parse::<usize>().ok().filter(|s| *s > 0)?),
        _ => return None,
    };
    let backwards = || Err(format!("{{{inner}}} runs backwards: give {{{to}..{from}}}"));
    if let (Ok(a), Ok(b)) = (from.parse::<i64>(), to.parse::<i64>()) {
        if a > b {
            return Some(backwards());
        }
        let span = b.checked_sub(a).and_then(|s| usize::try_from(s).ok()).unwrap_or(usize::MAX);
        if span / step >= MOST {
            return Some(Err(format!("{{{inner}}} gives more than {MOST} hosts")));
        }
        let zeros = |w: &str| {
            let digits = w.trim_start_matches('-');
            digits.len() > 1 && digits.starts_with('0')
        };
        let width = if zeros(from) || zeros(to) { from.len().max(to.len()) } else { 0 };
        return Some(Ok((a..=b).step_by(step).map(|n| format!("{n:0width$}")).collect()));
    }
    let letter = |w: &str| w.len() == 1 && w.as_bytes()[0].is_ascii_alphabetic();
    if letter(from) && letter(to) {
        let (a, b) = (from.as_bytes()[0], to.as_bytes()[0]);
        if a > b {
            return Some(backwards());
        }
        return Some(Ok((a..=b).step_by(step).map(|c| char::from(c).to_string()).collect()));
    }
    None
}

#[cfg(test)]
#[path = "hosts_tests.rs"]
mod tests;
