//! The ids that a harness can print, read from its source (T-199): the first
//! argument of each check helper at a command position of a shell script,
//! with the loop variables that it names expanded over their literal lists;
//! and the literal first argument of `check(` in a Python harness. The reader
//! knows as much sh as the harnesses use: quotes, escapes, comments,
//! continuations, heredocs and the operators that start a command.

use std::collections::BTreeMap;

use crate::model::Problem;

/// The helpers that can print `ok` for their id, and those that can print
/// `FAIL`; `expect_rc` and `no_part` print one or the other.
const PASS: &[&str] = &["ok", "expect_rc", "no_part"];
const FAIL: &[&str] = &["bad", "expect_rc", "no_part"];
/// The helpers that print `skip` or `env`, and neither of the two above.
const OTHER: &[&str] = &["skipped", "unmet"];

/// The words after which a word starts a command.
const STARTERS: &[&str] = &["then", "else", "do", "{", "!", "if", "elif", "while", "until"];

/// What a harness can print for one id, and the first line that names it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Emits {
    pub line: usize,
    pub pass: bool,
    pub fail: bool,
}

/// Each id of a harness.
pub type Ids = BTreeMap<String, Emits>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Op(&'static str),
    Newline,
}

/// The tokens of a shell script, each with its line. A heredoc's body is left
/// out, and so is each comment.
fn tokens(text: &str) -> Vec<(usize, Tok)> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let (mut i, mut line, mut word_line) = (0, 1, 1);
    let mut word: Option<String> = None;
    let flush = |word: &mut Option<String>, out: &mut Vec<(usize, Tok)>, at: usize| {
        if let Some(w) = word.take() {
            out.push((at, Tok::Word(w)));
        }
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' if chars.get(i + 1) == Some(&'\n') => {
                i += 2;
                line += 1;
                continue;
            }
            '\\' => {
                if word.is_none() {
                    word_line = line;
                }
                let w = word.get_or_insert_with(String::new);
                if let Some(&next) = chars.get(i + 1) {
                    w.push(next);
                }
                i += 2;
                continue;
            }
            '\'' | '"' => {
                if word.is_none() {
                    word_line = line;
                }
                let w = word.get_or_insert_with(String::new);
                i += 1;
                while i < chars.len() && chars[i] != c {
                    if c == '"' && chars[i] == '\\' && i + 1 < chars.len() && "\"\\$`".contains(chars[i + 1]) {
                        i += 1;
                    }
                    if chars[i] == '\n' {
                        line += 1;
                    }
                    w.push(chars[i]);
                    i += 1;
                }
                i += 1;
                continue;
            }
            '#' if word.is_none() => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            ' ' | '\t' | '\r' => flush(&mut word, &mut out, word_line),
            '\n' => {
                flush(&mut word, &mut out, word_line);
                // Each heredoc named on this line, in order: its body is no
                // shell. `<<<` is a string, not a heredoc.
                let heredocs: Vec<(String, bool)> = out
                    .iter()
                    .rev()
                    .take_while(|(_, t)| *t != Tok::Newline)
                    .filter_map(|(_, t)| match t {
                        Tok::Word(w) => w.strip_prefix("<<").filter(|r| !r.starts_with('<')),
                        _ => None,
                    })
                    .map(|r| match r.strip_prefix('-') {
                        Some(d) => (d.to_string(), true),
                        None => (r.to_string(), false),
                    })
                    .filter(|(d, _)| !d.is_empty() && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                    .collect();
                out.push((line, Tok::Newline));
                line += 1;
                i += 1;
                for (delim, dash) in heredocs.into_iter().rev() {
                    while i < chars.len() {
                        let end = chars[i..].iter().position(|&c| c == '\n').map_or(chars.len(), |p| i + p);
                        let body: String = chars[i..end].iter().collect();
                        i = end + 1;
                        line += 1;
                        let body = if dash { body.trim_start_matches('\t') } else { body.as_str() };
                        if body.trim_end_matches('\r') == delim {
                            break;
                        }
                    }
                }
                continue;
            }
            ';' | '&' | '|' | '(' | ')' => {
                flush(&mut word, &mut out, word_line);
                let two: String = chars[i..chars.len().min(i + 2)].iter().collect();
                let op = match two.as_str() {
                    "&&" => "&&",
                    "||" => "||",
                    ";;" => ";;",
                    _ => match c {
                        ';' => ";",
                        '&' => "&",
                        '|' => "|",
                        '(' => "(",
                        _ => ")",
                    },
                };
                out.push((line, Tok::Op(op)));
                i += op.len();
                continue;
            }
            _ => {
                if word.is_none() {
                    word_line = line;
                }
                word.get_or_insert_with(String::new).push(c);
            }
        }
        i += 1;
    }
    flush(&mut word, &mut out, word_line);
    out
}

/// A loop `for NAME in WORDS; do` and its line.
struct Loop {
    line: usize,
    name: String,
    words: Vec<String>,
}

/// The ids of a shell script.
pub fn shell(file: &str, text: &str, problems: &mut Vec<Problem>) -> Ids {
    let toks = tokens(text);
    let mut loops: Vec<Loop> = Vec::new();
    let mut sites: Vec<(usize, &str, String)> = Vec::new();
    let mut start = true;
    for (k, (line, tok)) in toks.iter().enumerate() {
        let next_word = |n: usize| match toks.get(k + n) {
            Some((_, Tok::Word(w))) => Some(w.as_str()),
            _ => None,
        };
        let was_start = start;
        start = match tok {
            Tok::Newline | Tok::Op(_) => true,
            Tok::Word(w) => STARTERS.contains(&w.as_str()),
        };
        let Tok::Word(w) = tok else { continue };
        if !was_start {
            continue;
        }
        if w == "for" && next_word(2) == Some("in") {
            let name = next_word(1).unwrap_or_default().to_string();
            let words: Vec<String> = toks[k + 3..]
                .iter()
                .take_while(|(_, t)| matches!(t, Tok::Word(_)))
                .filter_map(|(_, t)| if let Tok::Word(w) = t { Some(w.clone()) } else { None })
                .collect();
            loops.push(Loop { line: *line, name, words });
        }
        let helper = PASS.iter().chain(FAIL).chain(OTHER).find(|h| **h == w.as_str());
        let (Some(helper), false) = (helper, toks.get(k + 1).map(|(_, t)| t) == Some(&Tok::Op("("))) else {
            continue;
        };
        match next_word(1) {
            // A helper that passes its caller's id on.
            Some(id) if id.starts_with('$') && !id.starts_with("${") => {}
            Some(id) => sites.push((*line, helper, id.to_string())),
            None => problems.push(Problem::new(file, *line, format!("`{helper}` with no id"))),
        }
    }
    let mut ids = Ids::new();
    for (line, helper, template) in sites {
        for id in expand(file, line, &template, &loops, problems) {
            let e = ids.entry(id).or_insert_with(|| Emits { line, ..Emits::default() });
            e.pass |= PASS.contains(&helper);
            e.fail |= FAIL.contains(&helper);
        }
    }
    ids
}

/// The ids of a template: each `${NAME}` (the loop's word) and `${NAME%%:*}`
/// (the word up to its first `:`) over the literal list of the nearest loop
/// `for NAME in` above it.
fn expand(file: &str, line: usize, template: &str, loops: &[Loop], problems: &mut Vec<Problem>) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut rest = template;
    while let Some(at) = rest.find('$') {
        let lit = &rest[..at];
        out.iter_mut().for_each(|o| o.push_str(lit));
        let after = &rest[at..];
        let Some(close) = after.strip_prefix("${").and_then(|a| a.find('}')) else {
            problems.push(Problem::new(file, line, format!("the id {template:?} names a `$` that is not ${{NAME}}")));
            return Vec::new();
        };
        let inner = &after[2..2 + close];
        let (name, label) = match inner.strip_suffix("%%:*") {
            Some(name) => (name, true),
            None => (inner, false),
        };
        let Some(lp) = loops.iter().rev().find(|l| l.name == name && l.line <= line) else {
            problems.push(Problem::new(file, line, format!("the id {template:?} names ${name}, of no loop above it")));
            return Vec::new();
        };
        let mut next = Vec::new();
        for word in &lp.words {
            let value = if label { word.split(':').next().unwrap_or_default() } else { word.as_str() };
            if value.contains(['$', '`', '*', '?', '[']) {
                let what = format!("the loop of ${name} at line {} has a word that is not literal: {word:?}", lp.line);
                problems.push(Problem::new(file, line, what));
                return Vec::new();
            }
            next.extend(out.iter().map(|o| format!("{o}{value}")));
        }
        out = next;
        rest = &after[3 + close..];
    }
    out.iter_mut().for_each(|o| o.push_str(rest));
    out
}

/// The ids of a Python harness: the literal first argument of each `check(`.
pub fn python(file: &str, text: &str, problems: &mut Vec<Problem>) -> Ids {
    let mut ids = Ids::new();
    for (i, raw) in text.lines().enumerate() {
        let code = raw.split('#').next().unwrap_or_default();
        let mut from = 0;
        while let Some(at) = code[from..].find("check(") {
            let at = from + at;
            from = at + 6;
            let before = code[..at].trim_end();
            if before.ends_with("def") || code[..at].ends_with(|c: char| c.is_alphanumeric() || c == '_' || c == '.') {
                continue;
            }
            let arg = code[from..].trim_start();
            let Some(q) = arg.chars().next().filter(|q| *q == '"' || *q == '\'') else {
                problems.push(Problem::new(file, i + 1, "`check(` with an id that is not a literal string"));
                continue;
            };
            let Some(end) = arg[1..].find(q) else { continue };
            let e = ids.entry(arg[1..1 + end].to_string()).or_insert_with(|| Emits { line: i + 1, ..Emits::default() });
            e.pass = true;
            e.fail = true;
        }
    }
    ids
}
