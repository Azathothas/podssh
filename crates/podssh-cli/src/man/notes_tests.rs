//! The tests of the notes: each name in a note exists, and a planted one is found.

use super::*;
use crate::flags::{verb_for, VERBS};
use crate::ssh::keywords;

/// The words of a note, split at spaces and at the punctuation around
/// names (but not at `-`, `_` or `=`).
fn words(note: &str) -> Vec<&str> {
    note.split(|c: char| c.is_whitespace() || "(),;:.'".contains(c)).filter(|w| !w.is_empty()).collect()
}

fn flag_exists(verb: &str, flag: &str) -> bool {
    let rows = |v: &str| verb_for(v).map(|v| v.flags).unwrap_or(&[]);
    let names = |r: &crate::flags::FlagRow| {
        let mut n = vec![format!("--{}", r.long)];
        if let Some(c) = r.short {
            n.push(format!("-{c}"));
        }
        n
    };
    // A note may also name a flag of ssh (OpenSSH's), and -tt is -t twice;
    // -KL, -KR and -KD are commands of the escape ~C (T-291), no flags.
    flag == "-tt"
        || flag == "--help"
        || flag == "--"
        || ["-KL", "-KR", "-KD"].contains(&flag)
        || rows(verb).iter().chain(rows("ssh")).any(|r| names(r).iter().any(|n| n == flag))
}

/// Flags of another program, which a note that names the program may
/// name too: the client that a note of `pipe` shows (T-483).
const OTHERS: &[(&str, &[&str])] = &[("curl", &["--unix-socket", "--proxy"])];

fn another_program_s(note: &str, flag: &str) -> bool {
    OTHERS.iter().any(|(program, flags)| note.contains(program) && flags.contains(&flag))
}

fn keyword_exists(name: &str) -> bool {
    let noted = keywords::NOTED.iter().map(|(k, _)| *k);
    let mut known = keywords::known_names().chain(keywords::IGNORED.iter().copied()).chain(noted);
    known.any(|k| k.eq_ignore_ascii_case(name))
}

fn problems() -> Vec<String> {
    let variables: Vec<&str> = super::super::facts::variables().flat_map(|(n, _)| n.iter().copied()).collect();
    let mut out = Vec::new();
    for verb in VERBS {
        for note in for_verb(verb.name) {
            out.extend(problems_in(verb.name, note, &variables));
        }
    }
    out
}

fn problems_in(verb: &str, note: &str, variables: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let words = words(note);
    for (i, &w) in words.iter().enumerate() {
        let flag_shaped = w.starts_with('-')
            && w.len() > 1
            && w.chars().nth(1).is_some_and(|c| c.is_ascii_alphanumeric() || c == '-');
        // "podssh node --derp" names a flag of node, not of this verb.
        let named = match (i.checked_sub(2).map(|j| words[j]), i.checked_sub(1).map(|j| words[j])) {
            (Some("podssh"), Some(other)) if verb_for(other).is_some() => other,
            _ => verb,
        };
        // The first word of a detached child (T-380) follows podssh, before any verb.
        let child = w == crate::detach::CHILD_FLAG && i.checked_sub(1).map(|j| words[j]) == Some("podssh");
        if flag_shaped && !w.contains('=') && !child && !flag_exists(named, w) && !another_program_s(note, w) {
            out.push(format!("{verb}: the flag {w} does not exist"));
        }
        // A variable given a value (NAME=yes) is a variable, not a keyword.
        let variable_shaped = |s: &str| s.contains('_') && s.chars().all(|c| c.is_ascii_uppercase() || c == '_');
        if let Some((name, _)) = w.split_once('=') {
            if variable_shaped(name) {
                if !variables.contains(&name) {
                    out.push(format!("{verb}: the variable {name} is not in ENVIRONMENT"));
                }
            } else if name.starts_with(|c: char| c.is_ascii_uppercase()) && !keyword_exists(name) {
                out.push(format!("{verb}: the keyword {name} does not exist"));
            }
        }
        if variable_shaped(w) && !variables.contains(&w) {
            out.push(format!("{verb}: the variable {w} is not in ENVIRONMENT"));
        }
    }
    out
}

/// The note of what podssh reads from the terminal names each escape of
/// the code, and no other (T-130): `~` and a key, with `~~`.
#[test]
fn the_terminal_note_names_each_escape() {
    let note = for_verb("ssh").iter().find(|n| n.contains("passes unchanged")).expect("the terminal's note");
    let named: std::collections::BTreeSet<char> = note
        .as_bytes()
        .windows(2)
        .filter(|w| w[0] == b'~' && w[1].is_ascii_graphic() && !b",;)".contains(&w[1]))
        .map(|w| w[1] as char)
        .collect();
    let mut escapes: std::collections::BTreeSet<char> =
        podssh_ssh::escape::ESCAPES.iter().map(|(key, ..)| *key as char).collect();
    escapes.insert('~');
    assert_eq!(named, escapes, "the note: {note}");
}

/// The note about -R says that the server listens (T-035), and neither
/// borrows the cause of -L and -D nor offers -W.
#[test]
fn the_note_about_r_says_that_the_server_listens() {
    let sentences: Vec<&str> =
        for_verb("ssh").iter().flat_map(|n| n.split(". ")).filter(|s| s.contains("-R")).collect();
    assert!(!sentences.is_empty(), "{sentences:#?}");
    assert!(sentences[0].contains("asks the server to listen"), "{}", sentences[0]);
    for sentence in sentences {
        for word in ["never", "local listener", "-W", "not implemented"] {
            assert!(!sentence.contains(word), "{word}: {sentence}");
        }
    }
}

#[test]
fn each_name_in_a_note_exists() {
    let p = problems();
    assert!(p.is_empty(), "{p:#?}");
}

/// The control: a note with a dropped flag, keyword or variable fails.
#[test]
fn a_planted_name_is_found() {
    let variables = ["SSH_ASKPASS"];
    let p = problems_in("ssh", "use --no-such-flag, -o NoSuchKeyword=yes, NO_SUCH_VAR and NO_SUCH_SET=yes", &variables);
    assert_eq!(p.len(), 4, "{p:#?}");
    assert!(problems_in("ssh", "use -W HOST:PORT, BatchMode=yes, SSH_ASKPASS=x and SSH_ASKPASS", &variables).is_empty());
    // Another verb's flag counts only after "podssh VERB", and as that verb's.
    assert!(problems_in("ssh", "see podssh node --derp", &variables).is_empty());
    assert_eq!(problems_in("ssh", "see --derp", &variables).len(), 1);
    assert_eq!(problems_in("ssh", "see podssh node --no-such-flag", &variables).len(), 1);
    // A detached child's first word, after podssh alone (T-380).
    assert!(problems_in("ssh", "as podssh --detach-child ssh", &variables).is_empty());
    assert_eq!(problems_in("ssh", "as --detach-child", &variables).len(), 1);
    // Another program's flag only in a note that names the program.
    assert!(problems_in("pipe", "curl's --unix-socket goes past its --proxy", &variables).is_empty());
    assert_eq!(problems_in("pipe", "a client's --unix-socket", &variables).len(), 1);
}
