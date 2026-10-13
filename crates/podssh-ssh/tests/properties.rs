//! Properties of `known_hosts` patterns and of the escape filter (T-202),
//! each checked on the inputs that proptest makes, 256 by default, and
//! shrunk to the smallest that fails: a negated pattern that matches
//! rejects the name, wherever it stands in the list; a hashed pattern made
//! from a name matches that name in any case; the case of the letters
//! changes no match; and the input of a session cut at any points gives the
//! same bytes and commands as the whole input.
//!
//! A property that fails writes its input to
//! `tests/properties.proptest-regressions`, committed with the repair:
//! proptest tries those inputs first at each run.

use podssh_ssh::escape::{Command, Escapes, ESCAPES};
use podssh_ssh::known_hosts::edit::hash_name;
use podssh_ssh::known_hosts::{matches, wildcard};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::FileFailurePersistence;

/// proptest's settings, 256 inputs unless `PROPTEST_CASES` says otherwise,
/// and a failing input kept beside this file.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    }
}

/// A name as podssh looks one up: a host, or `[host]:port` for a port that
/// is not 22, in either case.
fn name() -> impl Strategy<Value = String> {
    let host = "[a-zA-Z0-9][a-zA-Z0-9.-]{0,20}";
    prop_oneof![host.boxed(), (host, 1u16..).prop_map(|(host, port)| format!("[{host}]:{port}")).boxed()]
}

/// A pattern of a list: letters, digits, `.`, `-`, `_` and the wildcards,
/// negated or not.
fn pattern() -> impl Strategy<Value = String> {
    "!?[a-zA-Z0-9._*?-]{0,12}"
}

/// `text` with the case of each ASCII letter swapped where `flips` says.
fn flip_case(text: &str, flips: &[bool]) -> String {
    text.chars()
        .enumerate()
        .map(|(i, c)| match flips.get(i) {
            Some(true) if c.is_ascii_lowercase() => c.to_ascii_uppercase(),
            Some(true) => c.to_ascii_lowercase(),
            _ => c,
        })
        .collect()
}

/// A pattern made from `name` that matches it: each character kept, its
/// case swapped, or a `?`, as `marks` says, and a `*` for the rest of the
/// name from `star`, if given.
fn covering(name: &str, marks: &[u8], star: Option<usize>) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if star == Some(i) {
            out.push('*');
            return out;
        }
        match marks.get(i).copied().unwrap_or(0) % 3 {
            1 => out.push('?'),
            2 if c.is_ascii_lowercase() => out.push(c.to_ascii_uppercase()),
            2 => out.push(c.to_ascii_lowercase()),
            _ => out.push(c),
        }
    }
    out
}

proptest! {
    #![proptest_config(config())]

    /// A negated pattern that matches the name rejects it, whatever else in
    /// the list matches, and wherever it stands.
    #[test]
    fn a_negated_pattern_that_matches_rejects_the_name(
        name in name(),
        others in vec(pattern(), 0..5),
        at in any::<Index>(),
        marks in vec(any::<u8>(), 0..40),
        star in prop::option::of(any::<Index>()),
        positive in any::<bool>(),
    ) {
        let star = star.map(|s| s.index(name.chars().count()));
        let cover = covering(&name, &marks, star);
        prop_assert!(wildcard(cover.to_ascii_lowercase().as_bytes(), name.to_ascii_lowercase().as_bytes()), "{}", cover);
        let mut list = others;
        if positive {
            list.push(name.clone());
        }
        list.insert(at.index(list.len() + 1), format!("!{cover}"));
        let list = list.join(",");
        prop_assert!(!matches(&list, &name), "{:?} matched {:?}", list, name);
    }

    /// A hashed pattern, as `ssh-keygen -H` makes one from a name, matches
    /// that name in any case, and no other name.
    #[test]
    fn a_hashed_pattern_matches_its_name_in_any_case(
        name in name(),
        salt in any::<[u8; 20]>(),
        flips in vec(any::<bool>(), 0..40),
        other in name(),
    ) {
        let hashed = hash_name(&name, &salt);
        prop_assert!(matches(&hashed, &flip_case(&name, &flips)), "{} for {:?}", hashed, name);
        if !other.eq_ignore_ascii_case(&name) {
            prop_assert!(!matches(&hashed, &other), "{} for {:?} matched {:?}", hashed, name, other);
        }
    }

    /// The case of the letters, in the patterns or in the name, changes no
    /// match.
    #[test]
    fn the_case_of_the_letters_changes_no_match(
        name in name(),
        patterns in vec(pattern(), 0..5),
        marks in vec(any::<u8>(), 0..40),
        cover in any::<bool>(),
        flips_of_list in vec(any::<bool>(), 0..120),
        flips_of_name in vec(any::<bool>(), 0..40),
    ) {
        let mut patterns = patterns;
        if cover {
            patterns.push(covering(&name, &marks, None));
        }
        let list = patterns.join(",");
        let want = matches(&list, &name);
        prop_assert_eq!(matches(&flip_case(&list, &flips_of_list), &flip_case(&name, &flips_of_name)), want);
    }
}

/// The escape character of a session: `~`, `^]`, or any byte.
fn escape_char() -> impl Strategy<Value = u8> {
    prop_oneof![Just(b'~'), Just(0x1d), any::<u8>()]
}

/// Input of a session for `escape`: the escape character, line ends, and
/// the keys of the escapes, often; any byte besides.
fn input(escape: u8) -> impl Strategy<Value = Vec<u8>> {
    let keys: Vec<u8> = ESCAPES.iter().map(|(key, _, _)| *key).chain(*b"xa~").collect();
    let byte = prop_oneof![
        3 => Just(escape),
        3 => prop::sample::select(vec![b'\r', b'\n']),
        3 => prop::sample::select(keys),
        2 => any::<u8>(),
    ];
    vec(byte, 0..64)
}

/// `input` cut at `cuts`, each taken modulo its length plus one.
fn pieces<'a>(input: &'a [u8], cuts: &[Index]) -> Vec<&'a [u8]> {
    let mut at: Vec<usize> = cuts.iter().map(|c| c.index(input.len() + 1)).collect();
    at.extend([0, input.len()]);
    at.sort_unstable();
    at.dedup();
    at.windows(2).map(|pair| &input[pair[0]..pair[1]]).collect()
}

proptest! {
    #![proptest_config(config())]

    /// The input cut at any points gives the same bytes and commands as the
    /// whole input, read until a command that ends the session, as the
    /// session reads it.
    #[test]
    fn the_input_cut_anywhere_gives_the_same_bytes_and_commands(
        (escape, detach, input, cuts) in (escape_char(), any::<bool>())
            .prop_flat_map(|(escape, detach)| (Just(escape), Just(detach), input(escape), vec(any::<Index>(), 0..8))),
    ) {
        let whole = Escapes::new(escape).with_detach(detach).feed(&input);
        let mut escapes = Escapes::new(escape).with_detach(detach);
        let (mut out, mut commands) = (Vec::new(), Vec::new());
        for piece in pieces(&input, &cuts) {
            let (bytes, found) = escapes.feed(piece);
            out.extend(bytes);
            let end = found.iter().any(|c| matches!(c, Command::Disconnect | Command::Detach));
            commands.extend(found);
            if end {
                break;
            }
        }
        prop_assert_eq!((out, commands), whole);
    }

    /// Input with no escape character passes as it came, with no command.
    #[test]
    fn input_with_no_escape_character_passes_as_it_came(
        escape in escape_char(),
        input in vec(any::<u8>(), 0..64),
    ) {
        let input: Vec<u8> = input.into_iter().filter(|b| *b != escape).collect();
        let (out, commands) = Escapes::new(escape).with_detach(true).feed(&input);
        prop_assert_eq!(out, input);
        prop_assert!(commands.is_empty(), "{:?}", commands);
    }
}
