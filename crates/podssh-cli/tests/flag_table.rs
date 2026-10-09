//! The flag tables in `src/flags.rs` are the CLI contract: `--help` and
//! `podssh man` are both rendered from them, so there is no second document to
//! keep in step.
//!
//! The expected `ssh` short-flag set is written out below on purpose. Adding or
//! removing an `ssh` flag must be a deliberate edit to that list, reviewed with
//! the code change. (A test that parses a line range of a document breaks
//! the test build whenever the document is edited, so this file reads no
//! document.)

use podssh_cli::flags::{FlagKind, VERBS};

/// Every short flag `podssh ssh` accepts or refuses by name: each flag of
/// OpenSSH 10.3p1's usage, as reviewed on 2026-10-08. Order does not matter.
const SSH_SHORT_FLAGS: &str = "plinJNstTeC46WEFvqVoxaPLRDABbkgcmfGIKMOSQwXYy";

#[test]
fn the_ssh_short_flags_are_exactly_the_reviewed_set() {
    let ssh = VERBS.iter().find(|v| v.name == "ssh").unwrap();
    let mut in_tree: Vec<char> = ssh.flags.iter().filter_map(|r| r.short).collect();
    let mut expected: Vec<char> = SSH_SHORT_FLAGS.chars().collect();
    in_tree.sort_unstable();
    expected.sort_unstable();
    assert_eq!(
        in_tree, expected,
        "the ssh short flags changed; if that is intended, update SSH_SHORT_FLAGS \
         in this file in the same change"
    );
}

/// Every letter of the usage of OpenSSH 10.3p1's `scp` and `sftp` (measured
/// on 2026-10-08, T-139): each has a row, so none is an unknown flag. Order
/// does not matter.
const SCP_SHORT_FLAGS: &str = "346ABCOpqRrsTvcDFiJloPSX";
const SFTP_SHORT_FLAGS: &str = "46AaCfNpqrvBbcDFiJloPRSsX";

#[test]
fn the_scp_and_sftp_short_flags_are_exactly_the_reviewed_sets() {
    for (name, reviewed) in [("scp", SCP_SHORT_FLAGS), ("sftp", SFTP_SHORT_FLAGS)] {
        let verb = VERBS.iter().find(|v| v.name == name).unwrap();
        let mut in_tree: Vec<char> = verb.flags.iter().filter_map(|r| r.short).collect();
        let mut expected: Vec<char> = reviewed.chars().collect();
        in_tree.sort_unstable();
        expected.sort_unstable();
        assert_eq!(in_tree, expected, "the {name} short flags changed; update the reviewed set in the same change");
    }
}

#[test]
fn no_short_flag_is_listed_twice_for_one_verb() {
    for v in VERBS {
        let mut seen: Vec<char> = Vec::new();
        for c in v.flags.iter().filter_map(|r| r.short) {
            assert!(!seen.contains(&c), "{}: -{c} appears twice", v.name);
            seen.push(c);
        }
    }
}

#[test]
fn a_flag_refuses_only_when_its_row_says_so() {
    // `FlagKind` alone decides refusal, so a row whose kind was flipped by
    // accident changes behaviour and this catches it. A refusal must also say
    // what to use instead; one that only says "no" is not actionable.
    for v in VERBS {
        for row in v.flags {
            match row.kind {
                FlagKind::Supported | FlagKind::Accepted => {
                    assert!(row.instead.is_none(), "{}/{} is usable but names a replacement", v.name, row.long)
                }
                FlagKind::Refused | FlagKind::NotInFirstRelease => assert!(
                    row.instead.is_some(),
                    "{}/{} is refused and must say what to use instead",
                    v.name,
                    row.long
                ),
            }
        }
    }
}

#[test]
fn the_forwarding_rows_name_w_only_where_it_helps() {
    // -L and -D need a local listener, so they are refused, and -W carries one
    // connection in the same direction. -R needs no local listener (the
    // server listens), and -W carries the other direction: its refusal names
    // neither.
    let ssh = VERBS.iter().find(|v| v.name == "ssh").unwrap();
    for name in ["forward-local", "dynamic-forward"] {
        let row = ssh.flags.iter().find(|r| r.long == name).unwrap();
        assert_eq!(row.kind, FlagKind::Refused, "{name}");
        assert_eq!(row.instead, Some("-W HOST:PORT"), "{name} must name -W");
    }
    let r = ssh.flags.iter().find(|r| r.long == "forward-remote").unwrap();
    assert_eq!(r.kind, FlagKind::Refused);
    assert_eq!(r.instead, Some("no flag"), "-R has nothing to use instead");
    assert!(r.help.contains("not implemented yet"), "{}", r.help);
    for word in ["-W", "never", "listen", "bind"] {
        assert!(!r.help.contains(word), "-R must not say {word}: {}", r.help);
    }
}

#[test]
fn every_verb_has_an_owner_so_no_verb_can_be_a_silent_stub() {
    // An unimplemented subcommand is a refusal naming it, never a stub that
    // exits 0. Dispatch refuses by looking the verb up in `VERB_OWNER`; verbs
    // with their own dispatch arm are listed in DISPATCHED. Dispatch
    // also treats a verb with no row as an internal error (non-zero), so this
    // test is the first line of defence, not the only one.
    const DISPATCHED: &[&str] = &[
        "ts", "proxy", "ssh", "doctor", "keygen", "man", "status", "node", "relay", "operator", "cp", "mv", "scp",
        "sftp", "pipe",
    ];
    let owner_names: Vec<&str> = podssh_cli::flags::VERB_OWNER.iter().map(|(n, _)| *n).collect();
    for v in VERBS {
        if DISPATCHED.contains(&v.name) {
            continue;
        }
        assert!(
            owner_names.contains(&v.name),
            "{} has no owner, so podssh would refuse it as an internal error",
            v.name
        );
    }
    // The reverse: an owner row for a verb that does not exist is dead code.
    for (name, _) in podssh_cli::flags::VERB_OWNER {
        assert!(VERBS.iter().any(|v| v.name == *name), "{name} has an owner but is not a verb");
    }
}

#[test]
fn every_alias_resolves_and_every_verb_has_at_least_its_own_name() {
    for v in VERBS {
        assert!(
            v.aliases.contains(&v.name),
            "{} does not list itself as an alias, so `podssh {}` would not resolve",
            v.name,
            v.name
        );
        for a in v.aliases {
            assert_eq!(
                podssh_cli::flags::verb_for(a).map(|x| x.name),
                Some(v.name),
                "alias {a} does not resolve to {}",
                v.name
            );
        }
    }
}
