//! `Match` lines against what OpenSSH 10.3p1's `ssh -G` did with the same
//! lines (measured 2026-10-11, offline: each block added an `IdentityFile`,
//! which showed the blocks that applied).

use super::*;

fn seen(host: &'static str) -> Seen<'static> {
    Seen {
        host,
        original: host,
        user: Some("me"),
        local_user: Some("me"),
        tag: "",
        command: "",
        session: "shell",
        final_pass: false,
    }
}

fn applies(value: &str, seen: &Seen) -> bool {
    evaluate(value, seen).unwrap_or_else(|e| panic!("{value}: {e}")).applies
}

#[test]
fn a_host_matches_with_no_regard_to_case_and_a_negated_pattern_excludes() {
    let s = seen("h");
    for (value, want) in [
        ("host h", true),
        ("host H", true),
        ("originalhost H", true),
        ("host x,h", true),
        ("host *,!h", false),
        ("!host h", false),
        ("!host x", true),
        ("Host h", true),
        ("host \"h\"", true),
        ("host=h", true),
        ("!host=x", true),
        ("host h,", true),
        ("host ,h", true),
        ("host h host x", false),
    ] {
        assert_eq!(applies(value, &s), want, "{value}");
    }
}

/// `host` is the name after `HostName`; `originalhost` the name as typed.
#[test]
fn host_is_the_name_after_host_name_and_originalhost_the_name_as_typed() {
    let s = Seen { host: "real.example", ..seen("h") };
    assert!(!applies("host h", &s));
    assert!(applies("host real.example", &s));
    assert!(applies("host REAL.example", &s));
    assert!(applies("originalhost h", &s));
}

#[test]
fn the_other_criteria_match_with_case() {
    let s = Seen { user: Some("alice"), tag: "t1", command: "ls -l", session: "exec", ..seen("h") };
    for (value, want) in [
        ("user alice", true),
        ("user Alice", false),
        ("user bob", false),
        ("localuser me", true),
        ("localuser alice", false),
        ("tagged t1", true),
        ("tagged \"\"", false),
        ("!tagged t1", false),
        ("command ls*", true),
        ("command \"ls -l\"", true),
        ("command \"\"", false),
        ("sessiontype exec", true),
        ("sessiontype shell", false),
        ("sessiontype default", false),
        ("version OpenSSH_10.3p1", true),
        ("version OpenSSH*", true),
        ("version OpenSSH_10.3", false),
        ("version 10.3p1", false),
        ("host h user alice", true),
        ("host h user bob", false),
        ("user=alice tagged=t1", true),
    ] {
        assert_eq!(applies(value, &s), want, "{value}");
    }
    // With no tag and no command, an empty pattern matches them.
    assert!(applies("tagged \"\"", &seen("h")));
    assert!(applies("command \"\"", &seen("h")));
}

#[test]
fn all_stands_alone_or_after_one_criterion() {
    let s = seen("h");
    assert!(applies("all", &s));
    assert!(!applies("!all", &s));
    assert!(applies("host h all", &s));
    assert!(!applies("host x all", &s));
    for value in ["all host h", "host h user me all", "all=x"] {
        let err = evaluate(value, &s).unwrap_err();
        assert!(err.contains("cannot be combined"), "{value}: {err}");
    }
}

/// `final` and `canonical` hold in the final pass alone; a `final` with no
/// `!` asks for that pass, also on a line whose other criterion fails.
#[test]
fn final_and_canonical_hold_in_the_final_pass_and_final_asks_for_it() {
    let first = seen("h");
    let last = Seen { final_pass: true, ..seen("h") };
    assert_eq!(evaluate("final", &first).unwrap(), Outcome { applies: false, wants_final: true });
    assert_eq!(evaluate("final", &last).unwrap(), Outcome { applies: true, wants_final: true });
    assert_eq!(evaluate("canonical", &first).unwrap(), Outcome { applies: false, wants_final: false });
    assert!(evaluate("canonical", &last).unwrap().applies);
    assert_eq!(evaluate("!final", &first).unwrap(), Outcome { applies: true, wants_final: false });
    assert!(!evaluate("!canonical", &last).unwrap().applies);
    assert_eq!(evaluate("host nomatch final", &first).unwrap(), Outcome { applies: false, wants_final: true });
    assert_eq!(evaluate("final host h", &last).unwrap(), Outcome { applies: true, wants_final: true });
}

/// `exec` and `localnetwork` are refused where they would decide, and
/// nothing runs; where another criterion fails, the block is off whatever
/// they would say.
#[test]
fn exec_and_localnetwork_are_refused_where_they_decide() {
    let s = seen("h");
    for (value, says) in [
        ("exec \"exit 1\"", "Match exec"),
        ("host h exec true", "Match exec"),
        ("!exec true", "Match exec"),
        ("exec true all", "Match exec"),
        ("localnetwork 10.0.0.0/8", "Match localnetwork"),
    ] {
        let err = evaluate(value, &s).unwrap_err();
        assert!(err.contains(says), "{value}: {err}");
    }
    assert!(!applies("host other exec true", &s));
    assert!(!applies("exec true host other", &s));
    assert!(!applies("final exec true", &s), "the first pass: final does not hold");
}

#[test]
fn a_criterion_needs_its_patterns_and_another_word_is_refused() {
    let s = seen("h");
    assert!(evaluate("host", &s).unwrap_err().contains("Match host needs patterns"));
    assert!(evaluate("", &s).unwrap_err().contains("needs a criterion"));
    assert!(evaluate("bogus x", &s).unwrap_err().contains("Match bogus: not a criterion"));
    // `=` alone is the pattern of host, and h a criterion with none.
    assert!(evaluate("host = h", &s).unwrap_err().contains("Match h needs patterns"));
    let no_one = Seen { user: None, local_user: None, ..seen("h") };
    assert!(evaluate("user x", &no_one).unwrap_err().contains("no user is known"));
    assert!(evaluate("localuser x", &no_one).unwrap_err().contains("not known"));
}
