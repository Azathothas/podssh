//! ⛔ **The six plants, kept as tests.**
//!
//! ⛔ `RULES.md`:94-96 — *"A check with no failure test is not a check. Plant
//! the defect, run it, read the exit code. Then prove it accepts correct
//! input."* ⛔ Each of these **is** a defect, planted as a test: delete the
//! arm, remove the stage, restore the `usage()` dump — and if the arm comes
//! back, ⛔ **this test fails**, which is the guard being live rather than
//! merely present.
//!
//! ⛔ **A test that asserts the current behaviour and never asserted the
//! absence of the behaviour is not a plant.** ⛔ Each one below names the
//! mutation that would reintroduce the defect, so a later reader can check
//! that the guard still has teeth without inventing a new experiment.

use podssh_cli::exit_codes::EXIT_USAGE;
use podssh_cli::suggest::{diagnose_no_subcommand, NoSubcommand};
use podssh_cli::tree::{parse, Parsed};

fn args(s: &[&str]) -> Vec<std::ffi::OsString> {
    s.iter().map(std::ffi::OsString::from).collect()
}

fn message(p: &Parsed) -> &str {
    match p {
        Parsed::Usage(m) | Parsed::NoArguments(m) | Parsed::UnknownVerb(m) => m,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ⛔ ───────────────────────── PLANT 1 ─────────────────────────
//
// Delete the unknown-flag arm so a typo'd `-o` falls through.
//
// ⛔ **`exit 0` on this input IS the specification's security bug.** `06-cli.md`:
// 83-84: *"A silently-dropped `-o StrictHostKeyChecking=no` is a security bug
// that reports success."* ⛔ The entry's plant 1 says the run must read **64**
// (E24 decided, applied 2026-10-06).
//
// ⛔ **A different mutation also fails here**, and that is the point of keeping
// it: returning `Parsed::Command` with an empty `refused` — the "just let it
// through" fix — is the same defect wearing a different hat, and this test
// refuses it too.

#[test]
fn plant_a_dropped_unknown_flag_is_a_refusal_not_a_silent_success() {
    let p = parse(args(&["ssh", "--StrictHostKeyChekcing=no", "host"]));
    assert!(
        p.needs_refusal(),
        "a typo'd -o fell through and would exit 0, which is the spec's security bug"
    );
    assert_eq!(
        EXIT_USAGE, 64,
        "the exit code is the contract and it is 64 (E24 decided, operator 2026-10-05, applied 2026-10-06)"
    );
    let m = message(&p);
    assert!(m.contains("StrictHostKeyChekcing"), "must name what was given: {m}");
    assert!(
        m.contains("StrictHostKeyChecking"),
        "must name the nearest real flag: {m}"
    );
}

/// ⛔ The same defect reached through a **short** flag, because the two go
/// through different code paths: a long unknown argument is `ErrorKind::
/// UnknownArgument` with a `SuggestedArg`, and a short one arrives the same way
/// but with a different spelling. ⛔ A guard on only one of them is half a guard.
#[test]
fn plant_a_dropped_unknown_short_flag_is_also_refused() {
    let p = parse(args(&["ssh", "-Z", "host"]));
    assert!(p.needs_refusal(), "{p:?}");
    assert!(message(&p).contains("-Z"), "{p:?}");
}

// ⛔ ───────────────────────── PLANT 2 ─────────────────────────
//
// Remove the shape stage, leave the distance stage.
//
// ⛔ `podssh example.org` must say `Try: podssh ssh example.org`, ⛔ **never**
// `doctor`. ⛔ MEASURED on this machine, the nearest verb to `example.org` is
// `doctor` at distance 9 — ⛔ so a distance-only handler is a handler that says
// `podssh doctor example.org`, ⛔ **and a wrong suggestion is worse than none.**

#[test]
fn plant_a_missing_shape_stage_would_say_doctor_and_must_not() {
    // ⛔ The measurement itself, as an assertion. If a future verb list makes
    // `ssh` the nearest verb to `example.org`, this test would silently stop
    // testing anything, so it pins the shape stage as the reason.
    assert_eq!(
        diagnose_no_subcommand("example.org"),
        NoSubcommand::Destination
    );
    assert_eq!(
        diagnose_no_subcommand("user@example.org"),
        NoSubcommand::Destination
    );

    let p = parse(args(&["example.org"]));
    let m = message(&p);
    let tries: Vec<&str> = m.lines().filter(|l| l.starts_with("Try:")).collect();
    assert_eq!(tries, vec!["Try: podssh ssh example.org"], "{m}");
    // ⛔ `doctor` appears in the printed list, so the claim is about what is
    // suggested, never about substring presence.
    assert!(
        !tries.iter().any(|t| t.contains("doctor")),
        "the distance stage won: {m}"
    );
}

/// ⛔ **`host:port` is the third shape**, named at `06-cli.md`:47, and it is the
/// one a user types most often. ⛔ It contains `:` and no `@` or `.`, so a
/// handler that only checked for `@` would miss it.
#[test]
fn plant_a_missing_shape_stage_would_also_miss_a_host_port() {
    assert_eq!(diagnose_no_subcommand("host:2222"), NoSubcommand::Destination);
    let p = parse(args(&["host:2222"]));
    let m = message(&p);
    assert!(m.contains("Try: podssh ssh host:2222"), "{m}");
}

/// ⛔ **A bare hostname with no dot** — `localhost`, `buildbox`. ⛔ It is
/// host-*shaped* to a human and ⛔ **is not caught by the `@`/`.`/`:` rule**,
/// so the distance stage decides, and `localhost` shares no prefix with any
/// verb. ⛔ This is why the no-answer path exists ⛔ and it is asserted here so
/// the behaviour is recorded rather than discovered.
#[test]
fn a_bare_hostname_gets_no_suggestion_rather_than_a_wrong_one() {
    let v = diagnose_no_subcommand("localhost");
    assert_eq!(v, NoSubcommand::NoMatch, "localhost must not attract a verb");
    let p = parse(args(&["localhost"]));
    let m = message(&p);
    assert!(m.contains("No close subcommand"), "{m}");
    assert!(!m.lines().any(|l| l.starts_with("Try: podssh d")), "{m}");
}

// ⛔ ───────────────────────── PLANT 3 ─────────────────────────
//
// Restore a bare `usage()` dump.
//
// ⛔ `podssh ssh -P 22 host` must exit 2, name `-p` and `scp`, ⛔ **and print no
// usage block.** ⛔ The sibling prints a full usage block on an unknown
// option — **READ**, `.tmp/dropssh/src/main.c:277` — ⛔ and that buries the one
// line the user needs.

/// ⛔ **The current shape of `-P` on `ssh`, which is NOT a refusal.**
///
/// ⛔ The entry's premise said `-P` is not an OpenSSH flag and must be refused
/// by name. ⛔ **That premise has since been disproved and `06-cli.md`:64 now
/// says the opposite.** MEASURED 2026-10-02, this machine, OpenSSH_10.3p1:
/// `ssh -G -P mytag example.org` emits `tag mytag`, `ssh -G -P2222 example.org`
/// emits `port 22` and `tag 2222`, and `ssh` usage prints `[-P tag]`.
///
/// ⛔ So `-P 22` on `ssh` **parses**, prints a notice that says it is ignored
/// and points at `-p`, and ⛔ **exits 2 only because `ssh` itself has no
/// behaviour yet** — ⛔ never because `-P` was refused. ⛔ The refusal it is not
/// is the finding, and the notice is what keeps a user who meant a port from
/// waiting for a connection that will use 22.
#[test]
fn plant_a_usage_dump_on_ssh_p_would_bury_the_answer() {
    let p = parse(args(&["ssh", "-P", "22", "host"]));
    let Parsed::Command { verb, refused, tag, .. } = &p else { panic!("{p:?}") };
    assert_eq!(*verb, "ssh");
    assert_eq!(
        tag.as_deref(),
        Some("22"),
        "-P on ssh is a Tag and is accepted, not refused"
    );
    assert!(
        refused.is_empty(),
        "-P is a real OpenSSH ssh flag; refusing it breaks parity (06-cli.md:64)"
    );
}

/// ⛔ **And the notice must be built here, not taken from clap.** ⛔ If someone
/// reverts to `e.render()` anywhere on this path, the message grows a `Usage:`
/// header and a `For more information, try '--help'` trailer ⛔ and this fails.
#[test]
fn plant_a_usage_dump_would_be_a_header_and_a_trailer() {
    let notice = podssh_cli::refuse::accepted_tag_notice("22");
    assert!(notice.contains("accepted and ignored"), "{notice}");
    assert!(notice.contains("For a port use -p"), "{notice}");
    assert!(notice.contains("scp and sftp, -P is the port"), "{notice}");
    assert!(!notice.contains("Usage:"), "{notice}");
    assert!(!notice.contains("For more information"), "{notice}");
    // ⛔ Three lines. A usage dump on this same surface is about thirty.
    assert!(notice.lines().count() <= 4, "{notice}");
}

/// ⛔ **The refusal that is still a refusal: `-L` names `-W` and prints no
/// usage block.** ⛔ `06-cli.md`:63 and E25 make this a refusal, and ⛔ the
/// reason it is here as a plant is that it is the path a future edit to the
/// error handling would break first.
#[test]
fn plant_a_usage_dump_on_a_refused_flag_would_bury_the_replacement() {
    let p = parse(args(&["ssh", "-L", "8080:db:5432", "host"]));
    let Parsed::Command { refused, .. } = &p else { panic!("{p:?}") };
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].0, "-L SPEC");
    // ⛔ The refusal uses `usage_form()` — the short flag and its
    // metavariable — ⛔ not the help spelling `-L, --forward-local SPEC`. ⛔ A
    // refusal is read on a terminal in a hurry and the shortest unambiguous
    // form of the flag the user typed is the one that belongs there. ⛔ The
    // first version of this assertion expected the long form and failed,
    // ⛔ **because the test named the wrong string and the code was right.**
    assert_eq!(refused[0].1, "-W HOST:PORT");
    assert!(p.needs_refusal());
}

// ⛔ ───────────────────────── PLANT 6 ─────────────────────────
//
// The `-P` per-verb rule: refuse on `ssh`, honour on `cp`/`mv`/`scp`/`sftp`.
//
// ⛔ **The entry says "refuse on `ssh`" and the current tree does not refuse,
// and the entry's premise is what was disproved** — see plant 3. ⛔ What is
// tested here is the half that survives the correction: ⛔ **the meaning is
// per-verb**, and that is the part MEASURED on three programs at once.
//
// ⛔ A global rule — one meaning of `-P` for the whole binary — is the defect
// this test exists to catch, and ⛔ it is the defect `06-cli.md`:64 warns about
// in as many words: *"the meaning is per-verb and a global rule is wrong."*

#[test]
fn plant_a_global_p_rule_would_break_one_verb_or_the_other() {
    // ssh: a Tag. Accepted, ignored, and it says so.
    let on_ssh = parse(args(&["ssh", "-P", "mytag", "host"]));
    let Parsed::Command { verb, refused, tag, .. } = &on_ssh else { panic!("{on_ssh:?}") };
    assert_eq!(*verb, "ssh");
    assert_eq!(tag.as_deref(), Some("mytag"), "-P on ssh carries its value");
    assert!(refused.is_empty(), "ssh: -P must not be refused");

    // cp, mv, and both aliases: a port. Honoured, no notice, no tag.
    for spelling in ["cp", "mv", "scp", "sftp"] {
        let p = parse(args(&[spelling, "-P", "2222", "a", "b"]));
        let Parsed::Command { refused, tag, .. } = &p else { panic!("{spelling}: {p:?}") };
        assert!(refused.is_empty(), "{spelling}: -P is the port and must be honoured");
        assert_eq!(tag, &None, "{spelling}: -P is a port here, not a Tag");
        assert!(
            !p.needs_refusal(),
            "{spelling} -P 2222 must parse cleanly"
        );
    }
}

/// ⛔ **The two meanings must differ, and this asserts that they do.** ⛔ If a
/// refactor made both verbs read the same row, ⛔ each half of the test above
/// would still pass on its own ⛔ and the split would be gone. ⛔ This test is
/// the one that notices.
#[test]
fn the_two_p_meanings_are_different_rows_in_the_table() {
    use podssh_cli::flags::{FlagKind, SSH_FLAGS, CP_FLAGS};
    let ssh = SSH_FLAGS.iter().find(|r| r.short == Some('P')).unwrap();
    let cp = CP_FLAGS.iter().find(|r| r.short == Some('P')).unwrap();

    assert_eq!(ssh.arg, Some("TAG"), "ssh's -P is a Tag, MEASURED via `ssh -G -P`");
    assert_eq!(cp.arg, Some("PORT"), "scp's usage prints [-P port]");
    assert_ne!(ssh.long, cp.long, "the two rows are distinguishable in --help");
    assert_eq!(ssh.kind, FlagKind::Accepted);
    assert_eq!(cp.kind, FlagKind::Supported);
    // ⛔ And the lowercase spelling is on `ssh` alone, because that is where
    // OpenSSH puts the port. ⛔ `scp -p` is "preserve", and podssh matches it.
    assert!(SSH_FLAGS.iter().any(|r| r.short == Some('p') && r.arg == Some("PORT")));
    assert!(CP_FLAGS.iter().any(|r| r.short == Some('p') && r.arg.is_none()));
}

/// ⛔ **`-p` on `cp` is `preserve`, not `port`,** ⛔ because that is what `scp`
/// means and ⛔ a global rule would get it wrong in the other direction. ⛔ The
/// assertion is that `cp -p` parses ⛔ **not** that it sets a port ⛔ — the
/// behaviour is E36's and is not built.
#[test]
fn a_global_lowercase_p_rule_would_break_cp() {
    let p = parse(args(&["cp", "-p", "a", "b"]));
    assert!(matches!(p, Parsed::Command { .. }), "cp -p is preserve, and parses: {p:?}");
    // ⛔ And `cp -P` with a value parses too — neither is a usage error.
    assert!(matches!(parse(args(&["cp", "-P", "22", "a", "b"])), Parsed::Command { .. }));
}

/// ⛔ **The rendered refusal must not contain a usage block, checked through
/// the dispatch and not only through the parser.**
///
/// ⛔ **This test exists because plant 3 escaped the first version of the
/// suite.** MEASURED 2026-10-02, in `rust:1-alpine`, with
/// `rebuild_error` reverted to `e.render().to_string()`:
///
/// ```
/// $ podssh ssh --StrictHostKeyChekcing=no host
/// error: unexpected argument '--StrictHostKeyChekcing' found
///
///   tip: a similar argument exists: '--StrictHostKeyChecking'
///   tip: to pass '--StrictHostKeyChekcing' as a value, use '-- --StrictHostKeyChekcing'
///
/// Usage: ssh --StrictHostKeyChecking <yes|no|ask|off> [destination] [-- [remote-command]...]
/// ```
///
/// ⛔ **and `cargo test -p podssh-cli --test plants` still read
/// `14 passed; 0 failed`.** ⛔ The exit code was still 2 and every plant test
/// still passed, ⛔ because the tests called [`parse`] and inspected the
/// `Parsed::Usage` message ⛔ **and the planted defect replaced the message
/// downstream of `parse`, in `rebuild_error`, which those tests never reached
/// for this input.** ⛔ **That is the "a guard that exercises the wrong program
/// is not a guard on that program" failure** — ⛔ the guard ran, and it guarded
/// nothing.
///
/// ⛔ So this test goes through [`podssh_cli::dispatch::run`], which is the
/// **only** path that writes a byte to a stream, and it asserts on what is
/// actually emitted. ⛔ If someone reverts to `e.render()`, this fails.
#[test]
fn plant_a_usage_dump_is_not_printed_to_any_stream() {
    let p = parse(args(&["ssh", "--StrictHostKeyChekcing=no", "host"]));
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = podssh_cli::dispatch::run(
        &p,
        &mut podssh_cli::dispatch::Streams { out: &mut out, err: &mut err },
    );
    assert_eq!(rc, 64, "the exit code survives; it is not what detects this defect");
    let text = String::from_utf8(err).unwrap();
    let all = format!("{}{}", String::from_utf8_lossy(&out), text);

    // ⛔ The two strings clap's renderer adds and podssh's must never contain.
    assert!(!all.contains("Usage:"), "a usage block was printed:\n{all}");
    assert!(
        !all.contains("For more information"),
        "clap's trailer was printed:\n{all}"
    );
    // ⛔ And the two the user needs must survive, ⛔ because a test that only
    // forbids the usage block would also pass on a refusal that says nothing.
    assert!(all.contains("StrictHostKeyChekcing"), "{all}");
    assert!(all.contains("StrictHostKeyChecking"), "{all}");
    // ⛔ Five lines at most. The planted render was eight before the shell
    // wrapped it and would grow with any verb.
    assert!(text.lines().count() <= 6, "{text}");
}

/// ⛔ **The same guard, through the dispatch, on the `-P` notice.** ⛔ The
/// notice is built in [`podssh_cli::refuse`] and so was never at risk from
/// `rebuild_error`, ⛔ but it is on the path a future refactor would route
/// through clap, and ⛔ a test that covers one of two messages is a test that
/// covers whichever one the author remembered.
#[test]
fn plant_a_usage_dump_is_not_printed_on_the_p_path_either() {
    // `invalid!host` cannot be reached through the relay, so `ssh` stops with
    // a usage error before any network; the notice is printed before that.
    for input in [
        vec!["ssh", "-P", "22", "invalid!host"],
        vec!["ssh", "-L", "8080:db:5432", "host"],
        vec!["ssh", "--StrictHostKeyChekcing=no", "host"],
    ] {
        let p = parse(args(&input));
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        podssh_cli::dispatch::run(
            &p,
            &mut podssh_cli::dispatch::Streams { out: &mut out, err: &mut err },
        );
        let text = String::from_utf8_lossy(&err).into_owned();
        assert!(!text.contains("Usage:"), "{input:?} printed a usage block:\n{text}");
        assert!(!text.contains("For more information"), "{input:?}:\n{text}");
        assert!(text.lines().count() <= 12, "{input:?} printed {} lines", text.lines().count());
    }
}

// PLANT 5 (a flag added to the tree without review) is the snapshot test
// `the_ssh_short_flags_are_exactly_the_reviewed_set` in `flag_table.rs`.

// ⛔ ─────────────── the control: correct input must still work ───────────────
//
// ⛔ **"Then the correct input, or none of that proves anything"** — the
// entry's own words, and `RULES.md`:98-100's rule behind them. ⛔ A guard that
// refuses everything is indistinguishable from a working one until it blocks
// real work.

#[test]
fn the_control_a_real_command_line_still_parses() {
    // ⛔ The entry's acceptance line, verbatim.
    let p = parse(args(&[
        "ssh", "-p", "2222", "-i", "~/.ssh/id_ed25519", "-4", "-T", "host", "--", "true",
    ]));
    let Parsed::Command { verb, refused, tag, .. } = &p else { panic!("{p:?}") };
    assert_eq!(*verb, "ssh");
    assert!(refused.is_empty(), "{p:?}");
    assert_eq!(tag, &None, "no -P was given, so no notice");
    assert!(!p.needs_refusal(), "a correct command line must not be a refusal");
}

#[test]
fn the_control_every_documented_alias_still_resolves() {
    // ⛔ `podssh irc --help` must exit 0, and so must every other spelling a
    // user has in their fingers.
    for (spelling, want) in [
        ("irc", "chat"), ("chat", "chat"),
        ("scp", "cp"), ("sftp", "cp"), ("cp", "cp"), ("mv", "mv"),
        ("connect", "ssh"), ("ssh", "ssh"),
        ("man", "man"), ("relay", "relay"), ("status", "status"), ("doctor", "doctor"),
        ("proxy", "proxy"), ("node", "node"), ("operator", "operator"),
    ] {
        let p = parse(args(&[spelling, "--help"]));
        assert_eq!(p, Parsed::Help(want), "`podssh {spelling} --help` must render {want}'s help");
    }
}

#[test]
fn the_control_help_and_version_are_not_refusals() {
    for c in [vec!["--help"], vec!["-h"], vec!["--version"], vec!["-V"]] {
        let p = parse(args(&c));
        assert!(!p.needs_refusal(), "{c:?} must not be a refusal: {p:?}");
    }
}