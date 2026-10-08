//! ⛔ **Plant 6 as a test: the binary's stdout must be empty on every refusal.**
//!
//! ⛔ **This file exists because the unit suite could not see the defect.** ⛔
//! MEASURED 2026-10-02, in `rust:1-alpine`, with a single `println!` added to
//! the `UnknownVerb` arm of `dispatch::run`:
//!
//! ```
//! $ podssh example.org 2>/dev/null | wc -c
//! 770
//! ```
//!
//! ⛔ **and `cargo test -p podssh-cli` read `34 passed` and `17 passed`, 0
//! failed.** ⛔ The unit tests call [`podssh_cli::dispatch::run`] with an
//! in-memory [`podssh_cli::dispatch::Streams`] pair, ⛔ **and a `println!` does
//! not go through `Streams` at all** — it goes to the process's real stdout.
//! ⛔ So the test asserted on a channel the defect never touched, ⛔ and it
//! passed while the binary was broken.
//!
//! ⛔ That is [`RULES.md`](../../../RULES.md):96's rule reached from the other
//! direction: *"A guard that exercises the wrong program is not a guard on that
//! program."* ⛔ And it is the **second** time in this entry that a green suite
//! was reading a planted defect without noticing ⛔ (plant 3 did the same, in
//! `plants.rs`), ⛔ so this test runs the actual executable through
//! [`std::process::Command`] ⛔ and reads the real file descriptors.
//!
//! ⛔ `env!("CARGO_BIN_EXE_podssh")` is set by `cargo` for integration tests and
//! is the only way to get the binary's path without depending on `target/`
//! layout, ⛔ which differs between the host and the build image.

use std::process::{Command, Stdio};

/// Run the real `podssh` with `args`, and return `(exit, stdout, stderr)`.
///
/// ⛔ `Stdio::piped()` on both, ⛔ **and the child's stdout and stderr are two
/// separate pipes** — ⛔ which is the whole point: a `println!` shows up in
/// `stdout` and nowhere else, and mixing them would hide exactly the defect
/// this file exists to catch.
fn podssh(args: &[&str]) -> (i32, Vec<u8>, Vec<u8>) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(args)
        // No test may reach the network: a verb that would connect stops here.
        .env("PODSSH_OFFLINE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the podssh binary must be runnable by an integration test");
    (out.status.code().unwrap_or(-1), out.stdout, out.stderr)
}

/// ⛔ **Plant 6.** Every refusal writes to stderr and **nothing at all** to
/// stdout. ⛔ `06-cli.md`:251-252 requires it, and the acceptance is the byte
/// count `podssh example.org 2>/dev/null | wc -c`.
#[test]
fn a_refusal_writes_nothing_to_stdout() {
    let cases: Vec<Vec<&str>> = vec![
        vec![],
        vec!["example.org"],
        vec!["user@example.org"],
        vec!["host:2222"],
        vec!["localhost"],
        vec!["sttaus"],
        vec!["chatr"],
        vec!["xz"],
        vec!["nonsense"],
        vec!["ssh", "--StrictHostKeyChekcing=no", "host"],
        vec!["ssh", "-Z", "host"],
        vec!["ssh", "-L", "8080:db:5432", "host"],
        vec!["ssh", "-P", "22", "host"],
        vec!["--bogus"],
        vec!["-Z"],
        vec!["cp", "a"],
        vec!["man", "ssh", "extra"],
    ];
    for c in cases {
        let (rc, out, err) = podssh(&c);
        // ⛔ **Not `assert_eq!(rc, 2)`.** ⛔ `ssh -P 22 host` is in this list and
        // it exits **255**, ⛔ because `-P` is accepted and the connection is
        // what fails (here at `PODSSH_OFFLINE`, before any network).
        // ⛔ The first version of this test asserted 2 for every case and
        // failed on that row, ⛔ **because the test conflated "writes nothing to
        // stdout" with "is a usage error"**, ⛔ and the two are different
        // contracts. ⛔ What matters here is non-zero and empty stdout.
        assert_ne!(rc, 0, "podssh {c:?} exited 0 having refused nothing");
        assert!(
            out.is_empty(),
            "podssh {c:?} wrote {} bytes to stdout; a refusal must write none.\n\
             stdout was:\n{}",
            out.len(),
            String::from_utf8_lossy(&out)
        );
        assert!(
            !err.is_empty(),
            "podssh {c:?} wrote nothing at all; the user is told nothing"
        );
    }
}

/// ⛔ **The acceptance line, run as written.** ⛔
/// `podssh example.org 2>/dev/null | wc -c` must read **0**, and ⛔ this
/// asserts the same thing through the binary rather than through a shell ⛔ so
/// it runs in CI on a host with no `podssh` on `PATH`.
#[test]
fn the_acceptance_byte_count_is_zero() {
    let (_, out, _) = podssh(&["example.org"]);
    assert_eq!(
        out.len(),
        0,
        "the acceptance asserts `podssh example.org 2>/dev/null | wc -c` is 0"
    );
}

/// ⛔ **And the control: help and version are the answer, so they DO go to
/// stdout.** ⛔ A suite that only ever asserts "stdout is empty" is satisfied by
/// a binary that prints nothing at all, ⛔ and that binary would break every
/// user who types `podssh --help`.
#[test]
fn the_control_help_and_version_do_reach_stdout() {
    for c in [vec!["--help"], vec!["-h"], vec!["--version"], vec!["ssh", "--help"], vec!["irc", "--help"]] {
        let (rc, out, _) = podssh(&c);
        assert_eq!(rc, 0, "podssh {c:?} should succeed");
        assert!(
            !out.is_empty(),
            "podssh {c:?} wrote nothing to stdout; help and version are the answer"
        );
    }
}

/// ⛔ **The entry's control lines, run against the binary.** ⛔ Each names the
/// exit code it expects and asserts it, ⛔ because a message that is right in a
/// test harness and wrong in the binary is the failure mode this file exists to
/// rule out.
#[test]
fn the_entrys_control_lines_exit_as_documented() {
    // sttaus -> 64, naming status
    let (rc, _, err) = podssh(&["sttaus"]);
    assert_eq!(rc, 64);
    let err = String::from_utf8_lossy(&err);
    assert!(err.contains("Try: podssh status"), "{err}");

    // chatr -> 64, naming chat
    let (rc, _, err) = podssh(&["chatr"]);
    assert_eq!(rc, 64);
    let err = String::from_utf8_lossy(&err);
    assert!(err.contains("Try: podssh chat"), "{err}");

    // irc --help -> 0, the alias resolves
    let (rc, out, _) = podssh(&["irc", "--help"]);
    assert_eq!(rc, 0, "the alias must resolve");
    assert!(String::from_utf8_lossy(&out).contains("podssh chat"));

    // example.org -> 64, naming ssh, never doctor
    let (rc, _, err) = podssh(&["example.org"]);
    assert_eq!(rc, 64);
    let err = String::from_utf8_lossy(&err);
    assert!(err.contains("Try: podssh ssh example.org"), "{err}");
    let tries: Vec<&str> = err.lines().filter(|l| l.starts_with("Try:")).collect();
    assert_eq!(tries, vec!["Try: podssh ssh example.org"], "{err}");
}

/// ⛔ **The `-P` split, against the binary.** ⛔ `ssh -P` exits non-zero ⛔
/// because the connection fails (the suite runs offline), ⛔ **not** because
/// `-P` was refused ⛔
/// and the notice must be on stderr either way. ⛔ `cp -P 2222 a b` exits
/// non-zero for the same reason ⛔ and **must not print a notice**, because
/// there `-P` is the port and there is nothing surprising to say.
#[test]
fn the_p_split_is_visible_in_the_binarys_output() {
    let (rc, out, err) = podssh(&["ssh", "-P", "22", "host"]);
    assert_ne!(rc, 0);
    assert!(out.is_empty(), "ssh -P wrote to stdout: {out:?}");
    let err = String::from_utf8_lossy(&err);
    assert!(err.contains("accepted and ignored"), "{err}");
    assert!(err.contains("For a port use -p"), "{err}");

    // A verb that is not implemented says so before the `--timeout` gate
    // (GitHub #6): a piped `cp` with no `--timeout` exits 70, not 64, and
    // asks for no flag that would change nothing.
    let (rc, out, err) = podssh(&["cp", "-P", "2222", "a", "b"]);
    let text = String::from_utf8_lossy(&err);
    assert_eq!(rc, 70, "cp is not implemented, also with no --timeout: {text}");
    assert!(out.is_empty(), "cp -P wrote to stdout: {out:?}");
    assert!(text.contains("not implemented yet") && !text.contains("--timeout"), "{text}");

    let (rc, out, err) = podssh(&["cp", "-P", "2222", "a", "b", "--timeout", "30s"]);
    assert_ne!(rc, 0, "cp is not built, so it refuses; that is E36's clause");
    assert!(out.is_empty(), "cp -P wrote to stdout: {out:?}");
    let err = String::from_utf8_lossy(&err);
    assert!(
        !err.contains("accepted and ignored"),
        "on cp, -P is the port and there is nothing to warn about: {err}"
    );
    assert!(err.contains("not implemented yet"), "{err}");
}

/// ⛔ **No usage block, anywhere, from the real binary.** ⛔ Plant 3 in its
/// strongest form: ⛔ `clap`'s renderer adds a `Usage:` header and a
/// `For more information, try '--help'` trailer, and the unit tests call
/// `parse()` and never see them ⛔ because the render happens in `rebuild_error`
/// and the render is what `dispatch` prints.
#[test]
fn no_invocation_prints_a_usage_block() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["ssh", "--StrictHostKeyChekcing=no", "host"],
        vec!["ssh", "-Z", "host"],
        vec!["ssh", "--prot", "2222", "host"],
        vec!["example.org"],
        vec!["sttaus"],
        vec![],
    ];
    for c in cases {
        let (rc, out, err) = podssh(&c);
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&err)
        );
        assert!(!all.contains("Usage:"), "podssh {c:?} printed a usage block:\n{all}");
        assert!(
            !all.contains("For more information"),
            "podssh {c:?} printed clap's trailer:\n{all}"
        );
        assert_ne!(rc, 0, "podssh {c:?} must be a refusal");
    }
}
/// ⛔ **A wrong number of arguments is never reported as an unknown flag.**
///
/// ⛔ `clap` puts a positional's *usage string* in the same context key it puts
/// an unknown flag's name in, so the fallback arm turned a missing argument into
/// `podssh: unknown flag '[paths] [paths]...'` — a message about a flag the user
/// never typed. ⛔ The two refusals are different and the user's next move
/// depends on which one it is: add the argument, or stop passing one.
#[test]
fn a_positional_that_does_not_fit_is_not_reported_as_an_unknown_flag() {
    for (case, want) in [
        (vec!["cp", "a"], "the right number of arguments was not given"),
        (vec!["man", "ssh", "extra"], "'extra' is not an argument this verb takes"),
    ] {
        let (rc, out, err) = podssh(&case);
        let text = String::from_utf8_lossy(&err);
        assert_eq!(rc, 64, "podssh {case:?}: {text}");
        assert!(out.is_empty(), "podssh {case:?} wrote to stdout: {out:?}");
        assert!(
            text.contains(want),
            "podssh {case:?} must say what was wrong: {text}"
        );
        assert!(
            !text.contains("unknown flag"),
            "podssh {case:?} blamed a flag nobody typed: {text}"
        );
    }
}
