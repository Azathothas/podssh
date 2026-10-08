//! ⛔ **E32's acceptance, against the real binary.** ⛔ `docs/TODO/cli/man.md`'s
//! `Prove` block reads `podssh man --no-pager > page.1`, a `head -1` of it, a
//! no-TTY run, and an `env -i` run — ⛔ and every one of those is a claim about
//! the *process*, not about a function. ⛔ The unit tests in `src/man.rs` prove
//! the emitter; only the executable proves the pipes, the exit codes and the
//! argument parsing in front of them.
//!
//! ⛔ `env!("CARGO_BIN_EXE_podssh")` is set by `cargo` for integration tests, so
//! this runs in the build image with no `podssh` on `PATH` — ⛔ the same reason
//! `tests/binary_streams.rs` uses it (E31's plant 6).
//!
//! ⛔ **stdin and stdout are separate pipes, always.** A test that let the child
//! inherit either one could not tell a hung pager from a fast one, ⛔ and the
//! entry's plant 6 is exactly that mistake.

use std::process::{Command, Stdio};

/// Run the real `podssh` with `args`, a choice of stdin, and the environment
/// either inherited or cleared.
fn podssh(args: &[&str], stdin_null: bool, clean_env: bool) -> (i32, Vec<u8>, Vec<u8>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .stdin(if stdin_null { Stdio::null() } else { Stdio::piped() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if clean_env {
        cmd.env_clear();
    }
    let out = cmd.output().expect("the podssh binary must be runnable");
    (out.status.code().unwrap_or(-1), out.stdout, out.stderr)
}

fn page() -> String {
    podssh_cli::man::page()
}

/// ⛔ **The acceptance line, run as written.** ⛔ `podssh man --no-pager >
/// page.1` exits 0 with a non-empty page, ⛔ `head -1` of it is the `.TH` line
/// **verbatim**, and ⛔ `head -20` reaches `.SH NAME` and `.SH DESCRIPTION`.
#[test]
fn no_pager_writes_the_page_and_the_first_line_is_th() {
    let (rc, out, err) = podssh(&["man", "--no-pager"], true, false);
    assert_eq!(rc, 0, "stderr was: {}", String::from_utf8_lossy(&err));
    assert!(!out.is_empty(), "the page is empty");
    let text = String::from_utf8(out).unwrap();
    let first = text.lines().next().unwrap();
    assert!(first.starts_with(".TH PODSSH 1 \"podssh "), "head -1 read {first:?}");
    let head: Vec<&str> = text.lines().take(20).collect();
    for want in [".SH NAME", ".SH DESCRIPTION"] {
        assert!(head.contains(&want), "head -20 never reaches {want}");
    }
    // ⛔ The page the binary writes is the page the library generates: ⛔ nothing
    // between them may add a byte, because `head -1` is the whole check a
    // reader runs by hand.
    assert_eq!(text, page(), "the binary's page is not the library's page");
}

/// ⛔ **stdout is the answer and nothing else**, on the man path too —
/// `06-cli.md`:251-252, and this is the entry's plant 8: a pager's status line
/// printed to stdout would make `head -1 page.1` read *that* instead of `.TH`.
#[test]
fn the_page_is_the_only_thing_on_stdout() {
    for args in [vec!["man"], vec!["man", "--no-pager"], vec!["man", "ssh"]] {
        let (rc, out, err) = podssh(&args, true, false);
        assert_eq!(rc, 0, "podssh {args:?} exited {rc}: {}", String::from_utf8_lossy(&err));
        assert!(
            err.is_empty(),
            "podssh {args:?} wrote a diagnostic to stderr on a path with nothing to diagnose: {:?}",
            String::from_utf8_lossy(&err)
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with(".TH "), "podssh {args:?} began with {:?}", &text[..text.len().min(40)]);
        assert!(!text.contains("-- more --"), "the pager's prompt reached stdout");
    }
}

/// ⛔ **Plant 6, against the process.** ⛔ `podssh man` with **no terminal** must
/// write the whole page and return: ⛔ a pager entered on a descriptor that
/// cannot answer stops at its first screenful, which is a truncated page, ⛔ and
/// a pager that waits on it is a hang — the entry's plant reads `timeout 5`,
/// and this test reads the same defect without needing the timeout to fire.
///
/// ⛔ The assertion is byte equality with `--no-pager`'s output, ⛔ so a page
/// that stopped early, a page that was re-wrapped, and a page that was paged
/// into a file all fail here.
#[test]
fn with_no_terminal_the_whole_page_is_written_and_the_process_returns() {
    let (rc, out, err) = podssh(&["man"], true, false);
    assert_eq!(rc, 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(
        String::from_utf8(out).unwrap(),
        page(),
        "`podssh man` with no terminal did not write the whole page"
    );
    assert!(err.is_empty(), "{:?}", String::from_utf8_lossy(&err));
}

/// ⛔ **The `Prove` block's `env -i` line.** ⛔ `env -i PATH=/nonexistent podssh
/// man --no-pager` must exit 0 with the page: ⛔ the argument is that the page
/// needs nothing from the host — no `man(1)`, no pager, no `MANPATH`, no
/// `$TERM`. ⛔ `Command::env_clear` is the stronger form of the same claim (the
/// variable is absent rather than pointing at nothing), ⛔ and the script that
/// runs in the build image also runs the literal command.
#[test]
fn the_page_needs_nothing_from_the_environment() {
    let (rc, out, err) = podssh(&["man", "--no-pager"], true, true);
    assert_eq!(rc, 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(String::from_utf8(out).unwrap(), page());
}

/// ⛔ An unknown section is exit **64** and **nothing on stdout** — `man.md`:150-153
/// (E24 decided, applied 2026-10-06) — ⛔ and the control is the section that does exist.
#[test]
fn an_unknown_section_exits_sixty_four_and_writes_nothing_to_stdout() {
    let (rc, out, err) = podssh(&["man", "nonsense"], true, false);
    // ⛔ **`64` is the decided-and-applied value** (E24; operator 2026-10-05,
    // applied 2026-10-06).
    assert_eq!(rc, 64, "the usage exit; E24's 64, applied");
    assert!(out.is_empty(), "an unknown section wrote {} bytes to stdout", out.len());
    let err = String::from_utf8(err).unwrap();
    assert!(err.contains("nonsense"), "{err}");
    assert!(err.contains("ssh"), "the refusal must name the sections: {err}");

    let (rc, out, _) = podssh(&["man", "ssh"], true, false);
    assert_eq!(rc, 0);
    assert!(String::from_utf8(out).unwrap().starts_with(".TH PODSSH-SSH 1"), "the section page");
}

/// ⛔ **Plant 10: what the page must never carry.**
///
/// ⛔ `docs/TODO/cli/man.md`:155-160 names three things and this checks two of
/// them: **the relay host** (E06's drift gate owns it) and **any token or
/// credential**. ⛔ The third — *"any sentence copied out of `docs/spec/`"* — is
/// not checkable by a string match and is a review matter.
///
/// ⛔ The rule behind it is general and not about this verb: a manual page is a
/// document people paste into issue reports, and `RULES.md`:124-130 is the
/// standing rule that a token never enters output, a log, or an issue. ⛔ The
/// page is generated from the table, so this is a claim about every string the
/// table can ever hold — ⛔ which is why it is checked on the bytes the binary
/// writes rather than argued from the emitter's structure.
#[test]
fn the_page_carries_no_url_and_no_credential_shaped_string() {
    let (rc, out, err) = podssh(&["man", "--no-pager"], true, false);
    assert_eq!(rc, 0, "{}", String::from_utf8_lossy(&err));
    let text = String::from_utf8(out).unwrap().to_lowercase();
    for needle in [
        "://",
        "ajam.dev",
        "bearer",
        "authorization",
        "token",
        "password",
        "secret",
        "credential",
    ] {
        assert!(
            !text.contains(needle),
            "the page carries {needle:?}, and a page is a document that gets pasted into issues"
        );
    }
}

/// ⛔ **Plants 4 and 5: nothing on this path spawns anything.**
/// ⛔ The entry's form of this check is `strace` — *"1, never 2 — a second
/// `execve` on this path is the defect"* — ⛔ and `man.md`:246-252 already says
/// `strace` may not exist and that the host-side proof belongs to E05's
/// `podssh-probe`, ⛔ so the trace half is `????` until that entry lands.
///
/// ⛔ **This is the half that can be proven here, and it is stronger than it
/// looks**: `man.rs` and `pager.rs` are the whole of the path, ⛔ and this reads
/// their *code* — comments stripped, so the prose explaining why is free — and
/// asserts that no line of either names a way to start a process. ⛔ A page that
/// shells out to `man(1)`, `less`, `more` or `pg` cannot pass it.
#[test]
fn the_man_path_cannot_start_a_process() {
    for (name, src) in [
        ("man.rs", include_str!("../src/man.rs")),
        ("pager.rs", include_str!("../src/pager.rs")),
    ] {
        for (n, line) in src.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for needle in ["std::process", "Command", "spawn", "exec"] {
                assert!(
                    !code.contains(needle),
                    "{name}:{} names {needle:?} — the man path must never start a process: {code:?}",
                    n + 1
                );
            }
        }
    }
}
