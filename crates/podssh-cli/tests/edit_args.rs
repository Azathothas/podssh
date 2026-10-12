//! `podssh edit`'s command line (T-149), against the binary and offline: a
//! bad operand is 64, no editor is 78 and names `EDITOR`, and no terminal is
//! 64, each before anything is attempted; the editor is `VISUAL`, else
//! `EDITOR`, else `vi` on `PATH`. The edit itself, against OpenSSH, is in the
//! gate (`scripts/interop-edit.sh`).

mod cleanup;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use podssh_cli::edit::editor::{choose, EditorEnv};

/// A directory of the test's own, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-edit-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// Run `podssh edit` offline with no terminal, with `env` set and `VISUAL`
/// and `EDITOR` removed first; (exit code, stdout, stderr).
fn edit(words: &[&str], env: &[(&str, OsString)]) -> (i32, Vec<u8>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("edit")
        .args(words)
        // No test may reach the network, nor read the machine's settings;
        // and a refusal that let the run on would write no copy (78).
        .env("PODSSH_OFFLINE", "1")
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_CACHE_DIR", "none")
        .env_remove("VISUAL")
        .env_remove("EDITOR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        cmd.env(name, value);
    }
    let out = cmd.output().expect("the podssh binary runs");
    (out.status.code().unwrap_or(-1), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// An editor that is set: the run gets past the choice of the editor.
fn with_editor() -> Vec<(&'static str, OsString)> {
    vec![("EDITOR", OsString::from("podssh-test-editor"))]
}

#[test]
fn a_bad_operand_is_64_and_nothing_is_attempted() {
    for (words, says) in [
        (&[][..], "give the file to edit"),
        (&["notes.txt"][..], "is a path here"),
        (&["host:"][..], "names no file"),
        (&["host:dir/"][..], "names no file"),
        (&["@host:f"][..], "empty user"),
    ] {
        let (rc, out, err) = edit(words, &with_editor());
        assert_eq!(rc, 64, "{words:?}: {err}");
        assert!(out.is_empty(), "{words:?} wrote to stdout");
        assert!(err.contains(says) && err.contains("Nothing has been attempted"), "{words:?}: {err}");
    }
    // One file only: a second is the parser's refusal.
    let (rc, out, err) = edit(&["host:a", "host:b"], &with_editor());
    assert_eq!(rc, 64, "{err}");
    assert!(out.is_empty());
}

#[test]
fn with_no_editor_it_is_78_and_names_editor() {
    // No VISUAL, no EDITOR, and a PATH with no vi.
    let empty = scratch("path");
    let (rc, out, err) = edit(&["host:notes.txt"], &[("PATH", empty.into_os_string())]);
    assert_eq!(rc, 78, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("EDITOR") && err.contains("Nothing has been attempted"), "{err}");
}

#[test]
fn with_no_terminal_it_is_64() {
    for env in [with_editor(), vec![("VISUAL", OsString::from("")), ("EDITOR", OsString::from("nano"))]] {
        let (rc, out, err) = edit(&["host:notes.txt"], &env);
        assert_eq!(rc, 64, "{env:?}: {err}");
        assert!(out.is_empty());
        assert!(err.contains("a terminal on stdin and stdout"), "{env:?}: {err}");
    }
}

#[test]
fn the_help_shows_the_connection_flags_and_no_timeout() {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh")).args(["edit", "--help"]).output().expect("runs");
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("podssh edit [OPTIONS] [user@]host:PATH"), "{help}");
    for flag in ["-P, --port PORT", "-i, --identity-file FILE", "-J, --jump-host", "--direct", "--relay-host"] {
        assert!(help.contains(flag), "{flag}: {help}");
    }
    assert!(!help.contains("--timeout") && !help.contains("--jsonl"), "{help}");
}

#[test]
fn the_editor_is_visual_then_editor_then_vi() {
    let env = |visual: Option<&str>, editor: Option<&str>, vi: bool| EditorEnv {
        visual: visual.map(OsString::from),
        editor: editor.map(OsString::from),
        vi: vi.then(|| PathBuf::from("/usr/bin/vi")),
    };
    let from = |e: &EditorEnv| choose(e).map(|c| (c.shown(), c.from));
    assert_eq!(from(&env(Some("emacs -nw"), Some("nano"), true)), Ok(("emacs -nw".to_string(), "VISUAL")));
    assert_eq!(from(&env(None, Some("nano -w"), true)), Ok(("nano -w".to_string(), "EDITOR")));
    assert_eq!(from(&env(Some(""), None, true)), Ok(("/usr/bin/vi".to_string(), "PATH")));
    let none = choose(&env(Some(" "), Some(""), false)).expect_err("no editor");
    assert!(none.contains("EDITOR"), "{none}");
    // The words go to the program, with no shell: a quote is a character.
    let words = choose(&env(None, Some("code --wait 'x y'"), false)).expect("an editor").words;
    assert_eq!(words, ["code", "--wait", "'x", "y'"].map(OsString::from));
}
