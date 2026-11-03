//! `podssh edit`'s command line (T-149), against the binary and offline: a
//! bad operand is 64, no editor is 78 and names `EDITOR`, and no terminal is
//! 64 and names `--no-terminal`, each before anything is attempted; the
//! editor is `VISUAL`, else `EDITOR`, else `vi` on `PATH`. `--no-terminal`
//! (T-510) needs a bound with no terminal, and runs an editor that is a
//! script against the test's server and OpenSSH's `sftp-server`. The edit
//! itself, against OpenSSH, is in the gate (`scripts/interop-edit.sh`).

mod cleanup;
#[cfg(unix)]
mod ssh_harness;

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
        assert!(err.contains("--no-terminal"), "the refusal names the flag: {err}");
    }
}

/// `--no-terminal` (T-510): with no terminal it needs a bound, as `cp` does
/// (64 with none, 78 for a bad `PODSSH_TIMEOUT`); with one it gets past the
/// terminal, to the copy's directory, which the test's `PODSSH_CACHE_DIR`
/// of none refuses (78); `--timeout` without it is 64.
#[test]
fn no_terminal_needs_a_bound_and_gets_past_the_terminal() {
    let (rc, out, err) = edit(&["--no-terminal", "host:notes.txt"], &with_editor());
    assert_eq!(rc, 64, "{err}");
    assert!(out.is_empty() && err.contains("podssh edit: --timeout DURATION is required"), "{err}");
    let (rc, _, err) = edit(&["--no-terminal", "--timeout", "30x", "host:notes.txt"], &with_editor());
    assert_eq!(rc, 64, "{err}");
    let mut bad = with_editor();
    bad.push(("PODSSH_TIMEOUT", OsString::from("30x")));
    let (rc, _, err) = edit(&["--no-terminal", "host:notes.txt"], &bad);
    assert_eq!(rc, 78, "{err}");
    let (rc, _, err) = edit(&["--timeout", "5s", "host:notes.txt"], &with_editor());
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--timeout goes with --no-terminal"), "{err}");
    let (rc, out, err) = edit(&["--no-terminal", "--timeout", "5s", "host:notes.txt"], &with_editor());
    assert_eq!(rc, 78, "past the terminal, to the copy's directory: {err}");
    assert!(out.is_empty() && err.contains("PODSSH_CACHE_DIR is none") && !err.contains("terminal"), "{err}");
}

#[test]
fn the_help_shows_the_connection_flags_and_no_terminal() {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh")).args(["edit", "--help"]).output().expect("runs");
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("podssh edit [OPTIONS] [user@]host:PATH"), "{help}");
    for flag in ["-P, --port PORT", "-i, --identity-file FILE", "-J, --jump-host", "--direct", "--relay-host"] {
        assert!(help.contains(flag), "{flag}: {help}");
    }
    assert!(help.contains("--no-terminal") && help.contains("--timeout DURATION"), "{help}");
    assert!(!help.contains("--jsonl"), "{help}");
}

/// The test's SSH server, whose `sftp` is OpenSSH's `sftp-server` in `home`.
#[cfg(unix)]
fn server(home: &std::path::Path) -> (tokio::runtime::Runtime, u16) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    (runtime, port)
}

/// `podssh edit --no-terminal` with `args`, the editor `sh SCRIPT` whose body
/// is `body`, and `FAR_FILE` set to `far`, against the server of `port`,
/// with no terminal, 120 s at most; (exit code, stdout, stderr).
#[cfg(unix)]
fn edit_with(home: &std::path::Path, port: u16, body: &str, args: &[&str]) -> (i32, Vec<u8>, String) {
    // Read by sh, never run itself: a file just written can be busy to run.
    let script = home.join("editor.sh");
    std::fs::write(&script, format!("{body}\n")).unwrap();
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["edit", "--no-terminal", "--direct", "-P", &port.to_string()])
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={known}"))
        .args(args)
        .current_dir(home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_CACHE_DIR", home.join("cache"))
        .env("HOME", home)
        .env("EDITOR", format!("sh {}", script.display()))
        .env("FAR_FILE", home.join("far/notes.txt"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["VISUAL", "PODSSH_OFFLINE", "PODSSH_TIMEOUT", "HTTPS_PROXY", "https_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.spawn().expect("the podssh binary runs");
    let started = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > std::time::Duration::from_secs(120) {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The copies that the cache of `home` keeps, by their bytes.
#[cfg(unix)]
fn kept(home: &std::path::Path) -> Vec<Vec<u8>> {
    let Ok(dirs) = std::fs::read_dir(home.join("cache")) else { return Vec::new() };
    dirs.filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("edit-"))
        .filter_map(|e| std::fs::read(e.path().join("notes.txt")).ok())
        .collect()
}

/// An editor that is a script (T-510), against the test's server and
/// OpenSSH's `sftp-server`, with no terminal: it adds a line, the far file
/// has it, and the exit is 0 with nothing on stdout; the far file changed
/// meanwhile: 73, nothing sent, the copy kept and its directory named for
/// removal; an editor that waits past `--timeout`: 75, ended, nothing kept.
#[cfg(unix)]
#[test]
fn no_terminal_runs_an_editor_that_is_a_script() {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let home = scratch("script");
    let (_runtime, port) = server(&home);
    std::fs::create_dir_all(home.join("far")).unwrap();
    std::fs::write(home.join("far/notes.txt"), b"first\n").unwrap();
    let target = "u@127.0.0.1:far/notes.txt";
    let (rc, out, err) = edit_with(&home, port, "echo added >> \"$1\"", &["--timeout", "60s", target]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.is_empty(), "stdout stays empty: {}", String::from_utf8_lossy(&out));
    assert_eq!(std::fs::read(home.join("far/notes.txt")).unwrap(), b"first\nadded\n");
    assert!(kept(&home).is_empty(), "the copy went after the success");
    // The far file changes while the editor runs: nothing is sent.
    let body = "echo mine >> \"$1\"; echo theirs >> \"$FAR_FILE\"";
    let (rc, _, err) = edit_with(&home, port, body, &["--timeout", "60s", target]);
    assert_eq!(rc, 73, "{err}");
    assert_eq!(std::fs::read(home.join("far/notes.txt")).unwrap(), b"first\nadded\ntheirs\n", "never overwritten");
    assert!(err.contains("your copy stays at") && err.contains("rm -r") && err.contains("once you merged it"), "{err}");
    assert_eq!(kept(&home), [b"first\nadded\nmine\n".to_vec()], "the copy stays, with the change");
    // An editor that waits: the bound ends it, and nothing is sent.
    let started = std::time::Instant::now();
    let (rc, _, err) = edit_with(&home, port, "sleep 30", &["--timeout", "2s", target]);
    assert_eq!(rc, 75, "{err}");
    assert!(started.elapsed() < std::time::Duration::from_secs(20), "ended by the bound: {err}");
    assert!(err.contains("the --timeout of 2 s passed while the editor ran"), "{err}");
    assert_eq!(kept(&home).len(), 1, "a copy with no change goes; the one of the conflict stays");
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
