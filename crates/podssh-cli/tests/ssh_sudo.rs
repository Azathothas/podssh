//! `--sudo` and `--su` (T-032), against the test's SSH server, which runs
//! `sudo -S` and `su -c` as they run (`ssh_harness`): the password comes from
//! `SSH_ASKPASS` for each prompt, once; neither marker reaches the output;
//! the input waits for the command to start; with no prompt, no password is
//! asked for.

mod cleanup;
mod ssh_harness;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
}

/// An askpass program that answers `answer`, and logs each question in
/// `asked`.
fn askpass(dir: &Path, answer: &str) -> String {
    let asked = dir.join("asked");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(format!("askpass-{answer}"));
        let script = format!("#!/bin/sh\necho \"$1\" >> '{}'\nprintf '%s\\n' '{answer}'\n", asked.display());
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.to_string_lossy().into_owned()
    }
    #[cfg(windows)]
    {
        let path = dir.join(format!("askpass-{answer}.cmd"));
        let script = format!("@echo off\r\necho %1>> \"{}\"\r\necho({answer}\r\n", asked.display());
        std::fs::write(&path, script).unwrap();
        path.to_string_lossy().into_owned()
    }
}

struct Server {
    dir: PathBuf,
    port: u16,
    _runtime: tokio::runtime::Runtime,
}

fn server(name: &str) -> Server {
    let dir = std::env::temp_dir().join(format!("podssh-sudo-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    Server { dir, port, _runtime: runtime }
}

/// `podssh ssh --direct FLAG USER@127.0.0.1 'id -u; cat'` with `input`, its
/// password from `answer`. The input is there at once, unless `late`.
fn elevated(s: &Server, flag: &str, user: &str, answer: &str, input: &str, late: bool) -> Ran {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &s.port.to_string(), flag, "-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", s.dir.join("known_hosts").display()));
    cmd.args([&format!("{user}@127.0.0.1"), "id -u; cat"]);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", &s.dir).env("USERPROFILE", &s.dir);
    cmd.env("SSH_ASKPASS", askpass(&s.dir, answer)).env("SSH_ASKPASS_REQUIRE", "force");
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // At once, the input tests that it waits for the command's start; a
    // second later, a session that sent a password unasked is still there
    // to show it.
    let (mut stdin, input) = (child.stdin.take().unwrap(), input.to_string());
    std::thread::spawn(move || {
        if late {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        let _ = stdin.write_all(input.as_bytes());
    });
    let out = child.wait_with_output().unwrap();
    Ran {
        code: out.status.code(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Whether `text` holds a marker of podssh's, `podssh-ID-password` or
/// `podssh-ID-started`, whatever its random ID.
fn has_marker(text: &str) -> bool {
    text.contains("-password") || text.contains("-started")
}

fn asked(s: &Server) -> String {
    std::fs::read_to_string(s.dir.join("asked")).unwrap_or_default()
}

/// sudo asks: one password through SSH_ASKPASS, the command runs, and its
/// input comes after the password, never with it.
#[test]
fn sudo_sends_the_password_for_its_prompt_and_then_the_input() {
    let s = server("asks");
    let ran = elevated(&s, "--sudo", "sudo-u", "secret", "hello\n", false);
    assert_eq!((ran.code, ran.out.as_str()), (Some(0), "0\nhello\n"), "{}", ran.err);
    assert!(!has_marker(&ran.err) && !has_marker(&ran.out), "a marker in the output: {}", ran.err);
    let asked = asked(&s);
    assert_eq!(asked.lines().count(), 1, "{asked}");
    assert!(asked.contains("[sudo] password for sudo-u@"), "{asked}");
}

/// A wrong password: sudo asks again, and podssh ends the input, so sudo
/// fails, with its own words and podssh's.
#[test]
fn sudo_ends_the_input_when_it_asks_again() {
    let s = server("wrong");
    let ran = elevated(&s, "--sudo", "sudo-u", "wrong", "hello\n", false);
    assert_eq!(ran.code, Some(1), "{}", ran.err);
    assert!(ran.err.contains("Sorry, try again.") && ran.err.contains("the password was refused"), "{}", ran.err);
    assert!(!has_marker(&ran.err), "{}", ran.err);
    assert_eq!(ran.out, "", "the input never reached the command");
    assert_eq!(asked(&s).lines().count(), 1, "one question");
}

/// A NOPASSWD rule: no prompt, so no question, and the command runs.
#[test]
fn sudo_asks_nothing_without_a_prompt() {
    let s = server("nopass");
    let ran = elevated(&s, "--sudo", "sudo-nopass-u", "secret", "hello\n", true);
    assert_eq!((ran.code, ran.out.as_str()), (Some(0), "0\nhello\n"), "{}", ran.err);
    assert_eq!(asked(&s), "", "the askpass program never ran");
}

/// su, in a pty: its prompt is answered once, its own output is dropped
/// once the command starts, and shown when it refuses.
#[test]
fn su_answers_its_prompt_and_shows_its_refusal() {
    let s = server("su");
    let ran = elevated(&s, "--su", "su-u", "secret", "hello\n", false);
    assert_eq!((ran.code, ran.out.as_str()), (Some(0), "0\nhello\n"), "{}", ran.err);
    assert!(asked(&s).contains("[su] password of root@"), "{}", asked(&s));
    let refused = elevated(&s, "--su", "su-u", "wrong", "", false);
    assert_eq!(refused.code, Some(1), "{}", refused.err);
    assert!(refused.err.contains("su: Authentication failure"), "{}", refused.err);
}

/// The flags need a command, one of them at once, and the pty that each
/// asks for: usage errors, before anything connects.
#[test]
fn sudo_and_su_refuse_what_cannot_go_with_them() {
    let refused = |args: &[&str], said: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
            .args(["ssh", "--direct"])
            .args(args)
            .env("PODSSH_SSH_CONFIG", "none")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {err}");
        assert!(err.contains(said), "{args:?}: {err}");
    };
    refused(&["--sudo", "u@127.0.0.1"], "give the command");
    refused(&["--sudo", "--su", "u@127.0.0.1", "id"], "give one");
    refused(&["--sudo", "-t", "u@127.0.0.1", "id"], "drop -t");
    refused(&["--su", "-T", "u@127.0.0.1", "id"], "drop -T");
    refused(&["--sudo", "-N", "u@127.0.0.1"], "give the command");
}
