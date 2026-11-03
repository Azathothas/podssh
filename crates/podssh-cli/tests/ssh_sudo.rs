//! `--sudo` and `--su` (T-032), against the test's SSH server, which runs
//! `sudo -S` and `su -c` as they run (`ssh_harness`): the password comes from
//! `SSH_ASKPASS` for each prompt, once; neither marker reaches the output;
//! the input waits for the command to start; with no prompt, no password is
//! asked for. A password that cannot be given ends su's read on its pty, so
//! that su refuses at once, and a su that does not end gives 255 (T-501).

mod cleanup;
mod ssh_harness;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
    /// How long the run took.
    took: Duration,
}

/// The run to its end within `limit`: a run that waits for ever must fail
/// the test, not hold it.
fn within(mut child: Child, limit: Duration) -> Ran {
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > limit {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!("no end within {limit:?}: {}", String::from_utf8_lossy(&out.stderr));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let took = start.elapsed();
    let out = child.wait_with_output().unwrap();
    Ran {
        code: out.status.code(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
        took,
    }
}

/// An askpass program that logs its question in `asked` and fails, as a
/// cancelled dialog or a password store that is locked does (T-501).
fn askpass_failing(dir: &Path) -> String {
    let asked = dir.join("asked");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("askpass-fails");
        std::fs::write(&path, format!("#!/bin/sh\necho \"$1\" >> '{}'\nexit 1\n", asked.display())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.to_string_lossy().into_owned()
    }
    #[cfg(windows)]
    {
        let path = dir.join("askpass-fails.cmd");
        std::fs::write(&path, format!("@echo off\r\necho %1>> \"{}\"\r\nexit /b 1\r\n", asked.display())).unwrap();
        path.to_string_lossy().into_owned()
    }
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

/// `podssh ssh --direct FLAG [OPTIONS] USER@127.0.0.1 'id -u; cat'`, with
/// `askpass` as SSH_ASKPASS (forced), or none at all.
fn command(s: &Server, flag: &str, user: &str, askpass: Option<String>, options: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &s.port.to_string(), flag, "-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", s.dir.join("known_hosts").display()));
    cmd.args(options).args([&format!("{user}@127.0.0.1"), "id -u; cat"]);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", &s.dir).env("USERPROFILE", &s.dir);
    match askpass {
        Some(program) => cmd.env("SSH_ASKPASS", program).env("SSH_ASKPASS_REQUIRE", "force"),
        None => cmd.env_remove("SSH_ASKPASS").env_remove("SSH_ASKPASS_REQUIRE"),
    };
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd
}

/// `podssh ssh --direct FLAG USER@127.0.0.1 'id -u; cat'` with `input`, its
/// password from `answer`. The input is there at once, unless `late`.
fn elevated(s: &Server, flag: &str, user: &str, answer: &str, input: &str, late: bool) -> Ran {
    let mut cmd = command(s, flag, user, Some(askpass(&s.dir, answer)), &[]);
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
    within(child, Duration::from_secs(60))
}

/// A run whose password cannot be given: its stdin open and empty, as an
/// agent's harness leaves it, so that only the end of su's read ends it.
fn unanswered(s: &Server, flag: &str, user: &str, askpass: Option<String>, options: &[&str], limit: u64) -> Ran {
    let mut cmd = command(s, flag, user, askpass, options);
    let child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    within(child, Duration::from_secs(limit))
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

/// A helper that fails sends su no password: podssh ends su's read on its
/// pty, the channel's EOF alone never reaching it, and su refuses at once,
/// with its words and status; the line names the helper's end (T-501).
#[test]
fn su_ends_at_once_when_the_askpass_helper_fails() {
    let s = server("su-cancel");
    let ran = unanswered(&s, "--su", "su-u", Some(askpass_failing(&s.dir)), &[], 20);
    assert_eq!(ran.code, Some(1), "{}", ran.err);
    assert!(ran.took < Duration::from_secs(10), "{:?}: {}", ran.took, ran.err);
    let said = "the password for the remote command: SSH_ASKPASS exited 1, so podssh sends su no password";
    assert!(ran.err.contains(said), "{}", ran.err);
    assert!(ran.err.contains("su: Authentication failure"), "{}", ran.err);
    assert_eq!(asked(&s).lines().count(), 1, "one question: {}", asked(&s));
}

/// With no way to ask (BatchMode), su's read ends at once too, and the
/// command is never said to have asked nothing.
#[test]
fn su_ends_at_once_when_podssh_may_ask_none() {
    let s = server("su-batch");
    let ran = unanswered(&s, "--su", "su-u", None, &["-o", "BatchMode=yes"], 20);
    assert_eq!(ran.code, Some(1), "{}", ran.err);
    assert!(ran.took < Duration::from_secs(10), "{:?}: {}", ran.took, ran.err);
    assert!(ran.err.contains("podssh may ask none") && ran.err.contains("sends su no password"), "{}", ran.err);
    assert!(!ran.err.contains("neither asked"), "{}", ran.err);
}

/// sudo with the same helper: its stdin, the channel, ends, and it refuses
/// with 1.
#[test]
fn sudo_keeps_its_refusal_when_the_askpass_helper_fails() {
    let s = server("sudo-cancel");
    let ran = unanswered(&s, "--sudo", "sudo-u", Some(askpass_failing(&s.dir)), &[], 20);
    assert_eq!(ran.code, Some(1), "{}", ran.err);
    assert!(ran.err.contains("sudo: 1 incorrect password attempt"), "{}", ran.err);
    assert!(ran.err.contains("SSH_ASKPASS exited 1, so podssh sends sudo no password"), "{}", ran.err);
}

/// A su that ignores the end of its read: 255 once its 30 s are up, with a
/// line that says what podssh did, never a wait for ever (T-501).
#[test]
fn a_su_that_does_not_end_gives_255_within_its_time() {
    let s = server("su-deaf");
    let ran = unanswered(&s, "--su", "su-deaf-u", Some(askpass_failing(&s.dir)), &[], 50);
    assert_eq!(ran.code, Some(255), "{}", ran.err);
    let said = "su did not end within 30 s after podssh sent it no password: SSH_ASKPASS exited 1";
    assert!(ran.err.contains(said), "{}", ran.err);
    assert!(ran.took < Duration::from_secs(45), "{:?}", ran.took);
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
