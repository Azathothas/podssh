//! The expect rules and `LocalCommand` of `podssh ssh` (T-191) through the
//! binary, against the test's SSH server on the loopback, whose `prompt` is
//! a shell's prompt in a pty (`ssh_harness/prompt.rs`): the rules in order
//! and the remote status, a rule that sees no match, and a session with no
//! pty. `LocalCommand` runs with `PermitLocalCommand=yes` alone, before the
//! session (Unix, where `/bin/sh` is); with no shell it is 78 before
//! anything connects (Windows). Against OpenSSH and Dropbear it runs in the
//! gate (`scripts/interop-expect.sh`).

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-expect-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The test's server on a runtime of its own, and its port.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16) {
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

/// `podssh ssh` with `args` on the loopback, its home in `home`, no
/// settings file, no ssh_config, and `env` set: (exit code, stdout, stderr).
fn ssh(home: &Path, args: &[&str], env: &[(&str, Option<&str>)]) -> (i32, String, String) {
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-o", "StrictHostKeyChecking=accept-new", "-o", known.as_str()])
        .args(args)
        .current_dir(home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", "none")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "PODSSH_OFFLINE"] {
        cmd.env_remove(name);
    }
    for (name, value) in env {
        match value {
            Some(value) => cmd.env(name, value),
            None => cmd.env_remove(name),
        };
    }
    let out = cmd.output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

#[test]
fn the_rules_send_their_keys_in_order_and_the_status_comes_back() {
    let home = scratch("rules");
    let (_runtime, port) = server(&home);
    let host = format!("pty-a@127.0.0.1:{port}");
    let rules = ["-tt", "--expect", "$ ", "--send", r"echo EXP\r", "--expect", "EXP", "--send", r"exit 4\r"];
    let mut args = rules.to_vec();
    args.extend([host.as_str(), "prompt"]);
    let (code, out, err) = ssh(&home, &args, &[]);
    assert_eq!(code, 4, "{out}{err}");
    // The prompt's echo of each key, and its answer, in order.
    let at = |text: &str| out.find(text).unwrap_or_else(|| panic!("{text:?} is not in {out:?}"));
    assert!(at("echo EXP\r\nEXP\r\n") < at("exit 4\r\n"), "{out:?}");
}

#[test]
fn a_rule_that_sees_no_match_ends_the_session_with_255_and_is_named() {
    let home = scratch("miss");
    let (_runtime, port) = server(&home);
    let host = format!("pty-a@127.0.0.1:{port}");
    let started = Instant::now();
    let args = ["-tt", "--expect", "$ ", "--send", "", "--expect", "NEVER", "--send", "x", "--expect-timeout", "2s"];
    let mut args = args.to_vec();
    args.extend([host.as_str(), "prompt"]);
    let (code, _, err) = ssh(&home, &args, &[]);
    assert_eq!(code, 255, "{err}");
    assert!(err.contains("--expect 2 (\"NEVER\") saw no match within 2 s"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
}

#[test]
fn a_session_with_no_pty_runs_no_rule() {
    let home = scratch("no-pty");
    let (_runtime, port) = server(&home);
    let host = format!("pty-a@127.0.0.1:{port}");
    // No -t, and no terminal here: a command gets no pty.
    let (code, out, err) = ssh(&home, &["--expect", "$ ", "--send", r"exit 4\r", host.as_str(), "prompt"], &[]);
    assert_eq!((code, out.as_str()), (255, ""), "{err}");
    assert!(err.contains("--expect needs a session with a pseudo-terminal"), "{err}");
}

/// The plant of the entry: with no PermitLocalCommand, the command would
/// run, and the case of `=no` fails.
#[cfg(unix)]
#[test]
fn local_command_runs_with_permit_local_command_yes_alone_and_before_the_session() {
    let home = scratch("local");
    let (_runtime, port) = server(&home);
    let host = format!("a@127.0.0.1:{port}");
    let line = format!("LocalCommand=touch {}/lc-%h", home.display());
    let shell = [("SHELL", Some("/bin/sh"))];
    let run = |permit: &[&str]| {
        let mut args = permit.to_vec();
        args.extend(["-o", line.as_str(), host.as_str(), "greet"]);
        ssh(&home, &args, &shell)
    };
    let (code, _, err) = run(&["-o", "PermitLocalCommand=no"]);
    assert_eq!(code, 0, "{err}");
    assert!(!home.join("lc-127.0.0.1").exists(), "PermitLocalCommand=no ran the command");
    let (code, _, err) = run(&[]);
    assert_eq!(code, 0, "{err}");
    assert!(!home.join("lc-127.0.0.1").exists(), "no PermitLocalCommand ran the command");
    let (code, _, err) = run(&["-o", "PermitLocalCommand=yes"]);
    assert_eq!(code, 0, "{err}");
    assert!(home.join("lc-127.0.0.1").exists(), "PermitLocalCommand=yes ran nothing: {err}");
    // Its output comes before the session's.
    let echo = ["-o", "PermitLocalCommand=yes", "-o", "LocalCommand=echo LOCAL", host.as_str(), "greet"];
    let (code, out, err) = ssh(&home, &echo, &shell);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, format!("LOCAL\n{}", ssh_harness::GREETING), "{err}");
}

/// No shell for LocalCommand: 78, before anything connects.
#[cfg(windows)]
#[test]
fn local_command_with_no_shell_is_78_before_anything_connects() {
    let home = scratch("no-shell");
    let args = ["-o", "PermitLocalCommand=yes", "-o", "LocalCommand=echo LOCAL", "a@127.0.0.1:1", "true"];
    let (code, out, err) = ssh(&home, &args, &[("SHELL", None), ("PODSSH_OFFLINE", Some("1"))]);
    assert_eq!((code, out.as_str()), (78, ""), "{err}");
    assert!(err.contains("LocalCommand needs a shell: SHELL is not set"), "{err}");
}
