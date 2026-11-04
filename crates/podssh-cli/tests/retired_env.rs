//! The check of retired `PODSSH_` names (T-634) in the real binary. The
//! release's table is empty, so a retired name cannot be set here: the unit
//! tests of `retired`, `dispatch` and `node_install` take a row of their own.
//! What the binary can show is the line that the check never crosses: a name
//! that no row holds changes nothing, and what only prints still answers.

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The real podssh with `args` and one unknown `PODSSH_` name, to its end
/// within 30 s: no verb here connects (PODSSH_OFFLINE).
fn podssh(args: &[&str], unknown: bool) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_OFFLINE", "1").env_remove("PODSSH_ERROR_PROGRAM");
    if unknown {
        cmd.env("PODSSH_NO_SUCH_THING", "1");
    }
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh {args:?} did not end within 30 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

/// `podssh --version` answers with an unknown name set, on stdout alone.
#[test]
fn an_unknown_name_does_not_stop_podssh_version() {
    let out = podssh(&["--version"], true);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("podssh "), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
}

/// A run with an unknown name set is the same run as with none: `chat` in a
/// pipe asks for --timeout and exits 64, never 78.
#[test]
fn an_unknown_name_leaves_a_run_as_before() {
    let with = podssh(&["chat"], true);
    let without = podssh(&["chat"], false);
    assert_eq!(with.status.code(), Some(64), "{}", String::from_utf8_lossy(&with.stderr));
    let ran = |o: &Output| (o.status.code(), o.stdout.clone(), String::from_utf8_lossy(&o.stderr).into_owned());
    assert_eq!(ran(&with), ran(&without));
    assert!(!String::from_utf8_lossy(&with.stderr).contains("no longer read"));
}
