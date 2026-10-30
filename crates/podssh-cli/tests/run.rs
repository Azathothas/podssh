//! `podssh run` (T-192) against the binary, with no host: each refusal of
//! the command line is 64, before anything connects, with nothing on
//! stdout; and a host out of reach is 255. The copy and the command run in
//! `run_far.rs`, against the test's server, and against OpenSSH in the gate
//! (`scripts/interop-run.sh`).

mod cleanup;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-run-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh` with `args` in `home`, with no settings file and no
/// ssh_config, offline: (exit code, stdout, stderr).
fn podssh(home: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .current_dir(home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", "none")
        .env("PODSSH_OFFLINE", "1")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

#[test]
fn a_bad_command_line_is_64_before_anything_connects() {
    let home = scratch("refused");
    let missing = home.join("no-such-project").display().to_string();
    for (args, says) in [
        (&["run"][..], "give the host"),
        (&["run", "build1"][..], "give the command"),
        (&["run", "--from", missing.as_str(), "build1", "--", "true"][..], "is no directory here"),
        (&["run", "build1:/", "--", "true"][..], "the home directory or the root"),
        (&["run", "build1:~", "--", "true"][..], "the home directory or the root"),
        (&["run", "a,b", "--", "true"][..], "gives 2 hosts"),
        (&["run", "--no-such-flag", "build1", "--", "true"][..], "--no-such-flag"),
    ] {
        let (code, out, err) = podssh(&home, args);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
    }
}

#[test]
fn a_host_out_of_reach_is_255_and_runs_nothing() {
    let home = scratch("offline");
    let (code, out, err) = podssh(&home, &["run", "build1.example.org", "--", "touch", "ran"]);
    assert_eq!(code, 255, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(!home.join("ran").exists());
}
