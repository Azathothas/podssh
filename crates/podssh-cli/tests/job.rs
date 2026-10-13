//! `podssh job` (T-193) against the binary, with no host: each refusal of
//! the command line is 64, before anything connects, with nothing on
//! stdout; and a host out of reach is 255. The jobs themselves run in
//! `job_far.rs`, against the test's server, and against OpenSSH and Dropbear
//! in the gate (`scripts/interop-job.sh`).

mod cleanup;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-job-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh` with `args`, its home in `home`, with no settings file and no
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
    for (args, says) in [
        (&["job"][..], "give what to do"),
        (&["job", "run", "web1"][..], "not a command of podssh job"),
        (&["job", "list"][..], "give the host"),
        (&["job", "start", "web1"][..], "give the command after --"),
        (&["job", "start", "web1", "--"][..], "give the command after --"),
        // Without --, the -l of `ls -l` would be podssh's login name.
        (&["job", "start", "web1", "ls"][..], "is read as a flag"),
        (&["job", "list", "web1", "extra"][..], "list takes no word"),
        (&["job", "log", "web1"][..], "give one ID"),
        (&["job", "log", "web1", "xyz"][..], "8 hex digits"),
        (&["job", "stop", "web1", "abcd1234", "abcd1235"][..], "give one ID"),
        (&["job", "list", "a,b"][..], "gives 2 hosts"),
        (&["job", "--no-such-flag", "list", "web1"][..], "--no-such-flag"),
    ] {
        let (code, out, err) = podssh(&home, args);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
    }
}

#[test]
fn a_host_out_of_reach_is_255_and_stdout_stays_empty() {
    let home = scratch("offline");
    for args in [&["job", "list", "web1.example.org"][..], &["job", "start", "web1.example.org", "--", "true"][..]] {
        let (code, out, err) = podssh(&home, args);
        assert_eq!(code, 255, "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
        assert!(!err.is_empty(), "{args:?}: no word of why");
    }
}

#[test]
fn the_help_and_the_manual_name_each_subcommand() {
    let home = scratch("help");
    let (code, out, _) = podssh(&home, &["job", "--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("podssh job [OPTIONS] SUBCOMMAND HOST [ID] [-- COMMAND...]"), "{out}");
    let (code, man, _) = podssh(&home, &["man", "--no-pager", "job"]);
    assert_eq!(code, 0);
    for word in ["start", "list", "log", "stop", "tmux"] {
        assert!(man.contains(word), "{word}: {man}");
    }
}
