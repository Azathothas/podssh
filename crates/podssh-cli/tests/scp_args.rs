//! `podssh scp` and `podssh sftp` with OpenSSH's command lines (T-139),
//! against the binary and offline: each letter that podssh does not carry is
//! refused by name (64) with nothing attempted, each that it carries or
//! accepts goes on to connect, which offline cannot (69), and neither verb
//! asks for `--timeout`.

use std::process::{Command, Stdio};

/// Run the binary offline with no terminal; (exit code, stdout, stderr).
fn podssh(args: &[&str]) -> (i32, Vec<u8>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(args)
        // No test may reach the network: a copy that would connect stops here.
        .env("PODSSH_OFFLINE", "1")
        .env_remove("PODSSH_TIMEOUT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the podssh binary runs");
    (out.status.code().unwrap_or(-1), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn each_scp_letter_that_podssh_does_not_carry_is_refused_by_name() {
    for flag in [
        &["-O"][..],
        &["-R"],
        &["-r"],
        &["-p"],
        &["-A"],
        &["-S", "ssh"],
        &["-D", "/x"],
        &["-X", "nrequests=4"],
        &["-l", "100"],
        &["-c", "aes128-ctr"],
    ] {
        let mut args = vec!["scp"];
        args.extend_from_slice(flag);
        args.extend_from_slice(&["a", "host:b"]);
        let (rc, out, err) = podssh(&args);
        assert_eq!(rc, 64, "{flag:?}: {err}");
        assert!(out.is_empty(), "{flag:?} wrote to stdout");
        assert!(err.contains("is refused") && !err.contains("unknown flag"), "{flag:?}: {err}");
    }
}

#[test]
fn scp_goes_on_to_connect_with_its_own_letters_and_no_timeout() {
    // Offline nothing answers: 69, after the command line and the settings
    // passed. No --timeout: OpenSSH's scp has none, and each wait has a limit.
    for words in [
        &["a", "host:b"][..],
        &["-P", "2222", "-B", "-C", "-q", "-v", "-4", "a", "host:b"],
        &["-3", "-s", "-T", "host:a", "."],
        &["-o", "BatchMode=yes", "-i", "id_test", "-J", "jump", "a", "host:b"],
        &["a", "scp://u@host:2222/dir/b"],
        &["scp://host//srv/a", "."],
        &["--direct", "a", "host:b"],
    ] {
        let mut args = vec!["scp"];
        args.extend_from_slice(words);
        let (rc, out, err) = podssh(&args);
        assert_eq!(rc, 69, "{words:?}: {err}");
        assert!(out.is_empty(), "{words:?} wrote to stdout");
        assert!(!err.contains("--timeout"), "{words:?} asked for --timeout: {err}");
    }
}

#[test]
fn scp_refuses_as_cp_does_in_its_own_name() {
    for (words, says) in [
        (&["a"][..], "podssh scp: give a source and a destination"),
        (&["a", "b"][..], "podssh scp: both sides are local paths"),
        (&["a", "scp://host:0/x"][..], "no port from 1 to 65535"),
        (&["a", "scp://host/%zz"][..], "bad % escape"),
    ] {
        let mut args = vec!["scp"];
        args.extend_from_slice(words);
        let (rc, _, err) = podssh(&args);
        assert_eq!(rc, 64, "{words:?}: {err}");
        assert!(err.contains(says) && err.contains("Nothing has been attempted"), "{words:?}: {err}");
    }
}

#[test]
fn each_sftp_letter_that_podssh_does_not_carry_is_refused_by_name() {
    for flag in [
        &["-B", "32768"][..],
        &["-R", "16"],
        &["-r"],
        &["-p"],
        &["-A"],
        &["-l", "100"],
        &["-S", "ssh"],
        &["-D", "/x"],
        &["-X", "buffer=4"],
        &["-c", "aes128-ctr"],
    ] {
        let mut args = vec!["sftp"];
        args.extend_from_slice(flag);
        args.push("host");
        let (rc, _, err) = podssh(&args);
        assert_eq!(rc, 64, "{flag:?}: {err}");
        assert!(err.contains("is refused") && !err.contains("unknown flag"), "{flag:?}: {err}");
    }
}

#[test]
fn sftp_asks_for_its_destination_and_for_commands_with_no_terminal() {
    let (rc, _, err) = podssh(&["sftp"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("give a destination"), "{err}");
    // No terminal, no -b, and no file to fetch: nothing to do.
    let (rc, _, err) = podssh(&["sftp", "user@host"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("-b FILE") && err.contains("Nothing has been attempted"), "{err}");
    // A batch that cannot be read is a source that cannot be read.
    let (rc, _, err) = podssh(&["sftp", "-b", "no-such-batch-file", "host"]);
    assert_eq!(rc, 66, "{err}");
    // A batch, or a path to fetch, goes on to connect: offline, 69.
    let batch = std::env::temp_dir().join(format!("podssh-batch-{}", std::process::id()));
    std::fs::write(&batch, "pwd\n-rm x*\n@ls\nbye\n").expect("a batch");
    let shown = batch.display().to_string();
    for words in [
        &["-b", shown.as_str(), "host"][..],
        &["-b", "-", "-a", "-f", "-N", "-P", "2222", "u@host"],
        &["host:dir/file"],
        &["sftp://u@host:2222/x"],
        &["-s", "sftp", "-b", shown.as_str(), "host"],
    ] {
        let mut args = vec!["sftp"];
        args.extend_from_slice(words);
        let (rc, _, err) = podssh(&args);
        assert_eq!(rc, 69, "{words:?}: {err}");
    }
    let _ = std::fs::remove_file(&batch);
}
