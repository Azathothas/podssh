//! `podssh cp`'s and `podssh mv`'s command line, against the binary and
//! offline: each refusal is a usage error (64) with nothing attempted, and
//! each operand form that names a server goes on to connect, which offline
//! cannot (69).

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

/// `cp --timeout 5s` and `words`.
fn cp(words: &[&str]) -> (i32, Vec<u8>, String) {
    let mut args = vec!["cp", "--timeout", "5s"];
    args.extend_from_slice(words);
    podssh(&args)
}

/// `mv --timeout 5s` and `words`.
fn mv(words: &[&str]) -> (i32, Vec<u8>, String) {
    let mut args = vec!["mv", "--timeout", "5s"];
    args.extend_from_slice(words);
    podssh(&args)
}

#[test]
fn each_refusal_is_64_and_nothing_is_attempted() {
    for (words, says) in [
        (&[][..], "give a source and a destination"),
        (&["a"][..], "give a source and a destination"),
        (&["a", "b"][..], "both sides are local paths"),
        (&["./a:b", "dir/c:d"][..], "both sides are local paths"),
        (&["host:a", "./b", "other:c"][..], "from one side"),
        (&["host:a", "other:b", "./dst"][..], "more than one server"),
        (&["host:a", "host:b", "other:c"][..], "one source at a time"),
        (&["@host:a", "b"][..], "empty user"),
        (&["u@:a", "b"][..], "names no host"),
    ] {
        let (rc, out, err) = cp(words);
        assert_eq!(rc, 64, "{words:?}: {err}");
        assert!(out.is_empty(), "{words:?} wrote to stdout");
        assert!(err.contains(says) && err.contains("Nothing has been attempted"), "{words:?}: {err}");
    }
}

#[test]
fn recursive_and_preserve_refuse_by_name() {
    for flag in ["-r", "--recursive", "-p", "--preserve"] {
        let (rc, out, err) = cp(&[flag, "a", "host:b"]);
        assert_eq!(rc, 64, "{flag}: {err}");
        assert!(out.is_empty(), "{flag} wrote to stdout");
        assert!(err.contains("is refused") && err.contains("not implemented yet"), "{flag}: {err}");
    }
}

#[test]
fn a_config_file_is_refused_as_ssh_refuses_it() {
    let (rc, _, err) = cp(&["-F", "some_config", "a", "host:b"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("-F"), "{err}");
}

#[test]
fn each_operand_that_names_a_server_goes_on_to_connect() {
    // Offline, nothing answers: 69, after the plan and the settings passed.
    for words in [
        &["a", "host:b"][..],
        &["a", "user@host:"][..],
        &["host:/srv/a", "."][..],
        &["./a:b", "host:c"][..],
        &["a", "c", "host:dir/"][..],
        &["a", "[2001:db8::1]:b"][..],
        &["user@[::1]:a", "."][..],
        &["host:a", "other:b"][..],
        &["-P", "2222", "-i", "id_test", "-o", "BatchMode=yes", "a", "host:b"][..],
        &["--direct", "a", "host:b"][..],
    ] {
        let (rc, out, err) = cp(words);
        assert_eq!(rc, 69, "{words:?}: {err}");
        assert!(out.is_empty(), "{words:?} wrote to stdout");
    }
}

#[test]
fn a_drive_letter_is_local_on_windows_and_a_host_elsewhere() {
    // `C:\x` and `host:b`: one local file up on Windows; elsewhere two
    // servers, a copy across. Either way it connects, so offline it is 69.
    let (rc, _, err) = cp(&[r"C:\x", "host:b"]);
    assert_eq!(rc, 69, "{err}");
    // Two drive letters are two local paths on Windows, and two servers
    // elsewhere.
    let (rc, _, err) = cp(&[r"C:\x", r"D:\y"]);
    if cfg!(windows) {
        assert_eq!(rc, 64, "{err}");
        assert!(err.contains("both sides are local paths"), "{err}");
    } else {
        assert_eq!(rc, 69, "{err}");
    }
}

#[test]
fn jsonl_reports_a_failure_as_one_object_on_stdout() {
    let (rc, out, err) = cp(&["--jsonl", "a", "host:b"]);
    assert_eq!(rc, 69, "{err}");
    let text = String::from_utf8(out).expect("UTF-8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "{text}");
    let event: serde_json::Value = serde_json::from_str(lines[0]).expect("one JSON object");
    assert_eq!(event["event"], "error");
    assert_eq!(event["code"], 69);
}

#[test]
fn mv_refuses_as_cp_does_and_refuses_one_file_named_twice() {
    for (words, says) in [
        (&["a"][..], "podssh mv: give a source and a destination"),
        (&["a", "b"][..], "podssh mv: both sides are local paths"),
        (&["host:a", "host:a"][..], "name one file"),
        (&["host:a", "host:./a"][..], "name one file"),
    ] {
        let (rc, out, err) = mv(words);
        assert_eq!(rc, 64, "{words:?}: {err}");
        assert!(out.is_empty(), "{words:?} wrote to stdout");
        assert!(err.contains(says) && err.contains("Nothing has been attempted"), "{words:?}: {err}");
    }
}

#[test]
fn mv_between_hosts_says_first_that_it_is_not_atomic() {
    // Offline it reaches nothing (69), and the notice came first.
    for words in [&["a", "host:b"][..], &["host:a", "."][..], &["host:a", "other:b"][..]] {
        let (rc, _, err) = mv(words);
        assert_eq!(rc, 69, "{words:?}: {err}");
        let first = err.lines().next().unwrap_or_default();
        assert!(first.contains("are on different hosts") && first.ends_with("it is not atomic"), "{words:?}: {err}");
    }
    // Within one server the server renames: no notice.
    let (rc, _, err) = mv(&["host:a", "host:b"]);
    assert_eq!(rc, 69, "{err}");
    assert!(!err.contains("different hosts"), "{err}");
    // -q: no notice either.
    let (rc, _, err) = mv(&["-q", "a", "host:b"]);
    assert_eq!(rc, 69, "{err}");
    assert!(!err.contains("different hosts"), "{err}");
}
