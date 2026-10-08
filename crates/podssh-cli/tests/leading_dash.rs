//! A host or a target that starts with `-`, against the binary: each shape
//! is refused with exit 64 before anything comes near a connection, and `--`
//! is the way to pass a host that a script did not write.

use std::process::{Command, Stdio};

/// Run the binary offline: a run that gets past each check stops at
/// `PODSSH_OFFLINE` with a line that names it.
fn podssh(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(args)
        .env("PODSSH_OFFLINE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the podssh binary runs");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn each_host_that_starts_with_a_dash_is_refused_before_a_connection() {
    let shapes: [&[&str]; 9] = [
        &["ssh", "--", "-oProxyCommand=x"],
        &["ssh", "--", "user@-x", "true"],
        &["ssh", "-J=-x", "host"],
        &["ssh", "--relay-host=-x", "host"],
        &["ssh", "--direct", "-o", "HostName=-x", "-l", "u", "host", "true"],
        &["ssh", "-o", "HostName=-x", "-l", "u", "host", "true"],
        &["ssh", "-l", "u", "--", "-oHostName=evil.example", "true"],
        &["proxy", "--", "-oX", "22"],
        &["proxy", "-", "22"],
    ];
    for argv in shapes {
        let (rc, err) = podssh(argv);
        assert_eq!(rc, 64, "{argv:?}: {err}");
        assert!(!err.contains("PODSSH_OFFLINE"), "{argv:?} came near a connection: {err}");
    }
}

#[test]
fn a_host_taken_as_a_flag_value_in_proxy_names_the_remedy() {
    let (rc, err) = podssh(&["proxy", "--relay-host=evil.example", "22"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("put -- before it"), "{err}");
}

/// The control: after `--` and the host, a word that starts with `-` is the
/// command, and the run reaches the offline stop.
#[test]
fn after_the_host_a_dash_word_is_the_command() {
    let (rc, err) = podssh(&["ssh", "-l", "u", "--", "host", "-x"]);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("PODSSH_OFFLINE"), "{err}");
}
