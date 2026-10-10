//! `podssh pipe A B` (T-174) as a process, with podssh itself as the child,
//! so that no other tool is needed, on Windows too: the child's output and
//! its status come through, an address is checked before anything starts,
//! and a descriptor that is not open is refused.

use std::process::{Command, Stdio};

/// `podssh pipe ARGS`, stdin at its end: (code, stdout, stderr).
fn pipe(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .arg("pipe")
        .args(args)
        .env_remove("PAGER")
        .stdin(Stdio::null())
        .output()
        .expect("podssh runs");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// `exec:` of podssh itself with `words`, its path in quotes.
fn podssh_with(words: &str) -> String {
    format!("exec:'{}' {words}", env!("CARGO_BIN_EXE_podssh"))
}

#[test]
fn the_child_s_output_comes_through_and_its_status_is_the_pipe_s() {
    let (code, out, err) = pipe(&["stdio", &podssh_with("man --no-pager")]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("podssh pipe"), "the manual came through: {} bytes", out.len());
    // The child's own status, a usage error.
    let (code, _, err) = pipe(&["-", &podssh_with("man nonsense")]);
    assert_eq!(code, 64, "{err}");
    // With a child on each side, B's status.
    let (code, _, err) = pipe(&[&podssh_with("--version"), &podssh_with("man nonsense")]);
    assert_eq!(code, 64, "{err}");
}

#[test]
fn a_program_that_is_not_found_gives_127_as_a_shell_gives() {
    let (code, out, err) = pipe(&["stdio", "exec:podssh-no-such-program --x"]);
    assert_eq!(code, 127, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("podssh-no-such-program"), "{err}");
}

#[test]
fn each_address_is_checked_before_anything_starts() {
    for (args, code, says) in [
        (&["stdio", "-"][..], 64, "stdio on both sides"),
        (&["stdio"][..], 64, "missing B"),
        (&[][..], 64, "missing A and B"),
        (&["stdio", "udp:example.org:80"][..], 64, "the kinds are"),
        (&["stdio", "exec:sh -c 'exit"][..], 64, "does not close"),
        (&["stdio", "unix-connect:/run/x.sock"][..], 70, "not built yet"),
        (&["fd:x", "stdio"][..], 64, "fd:"),
    ] {
        let (rc, out, err) = pipe(args);
        assert_eq!(rc, code, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

/// A number that no test runner hands on: cargo's jobserver can leave low
/// ones open.
#[test]
fn a_descriptor_that_is_not_open_is_refused() {
    let (code, _, err) = pipe(&["fd:987", "stdio"]);
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("fd:987"), "{err}");
}
