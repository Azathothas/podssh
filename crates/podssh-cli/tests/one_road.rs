//! A run has one road: `--vless` (T-440) and `--wstunnel` (T-441), each a
//! server of the user's in place of the relay, refuse each other with exit
//! 64 on `ssh` and on `proxy`, before a file is read or anything comes near
//! a connection. Each road was drafted with no sight of the other, so this
//! is their meeting.

use std::process::{Command, Stdio};

/// Run the binary offline: a run that gets past each check stops at
/// `PODSSH_OFFLINE` with a line that names it.
fn podssh(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(args)
        // The ssh_config of the machine that runs the test must not change it.
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_OFFLINE", "1")
        .env_remove("PODSSH_WSTUNNEL")
        .env_remove("PODSSH_VIA")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the podssh binary runs");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// No such file: a refusal that read it would say so, not name two roads.
const NO_FILE: &str = "/nonexistent/podssh-one-road.links";

#[test]
fn vless_and_wstunnel_name_two_roads_on_ssh_and_on_proxy() {
    let runs: [(&[&str], &str); 4] = [
        (&["ssh", "--vless", NO_FILE, "--wstunnel", "wss://w.example", "h.example", "true"], "--wstunnel"),
        (&["ssh", "--wstunnel", "wss://w.example", "--vless", NO_FILE, "h.example", "true"], "--wstunnel"),
        (&["proxy", "--vless", NO_FILE, "--wstunnel", "wss://w.example", "h.example", "22"], "--wstunnel"),
        (&["proxy", "--wstunnel", "wss://w.example", "--vless", NO_FILE, "h.example", "22"], "--vless"),
    ];
    for (argv, names) in runs {
        let (rc, err) = podssh(argv);
        assert_eq!(rc, 64, "{argv:?}: {err}");
        assert!(err.contains(names) && err.contains("road"), "{argv:?}: {err}");
        assert!(!err.contains("PODSSH_OFFLINE") && !err.contains("nonexistent"), "{argv:?}: {err}");
    }
}

/// The variable of wstunnel's road gives way to `--vless` on the command
/// line, as each road's flag wins over another road's variable.
#[test]
fn the_flag_of_vless_wins_over_the_variable_of_wstunnel() {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["ssh", "--vless", NO_FILE, "h.example", "true"])
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_OFFLINE", "1")
        .env("PODSSH_WSTUNNEL", "wss://w.example")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the podssh binary runs");
    let err = String::from_utf8_lossy(&out.stderr);
    // The run took --vless's file, which does not exist (78), and named no
    // second road.
    assert_eq!(out.status.code(), Some(78), "{err}");
    assert!(!err.contains("two roads"), "{err}");
}
