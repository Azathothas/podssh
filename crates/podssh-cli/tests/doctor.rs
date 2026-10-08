//! `podssh doctor` as a process: the report on stdout, the counts, the exit
//! code, and nothing secret in the output. The default tests run offline
//! (`PODSSH_OFFLINE`), where the network checks must be reported as not
//! attempted, never as passing. The live test is opt-in:
//!
//! ```sh
//! cargo test -p podssh-cli --test doctor -- --ignored
//! ```

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Every variable that could steer the doctor somewhere this test did not
/// choose.
const STEERING: &[&str] = &[
    "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY",
    "PODSSH_RELAY", "PODSSH_RELAY_ADDR", "PODSSH_RELAY_TOKEN", "SSL_CERT_FILE",
];

struct Run {
    code: i32,
    out: String,
    err: String,
}

/// A fresh directory to stand in for HOME.
fn scratch_home() -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-doctor-test-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `podssh doctor ARGS` with HOME in a scratch directory, nothing
/// steering it but `set`, and every variable in `unset` removed.
fn doctor(args: &[&str], set: &[(&str, &str)], unset: &[&str], offline: bool) -> Run {
    let home = scratch_home();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("doctor").args(args).env("HOME", &home).env("USERPROFILE", &home);
    for name in STEERING {
        cmd.env_remove(name);
    }
    if offline {
        cmd.env("PODSSH_OFFLINE", "1");
    } else {
        cmd.env_remove("PODSSH_OFFLINE");
    }
    for (name, value) in set {
        cmd.env(name, value);
    }
    for name in unset {
        cmd.env_remove(name);
    }
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the podssh binary runs");
    let _ = std::fs::remove_dir_all(&home);
    Run {
        code: output.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&output.stdout).into_owned(),
        err: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// The counts on the summary line: (ok, FAIL, ????).
fn counts(out: &str) -> (usize, usize, usize) {
    let line = out.lines().rev().find(|l| l.contains(" ok, ")).unwrap_or_else(|| panic!("no summary:\n{out}"));
    let mut numbers = line.split([' ', ',']).filter_map(|w| w.parse::<usize>().ok());
    (numbers.next().unwrap(), numbers.next().unwrap(), numbers.next().unwrap())
}

#[test]
fn offline_the_network_is_not_attempted_and_never_reported_ok() {
    let run = doctor(&[], &[], &[], true);
    assert_eq!(run.code, 0, "{}{}", run.out, run.err);
    assert!(run.err.is_empty(), "the report belongs on stdout: {}", run.err);
    for section in ["this host", "egress"] {
        assert!(run.out.lines().any(|l| l == section), "no {section} section:\n{}", run.out);
    }
    assert!(
        run.out.contains("  ????  network        not attempted: PODSSH_OFFLINE is set"),
        "{}",
        run.out
    );
    assert!(!run.out.contains("\nrelay\n"), "the relay section ran offline:\n{}", run.out);
    let (ok, failed, unknown) = counts(&run.out);
    assert_eq!(failed, 0, "{}", run.out);
    assert!(ok >= 5 && unknown >= 1, "{}", run.out);
    // Every check line carries one of the three labels and nothing else.
    for line in run.out.lines().filter(|l| l.starts_with("  ")) {
        let label = line.split_whitespace().next().unwrap();
        assert!(["ok", "FAIL", "????"].contains(&label), "{line}");
    }
}

#[test]
fn without_home_host_keys_cannot_be_recorded_and_the_run_fails() {
    // The planted defect: no HOME at all. Exit 1, and the line says why.
    let run = doctor(&[], &[], &["HOME", "USERPROFILE"], true);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("  FAIL  known_hosts    HOME is not set"), "{}", run.out);
    assert_eq!(counts(&run.out).1, 1, "{}", run.out);
}

#[test]
fn a_proxy_is_named_and_its_credentials_never_appear() {
    let run = doctor(&[], &[("https_proxy", "http://alice:s3cr3t-pass@proxy.example:3128")], &[], true);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(
        run.out.contains("https_proxy names proxy.example:3128 with credentials (not shown)"),
        "{}",
        run.out
    );
    assert!(!run.out.contains("s3cr3t") && !run.out.contains("alice"), "{}", run.out);
}

#[test]
fn an_unusable_proxy_fails_without_echoing_its_credentials() {
    let run = doctor(&[], &[("HTTPS_PROXY", "socks5://alice:s3cr3t-pass@proxy.example:1080")], &[], true);
    assert_eq!(run.code, 1, "{}", run.out);
    // Windows reads variable names without regard to case, so the name
    // reported can be either spelling.
    let lower = run.out.to_ascii_lowercase();
    assert!(lower.contains("  fail  proxy          https_proxy is set but cannot be used"), "{}", run.out);
    assert!(!run.out.contains("s3cr3t") && !run.out.contains("alice"), "{}", run.out);
}

#[test]
fn a_token_in_the_environment_is_never_printed() {
    let token = "podssh-test-token-0123456789abcdef";
    let run = doctor(&[], &[("PODSSH_RELAY_TOKEN", token)], &[], true);
    assert!(!run.out.contains(token) && !run.err.contains(token), "{}{}", run.out, run.err);
}

#[test]
fn bad_relay_settings_are_usage_errors_with_nothing_on_stdout() {
    for args in [["--relay-addr", "not-a-pin"], ["--relay-host", "not a host"]] {
        let run = doctor(&args, &[], &[], true);
        assert_eq!(run.code, 64, "{args:?}: {}{}", run.out, run.err);
        assert!(run.out.is_empty(), "{args:?}: {}", run.out);
        assert!(run.err.starts_with("podssh doctor: "), "{args:?}: {}", run.err);
    }
}

#[test]
#[ignore = "network: checks the live relay and reaches github.com:22 through it"]
fn the_live_relay_path_checks_out_end_to_end() {
    let run = doctor(&[], &[], &[], false);
    assert_eq!(run.code, 0, "{}{}", run.out, run.err);
    assert!(run.out.contains("certificate verified for tcp.ssh.relay.ajam.dev"), "{}", run.out);
    assert!(run.out.contains("  ok    token"), "{}", run.out);
    let forward = run.out.lines().find(|l| l.contains("forward")).unwrap_or_default();
    assert!(forward.starts_with("  ok") && forward.contains("one of GitHub"), "{}", run.out);
    assert_eq!(counts(&run.out).1, 0, "{}", run.out);
}
