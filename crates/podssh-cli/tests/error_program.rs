//! `PODSSH_ERROR_PROGRAM` (T-195), against the binary: podssh hands the
//! report of its own failure to the program, and starts none after a
//! success, or for the status of a remote command on the test's SSH server,
//! 255 included. The program is this test binary itself, as the variable
//! takes no argument: run with none, it runs each test, and each test
//! first copies its stdin to the file of [`REPORT_TO`] and exits, on
//! Windows as on Unix.

mod cleanup;
mod ssh_harness;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Where this binary, run as the program, writes the report it got, and
/// beside it, in `.env`, which of the variables below it saw.
const REPORT_TO: &str = "PODSSH_TEST_REPORT_TO";
/// Set for [`sleeper`], which then runs for longer than any limit.
const SLEEP: &str = "PODSSH_TEST_SLEEP";
/// What the program must not get in its environment.
const KEPT_FROM_IT: [&str; 2] = ["PODSSH_RELAY_TOKEN", "PODSSH_ERROR_PROGRAM"];

const TOKEN: &str = "podssh-test-token-0123456789abcdef";
const PROXY: &str = "http://alice:s3cr3t-pass@proxy.example:3128";

/// This binary as the program: the report on stdin into the file of
/// [`REPORT_TO`], then the end of the process. Each test calls it first.
fn as_program() {
    let Some(to) = std::env::var_os(REPORT_TO) else { return };
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = ONE.lock();
    let mut report = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut report);
    let seen: Vec<&str> = KEPT_FROM_IT.into_iter().filter(|name| std::env::var_os(name).is_some()).collect();
    let mut env = PathBuf::from(&to).into_os_string();
    env.push(".env");
    let _ = std::fs::write(env, seen.join(","));
    let _ = std::fs::write(to, report);
    std::process::exit(0);
}

/// A program that runs for a minute, for the limit's test; else nothing.
#[test]
#[ignore = "the program of the limit's test; not a test of its own"]
fn sleeper() {
    if std::env::var_os(SLEEP).is_some() {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-error-program-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

struct Ran {
    code: Option<i32>,
    err: String,
    /// The report that the program got, when it ran.
    report: Option<Value>,
    /// The variables of [`KEPT_FROM_IT`] that the program saw.
    seen: Option<String>,
}

/// `podssh ARGS` with `program` as the program, and the variables `set`
/// over a clean environment; offline unless `set` says otherwise.
fn run(dir: &Path, program: &Path, args: &[&str], set: &[(&str, &str)]) -> Ran {
    let report = dir.join("report.json");
    let seen = dir.join("report.json.env");
    let _ = std::fs::remove_file(&report);
    let _ = std::fs::remove_file(&seen);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_ERROR_PROGRAM", program).env(REPORT_TO, &report);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("HOME", dir).env("USERPROFILE", dir);
    cmd.env("PODSSH_OFFLINE", "1");
    for name in ["PODSSH_RELAY_TOKEN", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    for (name, value) in set {
        match *value {
            "" => cmd.env_remove(name),
            value => cmd.env(name, value),
        };
    }
    let started = Instant::now();
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    assert!(started.elapsed() < Duration::from_secs(60), "{args:?} took {:?}", started.elapsed());
    let report = std::fs::read_to_string(&report).ok().map(|text| {
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("the report is not one JSON object ({e}): {text}"))
    });
    Ran {
        code: out.status.code(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
        report,
        seen: std::fs::read_to_string(&seen).ok(),
    }
}

fn me() -> PathBuf {
    std::env::current_exe().unwrap()
}

/// A usage error: exit 64, and a report with the command, the code and the
/// refusal.
#[test]
fn a_usage_error_gives_a_report() {
    as_program();
    let dir = scratch("usage");
    let ran = run(&dir, &me(), &["ssh", "-o", "NoSuchKeyword=1", "host.example"], &[]);
    assert_eq!(ran.code, Some(64), "{}", ran.err);
    let report = ran.report.unwrap_or_else(|| panic!("no report: {}", ran.err));
    assert_eq!(report["schema"], 1, "{report}");
    assert_eq!((report["verb"].as_str(), report["exit"].as_i64()), (Some("ssh"), Some(64)), "{report}");
    let messages = report["messages"].to_string();
    assert!(messages.contains("-o NoSuchKeyword: unknown option"), "{report}");
    assert_eq!(report["relay"], Value::Null, "{report}");
}

/// No relay host can be reached: exit 69, and a report.
#[test]
fn an_unavailable_relay_gives_a_report() {
    as_program();
    let dir = scratch("offline");
    let ran = run(&dir, &me(), &["proxy", "example.org", "80"], &[]);
    assert_eq!(ran.code, Some(69), "{}", ran.err);
    let report = ran.report.unwrap_or_else(|| panic!("no report: {}", ran.err));
    assert_eq!((report["verb"].as_str(), report["exit"].as_i64()), (Some("proxy"), Some(69)), "{report}");
    assert!(report["messages"].as_array().is_some_and(|m| !m.is_empty()), "{report}");
}

/// A success starts no program.
#[test]
fn a_success_gives_none() {
    as_program();
    let dir = scratch("success");
    for args in [&["--version"][..], &["man", "--no-pager", "exit-status"][..]] {
        let ran = run(&dir, &me(), args, &[]);
        assert_eq!(ran.code, Some(0), "{args:?}: {}", ran.err);
        assert!(ran.report.is_none(), "{args:?}: {:?}", ran.report);
    }
}

/// With a token and a proxy URL with its user and password in the
/// environment, neither is in the report, and the program gets neither the
/// token nor the variable that named it.
#[test]
fn a_report_holds_no_credential() {
    as_program();
    let dir = scratch("secrets");
    let set = [("PODSSH_RELAY_TOKEN", TOKEN), ("https_proxy", PROXY)];
    let ran = run(&dir, &me(), &["proxy", "example.org", "80"], &set);
    assert_eq!(ran.code, Some(69), "{}", ran.err);
    let report = ran.report.unwrap_or_else(|| panic!("no report: {}", ran.err)).to_string();
    for secret in [TOKEN, "s3cr3t", "alice", PROXY] {
        assert!(!report.contains(secret), "{secret}: {report}");
    }
    assert_eq!(ran.seen.as_deref(), Some(""), "the program saw these: {:?}", ran.seen);
}

/// A program that does not start: one line on stderr, and the run's code.
#[test]
fn a_program_that_does_not_start_is_one_line() {
    as_program();
    let dir = scratch("missing");
    let ran = run(&dir, &dir.join("no-such-program"), &["ssh", "-o", "NoSuchKeyword=1", "host.example"], &[]);
    assert_eq!(ran.code, Some(64), "{}", ran.err);
    let said: Vec<&str> = ran.err.lines().filter(|l| l.contains("PODSSH_ERROR_PROGRAM")).collect();
    assert_eq!(said.len(), 1, "{}", ran.err);
    assert!(said[0].contains("did not start"), "{}", ran.err);
}

/// A program that does not end is stopped at the limit; podssh goes on.
#[test]
fn a_program_is_stopped_at_its_limit() {
    as_program();
    let mut sleeper = Command::new(me());
    sleeper.args(["sleeper", "--exact", "--ignored"]).env(SLEEP, "1");
    let mut err = Vec::new();
    let started = Instant::now();
    podssh_cli::error_program::give(sleeper, b"{}\n", Duration::from_secs(1), &mut err);
    let took = started.elapsed();
    let err = String::from_utf8_lossy(&err);
    assert!(took < Duration::from_secs(20), "the program ran for {took:?}: {err}");
    assert!(err.contains("did not end within 1 s, and was stopped"), "{err}");
}

/// The test's server, with a new host key, on a runtime of its own.
fn server(dir: &Path) -> (tokio::runtime::Runtime, u16) {
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    (runtime, port)
}

/// `podssh ssh --direct` to `port` as `u`, running `command`, online.
fn ssh(dir: &Path, port: u16, command: &[&str]) -> Ran {
    let known = format!("UserKnownHostsFile={}", dir.join("known_hosts").display());
    let port = port.to_string();
    let mut args = vec!["ssh", "--direct", "-p", port.as_str()];
    args.extend(["-o", "BatchMode=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=accept-new"]);
    args.extend(["-o", known.as_str(), "u@127.0.0.1"]);
    args.extend(command);
    run(dir, &me(), &args, &[("PODSSH_OFFLINE", "")])
}

/// The remote command's status, 3, 143 for a signal, and 255, starts no
/// program: the code path decides, not the number. A failure of podssh to
/// connect does.
#[test]
fn a_remote_status_starts_no_program() {
    as_program();
    let dir = scratch("remote");
    let (_runtime, port) = server(&dir);
    for (command, code) in [(&["exit", "3"][..], 3), (&["kill", "TERM"][..], 143), (&["exit", "255"][..], 255)] {
        let ran = ssh(&dir, port, command);
        assert_eq!(ran.code, Some(code), "{command:?}: {}", ran.err);
        assert!(ran.report.is_none(), "{command:?}: {:?}", ran.report);
    }
    let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = gone.local_addr().unwrap().port();
    drop(gone);
    let ran = ssh(&dir, closed, &["true"]);
    assert_eq!(ran.code, Some(255), "{}", ran.err);
    let report = ran.report.unwrap_or_else(|| panic!("no report: {}", ran.err));
    assert_eq!((report["verb"].as_str(), report["exit"].as_i64()), (Some("ssh"), Some(255)), "{report}");
    assert!(report["messages"].to_string().contains("could not connect"), "{report}");
}
