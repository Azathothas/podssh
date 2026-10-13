//! `podssh health` (T-189) against the test's SSH server, which answers its
//! script as a Debian host does (`ssh_harness/health.rs`): one line for
//! each fact, the same facts as one JSON object, and the codes of a
//! failure. The reader of the answer has its own tests (`health::parse`).

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-health-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
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

struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
}

/// `podssh health --direct -p PORT ARGS u@127.0.0.1`.
fn health(dir: &Path, port: u16, args: &[&str]) -> Ran {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["health", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes", "-o", "IdentityAgent=none"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.args(args).arg("u@127.0.0.1");
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("HOME", dir).env("USERPROFILE", dir);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    Ran {
        code: out.status.code(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// One line for each fact, read from the server's answer, and exit 0.
#[test]
fn the_facts_are_one_line_each() {
    let dir = scratch("lines");
    let (_runtime, port) = server(&dir);
    let ran = health(&dir, port, &[]);
    assert_eq!(ran.code, Some(0), "{}", ran.err);
    let lines: Vec<&str> = ran.out.lines().collect();
    assert_eq!(lines.first().copied(), Some("host u@127.0.0.1"), "{}", ran.out);
    for want in [
        "load 0.15 0.21 0.18 (1, 5 and 15 min), 2 CPUs",
        "cpu 7.8 % busy over 1.0 s",
        "uptime 12 days 15 h 47 min",
        "disk /: 12.0 GiB used of 39.1 GiB (31 %), 25.1 GiB available",
        "processes 146",
    ] {
        assert!(lines.contains(&want), "{want}: {}", ran.out);
    }
    let memory = lines.iter().find(|l| l.starts_with("memory ")).expect("the memory's line");
    assert!(memory.starts_with("memory 2.4 GiB available of 3.8 GiB (64 %); swap "), "{memory}");
    let network: Vec<&&str> = lines.iter().filter(|l| l.starts_with("network ")).collect();
    assert_eq!(network.len(), 1, "the loopback is left out: {}", ran.out);
    assert!(network[0].starts_with("network eth0: 9.2 GiB in, 1.2 GiB out since the start; now 97.7 KiB/s in"));
}

/// `--json`: one object, with the available memory of `MemAvailable`.
#[test]
fn the_json_is_one_object() {
    let dir = scratch("json");
    let (_runtime, port) = server(&dir);
    let ran = health(&dir, port, &["--json"]);
    assert_eq!(ran.code, Some(0), "{}", ran.err);
    let doc: Value = serde_json::from_str(&ran.out).unwrap_or_else(|e| panic!("{e}: {}", ran.out));
    assert_eq!((doc["schema"].as_u64(), doc["exit"].as_i64()), (Some(1), Some(0)), "{doc}");
    assert_eq!(doc["destination"], "u@127.0.0.1");
    assert_eq!(doc["memory"]["available_kib"], 2561432, "{doc}");
    assert_eq!(doc["memory"]["available_estimated"], false, "{doc}");
    assert_eq!(doc["network"][0]["interface"], "eth0", "{doc}");
    assert_eq!(doc["disks"].as_array().map(Vec::len), Some(1), "{doc}");
    assert_eq!((doc["processes"].as_u64(), doc["error"].as_str()), (Some(146), None), "{doc}");
}

/// A failure gives the code of `podssh ssh`, 255, and says why on stderr;
/// with `--json`, the object holds the error. No host is a usage error.
#[test]
fn a_failure_is_255_and_no_host_is_64() {
    let dir = scratch("fail");
    let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = gone.local_addr().unwrap().port();
    drop(gone);
    let ran = health(&dir, closed, &[]);
    assert_eq!(ran.code, Some(255), "{}", ran.err);
    assert!(ran.out.is_empty(), "stdout is for the facts: {}", ran.out);
    assert!(ran.err.contains("podssh: health u@127.0.0.1: "), "{}", ran.err);
    let ran = health(&dir, closed, &["--json"]);
    assert_eq!(ran.code, Some(255), "{}", ran.err);
    let doc: Value = serde_json::from_str(&ran.out).unwrap_or_else(|e| panic!("{e}: {}", ran.out));
    assert_eq!(doc["exit"], 255, "{doc}");
    assert!(doc["error"].as_str().is_some_and(|e| !e.is_empty()), "{doc}");
    let out = Command::new(env!("CARGO_BIN_EXE_podssh")).args(["health", "--direct"]).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("podssh health: give the host"));
}
