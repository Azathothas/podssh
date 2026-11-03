//! `podssh health` (T-189) against the test's SSH server, which answers its
//! script as a Debian host does (`ssh_harness/health.rs`), or as a container
//! with the limits of a cgroup does (T-480): one line for each fact, the
//! same facts as one JSON object, and the codes of a failure. The reader of
//! the answer has its own tests (`health::parse`, `health::cgroup`). With
//! `--preflight` (T-482), the server in two modes: one that allows each
//! probe, and one that refuses both forwards and has no SFTP.

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
    health_as(dir, port, "u", args)
}

/// [`health`] as `user`, whose name says what the server answers.
fn health_as(dir: &Path, port: u16, user: &str, args: &[&str]) -> Ran {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["health", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes", "-o", "IdentityAgent=none"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.args(args).arg(format!("{user}@127.0.0.1"));
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
    assert_eq!(doc["preflight"], Value::Null, "no preflight was asked for: {doc}");
}

/// A line of the preflight, as `doctor` prints one: its label, its check
/// and its detail.
fn check(line: &str) -> Option<(&str, &str, &str)> {
    let shaped = line.len() > 23 && line.starts_with("  ") && line.is_char_boundary(23);
    shaped.then(|| (line[2..6].trim(), line[8..22].trim(), &line[23..]))
}

/// The checks of the section `preflight` of a run's stdout, in order.
fn checks(out: &str) -> Vec<(&str, &str, &str)> {
    let lines: Vec<&str> = out.lines().collect();
    let at = lines.iter().position(|l| *l == "preflight").unwrap_or_else(|| panic!("no section: {out}"));
    lines[at + 1..].iter().copied().filter_map(check).collect()
}

/// `--preflight` against a server that allows each probe: after the facts,
/// each check `ok` in its order, the counts, and exit 0; the JSON holds the
/// same checks in the form of `doctor --json`.
#[test]
fn the_preflight_of_a_server_that_allows_each_probe_is_ok() {
    let dir = scratch("preflight-ok");
    let (_runtime, port) = server(&dir);
    let ran = health_as(&dir, port, "preflight-ok-u", &["--preflight"]);
    assert_eq!(ran.code, Some(0), "{}\n{}", ran.out, ran.err);
    assert!(ran.out.lines().any(|l| l == "processes 146"), "the facts come first: {}", ran.out);
    let got = checks(&ran.out);
    let names: Vec<&str> = got.iter().map(|(_, name, _)| *name).collect();
    let order = ["login", "road", "sftp", "remote forward", "jump", "exec tools", "tmux", "cgroup", "keepalive"];
    assert_eq!(names, order, "{}", ran.out);
    assert!(got.iter().all(|(label, ..)| *label == "ok"), "{}", ran.out);
    let detail = |name: &str| got.iter().find(|(_, n, _)| *n == name).map(|(.., d)| *d).unwrap_or_default();
    assert!(detail("login").starts_with("preflight-ok-u@127.0.0.1 with no method"), "{}", ran.out);
    assert!(detail("login").contains("the server's version: SSH-2.0-"), "{}", ran.out);
    assert!(detail("road").starts_with("direct: not the relay"), "{}", ran.out);
    assert!(detail("remote forward").contains("port 40022, and stopped at the cancel: -R works"), "{}", ran.out);
    assert!(detail("jump").ends_with("-J, -L, -D and -W through this host work"), "{}", ran.out);
    assert!(detail("keepalive").contains("with a failure"), "russh's server refuses it: {}", ran.out);
    assert_eq!(ran.out.lines().last(), Some("9 ok, 0 FAIL, 0 ???? (could not be checked)"), "{}", ran.out);
    let ran = health_as(&dir, port, "preflight-ok-u", &["--preflight", "--json"]);
    assert_eq!(ran.code, Some(0), "{}", ran.err);
    let doc: Value = serde_json::from_str(&ran.out).unwrap_or_else(|e| panic!("{e}: {}", ran.out));
    assert_eq!((doc["exit"].as_i64(), doc["processes"].as_u64()), (Some(0), Some(146)), "{doc}");
    let counts = &doc["preflight"]["counts"];
    let counted = (counts["ok"].as_u64(), counts["fail"].as_u64(), counts["unknown"].as_u64());
    assert_eq!(counted, (Some(9), Some(0), Some(0)), "{doc}");
    let listed = doc["preflight"]["checks"].as_array().expect("the checks");
    assert!(listed.iter().all(|c| c["section"] == "preflight" && c["status"] == "ok"), "{doc}");
    assert_eq!(listed[3]["check"], "remote forward", "{doc}");
}

/// A server that refuses `tcpip-forward`, answers `direct-tcpip` with
/// administratively prohibited and has no SFTP: both forwards `FAIL` with
/// what they stop, `sftp` `ok` with the copy by exec, and exit 1.
#[test]
fn the_preflight_names_what_a_refusing_server_stops() {
    let dir = scratch("preflight-no");
    let (_runtime, port) = server(&dir);
    let ran = health_as(&dir, port, "preflight-no-u", &["--preflight"]);
    assert_eq!(ran.code, Some(1), "{}\n{}", ran.out, ran.err);
    let got = checks(&ran.out);
    let of = |name: &str| got.iter().find(|(_, n, _)| *n == name).map(|(l, _, d)| (*l, *d)).unwrap_or_default();
    let (label, detail) = of("remote forward");
    assert_eq!(label, "FAIL", "{}", ran.out);
    assert!(detail.contains("refused tcpip-forward: -R cannot work on this host"), "{detail}");
    let (label, detail) = of("jump");
    assert_eq!(label, "FAIL", "{}", ran.out);
    assert!(detail.contains("open failed: administratively prohibited: -J, -L, -D and -W"), "{detail}");
    let (label, detail) = of("sftp");
    assert_eq!(label, "ok", "{}", ran.out);
    assert!(detail.starts_with("no SFTP subsystem: podssh cp copies by exec"), "{detail}");
    for name in ["login", "road", "exec tools", "tmux", "cgroup", "keepalive"] {
        assert_eq!(of(name).0, "ok", "{name}: {}", ran.out);
    }
    assert_eq!(ran.out.lines().last(), Some("7 ok, 2 FAIL, 0 ???? (could not be checked)"), "{}", ran.out);
    let ran = health_as(&dir, port, "preflight-no-u", &["--preflight", "--json"]);
    assert_eq!(ran.code, Some(1), "{}", ran.err);
    let doc: Value = serde_json::from_str(&ran.out).unwrap_or_else(|e| panic!("{e}: {}", ran.out));
    assert_eq!((doc["exit"].as_i64(), doc["preflight"]["counts"]["fail"].as_u64()), (Some(1), Some(2)), "{doc}");
    let failed: Vec<&str> = doc["preflight"]["checks"]
        .as_array()
        .expect("the checks")
        .iter()
        .filter(|c| c["status"] == "FAIL")
        .filter_map(|c| c["check"].as_str())
        .collect();
    assert_eq!(failed, ["remote forward", "jump"], "{doc}");
}

/// A login that fails with `--preflight`: 255, as without it, and the
/// section's one line, `login` `FAIL`, in the text and in the JSON.
#[test]
fn a_preflight_whose_login_fails_is_255_with_its_line() {
    let dir = scratch("preflight-fail");
    let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = gone.local_addr().unwrap().port();
    drop(gone);
    let ran = health(&dir, closed, &["--preflight"]);
    assert_eq!(ran.code, Some(255), "{}", ran.err);
    let got = checks(&ran.out);
    assert_eq!(got.iter().map(|(l, n, _)| (*l, *n)).collect::<Vec<_>>(), [("FAIL", "login")], "{}", ran.out);
    let ran = health(&dir, closed, &["--preflight", "--json"]);
    assert_eq!(ran.code, Some(255), "{}", ran.err);
    let doc: Value = serde_json::from_str(&ran.out).unwrap_or_else(|e| panic!("{e}: {}", ran.out));
    assert_eq!(doc["preflight"]["checks"][0]["check"], "login", "{doc}");
    assert_eq!(doc["preflight"]["checks"][0]["status"], "FAIL", "{doc}");
}

/// A container of 4 CPUs and 4 GiB on a host of 16 (T-480): the lines give
/// its own CPUs and memory with their sources, the host's beside them, and
/// the JSON keeps the host's keys and adds `effective` and `cgroup`; a host
/// with no cgroup gives `effective` too, from the host.
#[test]
fn a_container_gives_its_cgroup_s_cpus_and_memory() {
    let dir = scratch("cgroup");
    let (_runtime, port) = server(&dir);
    let ran = health_as(&dir, port, "health-v2-u", &[]);
    assert_eq!(ran.code, Some(0), "{}", ran.err);
    let lines: Vec<&str> = ran.out.lines().collect();
    for want in [
        "load 2.10 1.80 1.50 (1, 5 and 15 min), 16 CPUs: the whole host's",
        "cpus 4 (cgroup v2 cpu.max), 16 on the host",
        "cpu 25.0 % busy over 1.0 s, the host's; the cgroup's 62.5 % of 4 CPUs, throttled in 4 of 10 periods",
    ] {
        assert!(lines.contains(&want), "{want}: {}", ran.out);
    }
    let memory = lines.iter().find(|l| l.starts_with("memory ")).expect("the memory's line");
    assert!(
        memory.starts_with("memory 3.3 GiB available of 4.0 GiB (82 %, cgroup v2 memory.max); the host: "),
        "{memory}"
    );
    for (user, cpus_from, memory_from) in [
        ("health-v2-u", "cgroup v2 cpu.max", "cgroup v2 memory.max"),
        ("health-v1-u", "cgroup v1 cfs_quota_us", "cgroup v1 memory.limit_in_bytes"),
    ] {
        let ran = health_as(&dir, port, user, &["--json"]);
        assert_eq!(ran.code, Some(0), "{user}: {}", ran.err);
        let doc: Value = serde_json::from_str(&ran.out).unwrap_or_else(|e| panic!("{e}: {}", ran.out));
        assert_eq!((doc["cpus"].as_u64(), doc["memory"]["total_kib"].as_u64()), (Some(16), Some(65842388)), "{doc}");
        let e = &doc["effective"];
        assert_eq!((e["cpus"].as_f64(), e["cpus_from"].as_str()), (Some(4.0), Some(cpus_from)), "{user}: {doc}");
        assert_eq!(e["memory_total_kib"], 4 * 1024 * 1024, "{user}: {doc}");
        assert_eq!(e["memory_from"], memory_from, "{user}: {doc}");
        assert!(doc["cgroup"]["version"].is_u64(), "{user}: {doc}");
    }
    let ran = health_as(&dir, port, "health-free-u", &["--json"]);
    let doc: Value = serde_json::from_str(&ran.out).unwrap_or_else(|e| panic!("{e}: {}", ran.out));
    let e = &doc["effective"];
    assert_eq!((e["cpus"].as_f64(), e["cpus_from"].as_str()), (Some(16.0), Some("host")), "{doc}");
    assert_eq!(e["memory_from"], "host", "{doc}");
    let ran = health(&dir, port, &["--json"]);
    let doc: Value = serde_json::from_str(&ran.out).unwrap_or_else(|e| panic!("{e}: {}", ran.out));
    assert_eq!((doc["effective"]["cpus"].as_f64(), doc["cgroup"].clone()), (Some(2.0), Value::Null), "{doc}");
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
