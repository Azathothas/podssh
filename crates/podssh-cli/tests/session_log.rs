//! The log of the sessions of this host (T-056): `podssh ssh` against the
//! test's SSH server, with `--direct`, and `podssh proxy` offline. With no
//! `PODSSH_SESSION_LOG` and no `SessionLog`, no file appears; with one, each
//! run adds one whole line, which never holds its command.

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-session-log-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Private, as the user's own directories are: the settings file is checked.
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// podssh with this test's cache, settings and home, and `log` as the
/// variable (none: unset).
fn podssh(dir: &Path, log: Option<&str>) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.env("PODSSH_CACHE_DIR", dir.join("cache")).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    cmd.env("HOME", dir).env("USERPROFILE", dir).stdin(Stdio::null());
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    match log {
        Some(value) => cmd.env("PODSSH_SESSION_LOG", value),
        None => cmd.env_remove("PODSSH_SESSION_LOG"),
    };
    cmd
}

fn ssh(dir: &Path, port: u16, log: Option<&str>, command: &str) -> Command {
    let mut cmd = podssh(dir, log);
    cmd.args(["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"]);
    cmd.args(["-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.args(["u@127.0.0.1", command]);
    cmd
}

fn server(dir: &Path) -> (tokio::runtime::Runtime, u16) {
    let key = dir.join("host_key");
    let made = podssh(dir, None).args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    (runtime, port)
}

fn lines(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: a broken line {l:?}"))).collect()
}

fn ok(out: &Output, code: i32) {
    assert_eq!(out.status.code(), Some(code), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn each_run_adds_one_line_and_none_without_the_variable() {
    let dir = scratch("runs");
    let (_runtime, port) = server(&dir);
    let file = dir.join("cache").join("sessions.jsonl");
    ok(&ssh(&dir, port, None, "exit 3").output().unwrap(), 3);
    ok(&ssh(&dir, port, Some("0"), "exit 3").output().unwrap(), 3);
    assert!(!file.exists(), "a log with no PODSSH_SESSION_LOG");
    ok(&ssh(&dir, port, Some("1"), "exit 3").output().unwrap(), 3);
    ok(&ssh(&dir, port, Some("yes"), "exit 0 SECRET-WORD").output().unwrap(), 0);
    let logged = lines(&file);
    assert_eq!(logged.len(), 2, "{logged:?}");
    let first = &logged[0];
    assert_eq!(
        (first["verb"].clone(), first["host"].clone(), first["port"].clone()),
        ("ssh".into(), "127.0.0.1".into(), port.into())
    );
    assert_eq!(
        (first["via"].clone(), first["end"].clone(), first["exit"].clone()),
        ("direct".into(), "status".into(), 3.into())
    );
    assert_eq!(first["bytes"]["stdout"], 4, "{first}");
    assert!(first["start"].as_str().unwrap().ends_with('Z') && first["duration_ms"].is_u64(), "{first}");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains("SECRET-WORD") && !text.contains("exit 0"), "the command was logged: {text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // podssh status shows the last line.
    let out = podssh(&dir, Some("1")).arg("status").output().unwrap();
    ok(&out, 0);
    let status: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(status["session_log"]["last"]["exit"], 0, "{status}");
    assert_eq!(status["session_log"]["file"], file.display().to_string());
    let out = podssh(&dir, None).arg("status").output().unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&out.stdout).unwrap()["session_log"], Value::Null);
}

#[test]
fn two_runs_at_once_give_two_whole_lines_in_the_file_named() {
    let dir = scratch("together");
    let (_runtime, port) = server(&dir);
    let file = dir.join("named.jsonl");
    let named = file.display().to_string();
    let spawn = |mut cmd: Command| cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let runs: Vec<_> = (0..2).map(|_| spawn(ssh(&dir, port, Some(&named), "exit 5"))).collect();
    for run in runs {
        assert_eq!(run.wait_with_output().unwrap().status.code(), Some(5));
    }
    let logged = lines(&file);
    assert_eq!(logged.len(), 2, "{logged:?}");
    assert!(logged.iter().all(|l| l["exit"] == 5));
}

#[test]
fn the_settings_file_turns_it_on_and_the_variable_off() {
    let dir = scratch("settings");
    let (_runtime, port) = server(&dir);
    let settings = dir.join("settings");
    std::fs::write(&settings, "# podssh\nSessionLog yes\n").unwrap();
    let file = dir.join("cache").join("sessions.jsonl");
    let mut run = ssh(&dir, port, None, "exit 0");
    ok(&run.env("PODSSH_SETTINGS", &settings).output().unwrap(), 0);
    assert_eq!(lines(&file).len(), 1);
    let mut run = ssh(&dir, port, Some("no"), "exit 0");
    ok(&run.env("PODSSH_SETTINGS", &settings).output().unwrap(), 0);
    assert_eq!(lines(&file).len(), 1, "PODSSH_SESSION_LOG=no beats the file");
    // A bad value is refused before anything connects, as each variable's.
    let out = ssh(&dir, port, Some("maybe"), "exit 0").output().unwrap();
    ok(&out, 78);
    assert!(String::from_utf8_lossy(&out.stderr).contains("PODSSH_SESSION_LOG"));
    std::fs::write(&settings, "SessionLog sometimes\n").unwrap();
    let mut run = ssh(&dir, port, None, "exit 0");
    let out = run.env("PODSSH_SETTINGS", &settings).output().unwrap();
    ok(&out, 78);
    assert!(String::from_utf8_lossy(&out.stderr).contains("SessionLog"), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_proxy_that_could_not_open_is_a_line_too() {
    let dir = scratch("proxy");
    let file = dir.join("cache").join("sessions.jsonl");
    let out =
        podssh(&dir, Some("1")).env("PODSSH_OFFLINE", "1").args(["proxy", "db.example", "5432"]).output().unwrap();
    assert_ne!(out.status.code(), Some(0));
    let logged = lines(&file);
    assert_eq!(logged.len(), 1, "{}", String::from_utf8_lossy(&out.stderr));
    let line = &logged[0];
    assert_eq!(
        (line["verb"].clone(), line["host"].clone(), line["port"].clone()),
        ("proxy".into(), "db.example".into(), 5432.into())
    );
    assert_eq!(
        (line["end"].clone(), line["failure"].clone(), line["via"].clone()),
        ("failed".into(), "relay".into(), "relay".into())
    );
    // A usage error names no destination, and adds no line.
    let out = podssh(&dir, Some("1")).args(["proxy", "db.example"]).output().unwrap();
    ok(&out, 64);
    assert_eq!(lines(&file).len(), 1);
}
