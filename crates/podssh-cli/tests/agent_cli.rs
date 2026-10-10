//! `podssh agent` as processes (T-034): the agent serves and says
//! `SSH_AUTH_SOCK`; `add` sends a key, `list` shows it, and `podssh ssh`
//! logs in with it, with no `-i`, to the test's SSH server, which needs a
//! key for a user named `key-...`; `remove` takes it back, and then the
//! login fails. The agent ends at a kill, and its socket goes.

mod cleanup;
mod ssh_harness;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-agent-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// podssh with a clean environment: `home` as HOME, and `sock` as
/// SSH_AUTH_SOCK when given.
fn podssh(home: &Path, sock: Option<&str>, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("HOME", home).env("USERPROFILE", home).env("PODSSH_SSH_CONFIG", "none");
    for name in
        ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_ASKPASS", "PODSSH_LISTEN"]
    {
        cmd.env_remove(name);
    }
    match sock {
        Some(sock) => cmd.env("SSH_AUTH_SOCK", sock),
        None => cmd.env_remove("SSH_AUTH_SOCK"),
    };
    cmd
}

/// Run to the end, within the limit.
fn ran(mut cmd: Command) -> Output {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

/// A process that is killed when the test ends, also when it fails.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The agent, started, and the socket of its line `SSH_AUTH_SOCK=...;`.
fn agent(home: &Path, args: &[&str]) -> (Running, String) {
    let mut all = vec!["agent"];
    all.extend_from_slice(args);
    let mut child =
        podssh(home, None, &all).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let first = lines.next().expect("a line").expect("the line of SSH_AUTH_SOCK");
    let sock = first
        .strip_prefix("SSH_AUTH_SOCK=")
        .and_then(|rest| rest.split_once(';'))
        .map(|(sock, _)| sock.to_string())
        .unwrap_or_else(|| panic!("not the line of SSH_AUTH_SOCK: {first}"));
    std::thread::spawn(move || for _ in lines {});
    (Running(child), sock)
}

#[test]
fn agent_serves_and_podssh_ssh_logs_in_with_its_key() {
    let home = scratch("serve");
    let key = home.join("id_agent");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-C", "agent-test", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let host_key = home.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&host_key));

    let (running, sock) = agent(&home, &[]);
    let empty = ran(podssh(&home, Some(&sock), &["agent", "list"]));
    assert_eq!(empty.status.code(), Some(1), "{}", String::from_utf8_lossy(&empty.stderr));
    assert!(String::from_utf8_lossy(&empty.stdout).contains("The agent has no identities."));

    let added = ran(podssh(&home, Some(&sock), &["agent", "add", key.to_str().unwrap()]));
    assert_eq!(added.status.code(), Some(0), "{}", String::from_utf8_lossy(&added.stderr));
    let listed = ran(podssh(&home, Some(&sock), &["agent", "list"]));
    let out = String::from_utf8_lossy(&listed.stdout);
    assert_eq!(listed.status.code(), Some(0), "{out}");
    // russh's agent keeps no comment: the fingerprint and the type.
    let fingerprint = String::from_utf8_lossy(
        &ran({
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
            cmd.args(["keygen", "-l", "-f"]).arg(&key);
            cmd
        })
        .stdout,
    )
    .split_whitespace()
    .nth(1)
    .unwrap_or_default()
    .to_string();
    assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");
    assert!(out.starts_with("256 ") && out.contains(&fingerprint) && out.contains("(ED25519)"), "{out}");

    let login = |sock: Option<&str>| {
        let known = home.join("known_hosts");
        let mut cmd = podssh(&home, sock, &["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes"]);
        cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
        cmd.arg(format!("UserKnownHostsFile={}", known.display()));
        cmd.args(["key-agent@127.0.0.1", "greet"]);
        ran(cmd)
    };
    let with = login(Some(&sock));
    assert_eq!(with.status.code(), Some(0), "the agent's key: {}", String::from_utf8_lossy(&with.stderr));
    let removed = ran(podssh(&home, Some(&sock), &["agent", "remove", "--all"]));
    assert_eq!(removed.status.code(), Some(0), "{}", String::from_utf8_lossy(&removed.stderr));
    let without = login(Some(&sock));
    assert_eq!(without.status.code(), Some(255), "no key: {}", String::from_utf8_lossy(&without.stderr));

    drop(running);
    #[cfg(unix)]
    assert!(!Path::new(&sock).exists(), "the socket went: {sock}");
}

#[test]
fn agent_subcommands_with_no_agent_say_so() {
    let home = scratch("none");
    let out = ran(podssh(&home, None, &["agent", "list"]));
    let err = String::from_utf8_lossy(&out.stderr);
    if cfg!(unix) {
        assert_eq!(out.status.code(), Some(69), "{err}");
        assert!(err.contains("SSH_AUTH_SOCK is not set"), "{err}");
    }
    let usage = ran(podssh(&home, None, &["agent", "frob"]));
    assert_eq!(usage.status.code(), Some(64), "{}", String::from_utf8_lossy(&usage.stderr));
}

#[test]
fn agent_refuses_to_listen_when_listening_is_off() {
    let home = scratch("off");
    let mut cmd = podssh(&home, None, &["agent"]);
    cmd.env("PODSSH_LISTEN", "no");
    let out = ran(cmd);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(78), "{err}");
    assert!(err.contains("PODSSH_LISTEN=no"), "{err}");
}
