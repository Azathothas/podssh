//! The exit code of `podssh ssh` when a session does not end with its
//! status on stdout (T-026), against the test's SSH server on the loopback:
//! a closed stdout waits for the status, 5 s at most, and never reads as a
//! success; `-N` that the server ends is 255, with the server's words.

mod cleanup;
mod ssh_harness;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-exit-status-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The test's server, with a new host key, on a runtime of its own.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    (runtime, port)
}

/// `podssh ssh --direct` to the server as `user`.
fn ssh(home: &Path, port: u16, args: &[&str]) -> Command {
    let known = home.join("known_hosts");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", known.display()));
    cmd.args(args);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd
}

/// Read some of stdout, then close it; the code and stderr, within the limit.
fn close_early(mut cmd: Command) -> (i32, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    stdout.read_exact(&mut buf).expect("the remote's bytes come");
    drop(stdout);
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh did not end within {LIMIT:?} after its stdout closed");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_closed_stdout_waits_for_the_status_and_gives_it() {
    let home = scratch("status");
    let (_runtime, port) = server(&home);
    let (code, err) = close_early(ssh(&home, port, &["tester@127.0.0.1", "spew"]));
    assert_eq!(code, 7, "the remote's status after its end of input: {err}");
}

#[test]
fn a_closed_stdout_with_no_status_is_never_a_success() {
    let home = scratch("mute");
    let (_runtime, port) = server(&home);
    let (code, err) = close_early(ssh(&home, port, &["tester@127.0.0.1", "spew-mute"]));
    assert_eq!(code, 255, "{err}");
}

#[test]
fn a_dash_n_session_that_the_server_ends_is_255_with_its_words() {
    let home = scratch("dash-n");
    let (_runtime, port) = server(&home);
    let mut cmd = ssh(&home, port, &["-N", "kick@127.0.0.1"]);
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh -N did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert!(err.contains("the server ended the connection") && err.contains("kicked by the test"), "{err}");
}
