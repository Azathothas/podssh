//! `podssh ssh` under `accept-new` when `known_hosts` cannot be read or
//! written (T-028), against the test's SSH server on the loopback: a user
//! file that cannot be read refuses an unknown key and names the file; a key
//! that cannot be recorded holds for this connection only, and podssh says
//! why.

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-host-keys-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The test's server, with a new host key, on a runtime of its own.
fn server(dir: &Path) -> (tokio::runtime::Runtime, u16) {
    let key = dir.join("host_key");
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

/// `podssh ssh --direct` under accept-new, with `known` as the user file
/// when given, and `home` as the home directory when given.
fn ssh(port: u16, known: Option<&Path>, home: Option<&Path>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new"]);
    if let Some(known) = known {
        cmd.arg("-o").arg(format!("UserKnownHostsFile={}", known.display()));
    }
    cmd.args(["tester@127.0.0.1", "true"]);
    cmd.env("PODSSH_SSH_CONFIG", "none");
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    match home {
        Some(home) => cmd.env("HOME", home).env("USERPROFILE", home),
        None => cmd.env_remove("HOME").env_remove("USERPROFILE"),
    };
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh ssh did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn an_unreadable_user_file_refuses_an_unknown_key_and_names_the_file() {
    let dir = scratch("unreadable");
    let (_runtime, port) = server(&dir);
    let known = dir.join("known_hosts.d");
    std::fs::create_dir(&known).unwrap();
    let out = ssh(port, Some(&known), Some(&dir));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert!(err.contains("known_hosts.d") && err.contains("cannot be verified"), "{err}");
}

#[test]
fn a_key_that_cannot_be_written_holds_for_this_connection_only() {
    let dir = scratch("unwritable");
    let (_runtime, port) = server(&dir);
    // A file where the directory of the user file would be: no write can
    // make it, on each system.
    std::fs::write(dir.join("plain"), b"a file").unwrap();
    let known = dir.join("plain").join("known_hosts");
    let out = ssh(port, Some(&known), Some(&dir));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("for this connection only") && err.contains("not recorded"), "{err}");
    assert!(err.contains("could not be written"), "{err}");
}

#[test]
fn with_no_home_the_key_is_not_recorded_and_the_note_says_why() {
    let dir = scratch("no-home");
    let (_runtime, port) = server(&dir);
    let out = ssh(port, None, None);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    let why = if cfg!(windows) { "neither HOME nor USERPROFILE is set" } else { "HOME is not set" };
    assert!(err.contains("for this connection only") && err.contains(why), "{err}");
}
