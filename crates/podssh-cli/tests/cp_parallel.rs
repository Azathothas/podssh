//! `podssh cp --parallel K` (T-141), against the test's SSH server on the
//! loopback, whose subsystem `sftp` is OpenSSH's `sftp-server`: a file of
//! more than one chunk goes up and comes back down as chunks, K at once, each
//! over an SFTP session of its own in the one connection, and agrees with the
//! disk; `-v` says the chunks and the tasks. A count out of range is refused.
//! With no `sftp-server` on this machine, the copies say that they did not
//! run.

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cp-parallel-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

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

/// `podssh cp` with `args`, in `home`: its code and stderr.
fn cp(home: &Path, port: u16, args: &[&str]) -> (i32, String) {
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["cp", "--timeout", "300s", "--direct", "-v", "-P", &port.to_string()])
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={known}"))
        .args(args)
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn data(len: usize) -> Vec<u8> {
    (0..len as u64).map(|i| (i.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 29) as u8).collect()
}

#[test]
fn a_file_of_several_chunks_goes_up_and_down_with_tasks_at_once() {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let home = scratch("chunks");
    let (_runtime, port) = server(&home);
    // Three chunks and a part: 8 MiB each.
    let want = data(25 * (1 << 20) + 12345);
    std::fs::write(home.join("here.bin"), &want).unwrap();
    let (rc, err) = cp(&home, port, &["--parallel", "4", "here.bin", "u@127.0.0.1:there.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("chunks of 8388608 bytes, 4 at once"), "{err}");
    assert_eq!(std::fs::read(home.join("there.bin")).unwrap(), want, "the server's copy");
    let (rc, err) = cp(&home, port, &["--parallel", "3", "u@127.0.0.1:there.bin", "back.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("chunks of 8388608 bytes, 3 at once"), "{err}");
    assert_eq!(std::fs::read(home.join("back.bin")).unwrap(), want, "the copy back");
    // One chunk or less goes in one stream, as with no flag.
    std::fs::write(home.join("small.bin"), data(1000)).unwrap();
    let (rc, err) = cp(&home, port, &["--parallel", "4", "small.bin", "u@127.0.0.1:small.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!err.contains("at once"), "{err}");
}

#[test]
fn a_count_of_tasks_out_of_range_is_refused_before_anything_connects() {
    let home = scratch("refused");
    for count in ["0", "17", "x"] {
        let (rc, err) = cp(&home, 1, &["--parallel", count, "a", "host:b"]);
        assert_eq!(rc, 64, "{count}: {err}");
        assert!(err.contains(&format!("--parallel {count}: give 1 to 16 tasks")), "{err}");
        assert!(err.contains("Nothing has been attempted"), "{err}");
    }
}
