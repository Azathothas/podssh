//! `podssh cp --inplace` (T-147), against the test's SSH server on the
//! loopback, whose subsystem `sftp` is OpenSSH's `sftp-server`
//! (`ssh_harness::sftp`): the bytes go into the destination itself, so a
//! second hard-linked name of it sees them, up and down, over a longer old
//! file, with `--delta` and with `mv`; without `--inplace` the second name
//! keeps the old bytes; podssh says first that a failure leaves the
//! destination damaged; a destination that is a link is refused (64). The
//! copy by exec, the inode check and a failure that leaves the destination
//! damaged are measured against OpenSSH in the gate
//! (`scripts/interop-inplace.sh`).

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cp-inplace-{name}-{}", std::process::id()));
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

/// `podssh VERB` with `args` against the server on `port`, in `home`: its
/// code and stderr.
fn podssh(home: &Path, port: u16, verb: &str, args: &[&str]) -> (i32, String) {
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args([verb, "--timeout", "120s", "--direct", "-P", &port.to_string()])
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

macro_rules! need_server {
    () => {
        if ssh_harness::sftp::server_path().is_none() {
            eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
            return;
        }
    };
}

fn data(len: usize, seed: u32) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

/// `name` in `home` with `old`, and `alias`, a second name of the same file.
fn with_alias(home: &Path, name: &str, alias: &str, old: &[u8]) {
    std::fs::write(home.join(name), old).unwrap();
    let _ = std::fs::remove_file(home.join(alias));
    std::fs::hard_link(home.join(name), home.join(alias)).unwrap();
}

#[test]
fn the_bytes_go_into_the_destination_itself_up_and_down() {
    need_server!();
    let home = scratch("updown");
    let (_runtime, port) = server(&home);
    // A new file shorter than the old one: its old bytes past the end go.
    let new = data(300_000, 1);
    std::fs::write(home.join("new.bin"), &new).unwrap();
    with_alias(&home, "far.bin", "far-alias.bin", &data(500_000, 2));
    let (rc, err) = podssh(&home, port, "cp", &["--inplace", "new.bin", "u@127.0.0.1:far.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.starts_with("podssh: --inplace writes into each destination itself"), "said first: {err}");
    assert_eq!(std::fs::read(home.join("far.bin")).unwrap(), new);
    assert_eq!(std::fs::read(home.join("far-alias.bin")).unwrap(), new, "one file: the second name sees the bytes");
    // Down, into a file here with a second name.
    with_alias(&home, "here.bin", "here-alias.bin", &data(400_000, 3));
    let (rc, err) = podssh(&home, port, "cp", &["--inplace", "u@127.0.0.1:new.bin", "here.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("here-alias.bin")).unwrap(), new, "down: one file");
    // Without --inplace, the rename leaves the second name with its bytes.
    let old = data(200_000, 4);
    with_alias(&home, "plain.bin", "plain-alias.bin", &old);
    let (rc, err) = podssh(&home, port, "cp", &["new.bin", "u@127.0.0.1:plain.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("plain.bin")).unwrap(), new);
    assert_eq!(std::fs::read(home.join("plain-alias.bin")).unwrap(), old, "a new file took the name");
    // No temporary name stays.
    let left: Vec<_> = std::fs::read_dir(&home).unwrap().flatten().collect();
    assert!(!left.iter().any(|e| e.file_name().to_string_lossy().contains(".podssh-")), "{left:?}");
}

#[test]
fn delta_and_mv_go_into_the_destination_itself() {
    need_server!();
    let home = scratch("delta");
    let (_runtime, port) = server(&home);
    // --delta over an old version: the changed block goes into the file.
    let mut new = data(3 << 20, 5);
    std::fs::write(home.join("new.bin"), &new).unwrap();
    new[(1 << 20) + 7] ^= 0xff;
    std::fs::write(home.join("changed.bin"), &new).unwrap();
    with_alias(&home, "far.bin", "far-alias.bin", &std::fs::read(home.join("new.bin")).unwrap());
    let (rc, err) = podssh(&home, port, "cp", &["--inplace", "--delta", "-v", "changed.bin", "u@127.0.0.1:far.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("far-alias.bin")).unwrap(), new, "one file: {err}");
    // mv: the source goes after the check.
    with_alias(&home, "moved.bin", "moved-alias.bin", b"old");
    let (rc, err) = podssh(&home, port, "mv", &["--inplace", "changed.bin", "u@127.0.0.1:moved.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!home.join("changed.bin").exists(), "the source went: {err}");
    assert_eq!(std::fs::read(home.join("moved-alias.bin")).unwrap(), new);
}

#[cfg(unix)]
#[test]
fn a_destination_that_is_a_link_is_refused() {
    need_server!();
    let home = scratch("link");
    let (_runtime, port) = server(&home);
    std::fs::write(home.join("new.bin"), b"new").unwrap();
    std::fs::write(home.join("real.bin"), b"real").unwrap();
    std::os::unix::fs::symlink("real.bin", home.join("link.bin")).unwrap();
    // Up: the far destination is a link.
    let (rc, err) = podssh(&home, port, "cp", &["--inplace", "new.bin", "u@127.0.0.1:link.bin"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("a symbolic link"), "{err}");
    assert_eq!(std::fs::read(home.join("real.bin")).unwrap(), b"real", "nothing went through the link");
}
