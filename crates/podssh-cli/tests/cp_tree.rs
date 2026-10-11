//! `podssh cp -r` (T-143), against the test's SSH server on the loopback,
//! whose subsystem `sftp` is OpenSSH's `sftp-server`: a tree with levels, an
//! empty directory and names with a space goes up and comes back down, each
//! file equal to its source; `--dry-run` says each action and changes
//! nothing; `--exclude` leaves paths out; and a server whose listing names
//! `../escape` is refused, with nothing written outside the target. Links and
//! FIFOs are measured against OpenSSH in the gate (`scripts/interop-cp.sh`).

mod cleanup;
mod ssh_harness;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cp-tree-{name}-{}", std::process::id()));
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

/// `podssh cp` with `args` in `home`: its code, stdout and stderr.
fn cp(home: &Path, port: u16, args: &[&str]) -> (i32, String, String) {
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["cp", "--timeout", "120s", "--direct", "-P", &port.to_string()])
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={known}"))
        .args(args)
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// Each path under `root`, `/` between its names, and a file's bytes; a
/// directory has none.
fn listing(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            if entry.file_type().unwrap().is_dir() {
                out.insert(child.clone(), None);
                stack.push((entry.path(), child));
            } else {
                out.insert(child, Some(std::fs::read(entry.path()).unwrap()));
            }
        }
    }
    out
}

/// A tree with levels, an empty directory, names with a space, and a file
/// that `*.log` names.
fn fixture(root: &Path) {
    std::fs::create_dir_all(root.join("a/b c/d")).unwrap();
    std::fs::create_dir_all(root.join("empty")).unwrap();
    std::fs::write(root.join("top.txt"), b"top").unwrap();
    std::fs::write(root.join("a/one two.bin"), (0..70_000u32).map(|i| i as u8).collect::<Vec<_>>()).unwrap();
    std::fs::write(root.join("a/b c/d/deep"), b"deep").unwrap();
    std::fs::write(root.join("a/skip.log"), b"log").unwrap();
}

macro_rules! need_server {
    () => {
        if ssh_harness::sftp::server_path().is_none() {
            eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
            return;
        }
    };
}

#[test]
fn a_tree_goes_up_and_down_and_a_dry_run_changes_nothing() {
    need_server!();
    let home = scratch("updown");
    let (_runtime, port) = server(&home);
    fixture(&home.join("src"));
    // A dry run: one line for each action, and no change there.
    let (rc, out, err) = cp(&home, port, &["-r", "--dry-run", "src", "u@127.0.0.1:up"]);
    assert_eq!(rc, 0, "{err}");
    assert!(
        out.contains("mkdir up/a/b c/d") && out.contains("copy ") && out.contains("top.txt -> up/top.txt"),
        "{out}"
    );
    assert!(!home.join("up").exists(), "a dry run changed nothing");
    // Without -r, a directory is named as one.
    let (rc, _, err) = cp(&home, port, &["src", "u@127.0.0.1:x"]);
    assert_eq!(rc, 66, "{err}");
    assert!(err.contains("a directory; -r copies it"), "{err}");
    // Up: the server's directory is the copy of src (it did not exist).
    let (rc, _, err) = cp(&home, port, &["-r", "src", "u@127.0.0.1:up"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(listing(&home.join("up")), listing(&home.join("src")), "the tree up");
    assert!(home.join("up/empty").is_dir(), "the empty directory");
    // Down, into a directory that exists: the copy goes under it.
    std::fs::create_dir_all(home.join("back")).unwrap();
    let (rc, _, err) = cp(&home, port, &["-r", "u@127.0.0.1:up", "back"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(listing(&home.join("back/up")), listing(&home.join("src")), "the tree down");
    // --exclude: the log stays out, and a pattern with a / from the root.
    let (rc, _, err) = cp(&home, port, &["-r", "--exclude", "*.log", "--exclude", "a/b c", "src", "u@127.0.0.1:part"]);
    assert_eq!(rc, 0, "{err}");
    let part = listing(&home.join("part"));
    assert!(part.contains_key("a/one two.bin") && part.contains_key("top.txt"), "{part:?}");
    assert!(!part.contains_key("a/skip.log") && !part.contains_key("a/b c"), "{part:?}");
    // mv -r: the tree is there, and its source goes.
    let want = listing(&home.join("src"));
    let (rc, _, err) = podssh_in(&home, port, &["mv", "-r", "src", "u@127.0.0.1:moved"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(listing(&home.join("moved")), want, "the tree moved");
    assert!(!home.join("src").exists(), "the source went: {err}");
}

/// `podssh VERB` with the options of [`cp`].
fn podssh_in(home: &Path, port: u16, args: &[&str]) -> (i32, String, String) {
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(&args[..1])
        .args(["--timeout", "120s", "--direct", "-P", &port.to_string()])
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={known}"))
        .args(&args[1..])
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

#[test]
fn a_listing_that_names_a_path_outside_the_target_is_refused() {
    need_server!();
    let home = scratch("escape");
    let (_runtime, port) = server(&home);
    fixture(&home.join("far"));
    // A file where `../escape` would land, and the one that it names.
    std::fs::write(home.join("escape"), b"server's").unwrap();
    std::fs::create_dir_all(home.join("here")).unwrap();
    let (rc, _, err) = cp(&home, port, &["-r", "evil-u@127.0.0.1:far", "here"]);
    assert_ne!(rc, 0, "{err}");
    assert!(err.contains("refused") && err.contains("not one component"), "{err}");
    assert!(!home.join("here/escape").exists() && !home.join("here/far/escape").exists(), "{err}");
    assert_eq!(std::fs::read(home.join("escape")).unwrap(), b"server's", "nothing written outside the target");
    // The rest of the tree still came.
    assert_eq!(std::fs::read(home.join("here/far/a/b c/d/deep")).unwrap(), b"deep");
}

#[test]
fn the_tree_flags_go_with_r() {
    let home = scratch("flags");
    for flag in [&["--dry-run"][..], &["--exclude", "*.x"], &["--exclude-from", "f"]] {
        let mut args = flag.to_vec();
        args.extend(["a", "host:b"]);
        let (rc, _, err) = cp(&home, 1, &args);
        assert_eq!(rc, 64, "{flag:?}: {err}");
        assert!(err.contains("go with -r"), "{err}");
    }
}
