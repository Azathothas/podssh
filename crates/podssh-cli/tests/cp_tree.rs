//! `podssh cp -r` (T-143), against the test's SSH server on the loopback,
//! whose subsystem `sftp` is OpenSSH's `sftp-server`: a tree with levels, an
//! empty directory and names with a space goes up and comes back down, each
//! file equal to its source; `--dry-run` says each action and changes
//! nothing; `--exclude` leaves paths out; and a server whose listing names
//! `../escape` is refused, with nothing written outside the target. A FIFO
//! is skipped with one note and no failure, each failure is said once, and
//! the first gives the code (T-476). A tree of many files names no flag, as
//! its files go several at once by default (T-474). Links and FIFOs are
//! measured against OpenSSH in the gate too (`scripts/interop-cp.sh`).
//! `-n`, `-u` and `-b` (T-473) are in `cp_tree_clobber/`.

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

// `-n`, `-u` and `-b` (T-473), with this file's server and helpers; after
// the macro, which it takes.
mod cp_tree_clobber;

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

/// The source copied once into the server's `dest`, where each later run of
/// the same command lands again: `dest/src`.
fn mirrored(home: &Path, port: u16) {
    fixture(&home.join("src"));
    std::fs::create_dir_all(home.join("dest")).unwrap();
    let (rc, _, err) = cp(home, port, &["-r", "src", "u@127.0.0.1:dest"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(listing(&home.join("dest/src")), listing(&home.join("src")));
}

#[test]
fn delete_mirrors_the_target_and_keeps_what_it_must() {
    need_server!();
    let home = scratch("delete");
    let (_runtime, port) = server(&home);
    mirrored(&home, port);
    // What the source lacks, an excluded name, and (on Unix) a link to a
    // file outside the target.
    let target = home.join("dest/src");
    std::fs::write(target.join("extra.txt"), b"x").unwrap();
    std::fs::create_dir_all(target.join("old/deep")).unwrap();
    std::fs::write(target.join("old/deep/y"), b"y").unwrap();
    std::fs::write(target.join("kept.log"), b"log").unwrap();
    std::fs::write(home.join("outside.txt"), b"outside").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(home.join("outside.txt"), target.join("link")).unwrap();
    // A dry run names each delete, and changes nothing.
    let run = |extra: &[&'static str]| {
        let mut args = vec!["-r", "--delete", "--exclude", "*.log"];
        args.extend_from_slice(extra);
        args.extend(["src", "u@127.0.0.1:dest"]);
        cp(&home, port, &args)
    };
    let (rc, out, err) = run(&["--dry-run"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.lines().any(|l| l == "delete dest/src/extra.txt"), "{out}");
    assert!(out.lines().any(|l| l == "delete dest/src/old"), "{out}");
    assert!(!out.contains("kept.log"), "{out}");
    assert!(target.join("extra.txt").exists(), "a dry run deleted nothing");
    // The mirror: what the source lacks goes; the excluded name, the file
    // that the link named, and each file of the source stay.
    let (rc, _, err) = run(&[]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("deleted, which the source does not have"), "{err}");
    assert!(!target.join("extra.txt").exists() && !target.join("old").exists(), "{err}");
    assert!(target.join("kept.log").exists(), "an excluded name is never deleted");
    assert_eq!(std::fs::read(home.join("outside.txt")).unwrap(), b"outside", "never the file that a link names");
    #[cfg(unix)]
    assert!(std::fs::symlink_metadata(target.join("link")).is_err(), "the link went");
    let mut want = listing(&home.join("src"));
    want.insert("kept.log".into(), Some(b"log".to_vec()));
    assert_eq!(listing(&target), want);
    // Down, the same: a file here that the server's tree lacks goes.
    std::fs::create_dir_all(home.join("back")).unwrap();
    let (rc, _, err) = cp(&home, port, &["-r", "u@127.0.0.1:src", "back"]);
    assert_eq!(rc, 0, "{err}");
    std::fs::write(home.join("back/src/stale"), b"s").unwrap();
    let (rc, _, err) = cp(&home, port, &["-r", "--delete", "u@127.0.0.1:src", "back"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!home.join("back/src/stale").exists(), "{err}");
    assert_eq!(listing(&home.join("back/src")), listing(&home.join("src")));
}

#[test]
fn delete_after_a_failed_copy_deletes_nothing() {
    need_server!();
    let home = scratch("delete-failed");
    let (_runtime, port) = server(&home);
    mirrored(&home, port);
    std::fs::write(home.join("dest/src/extra.txt"), b"x").unwrap();
    // A far file where the source has a directory: its mkdir fails, also for
    // root, and so does each file under it (a FIFO is no failure, T-476).
    std::fs::remove_dir_all(home.join("dest/src/a")).unwrap();
    std::fs::write(home.join("dest/src/a"), b"a file").unwrap();
    let (rc, _, err) = cp(&home, port, &["-r", "--delete", "src", "u@127.0.0.1:dest"]);
    assert_ne!(rc, 0, "{err}");
    assert!(err.contains("nothing was deleted"), "{err}");
    assert!(home.join("dest/src/extra.txt").exists(), "nothing deleted: {err}");
}

#[test]
fn delete_refuses_the_login_directory_and_needs_r() {
    need_server!();
    let home = scratch("delete-home");
    let (_runtime, port) = server(&home);
    fixture(&home.join("src"));
    // `.` as the source: the copy's root would be the login directory.
    let (rc, _, err) = cp(&home, port, &["-r", "--delete", ".", "u@127.0.0.1:"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--delete may not take"), "{err}");
    let (rc, _, err) = cp(&home, port, &["--delete", "src", "u@127.0.0.1:x"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("go with -r"), "{err}");
}

/// A tree of many files goes several at once with no `--parallel` (T-474),
/// so no line names the flag, as T-417's did when one at a time was the
/// default; nor after `--parallel 1`, which the user chose. Up and down,
/// each tree equal to its source.
#[test]
fn a_tree_of_many_files_names_no_flag() {
    need_server!();
    let home = scratch("many");
    let (_runtime, port) = server(&home);
    let many = home.join("many");
    std::fs::create_dir_all(&many).unwrap();
    for i in 0..60 {
        std::fs::write(many.join(format!("f{i:02}")), format!("file {i}\n")).unwrap();
    }
    let (rc, _, err) = cp(&home, port, &["-r", "many", "u@127.0.0.1:up"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!err.contains("--parallel") && !err.contains("one at a time"), "up: {err}");
    assert_eq!(listing(&home.join("up")), listing(&many), "the tree up");
    let (rc, _, err) = cp(&home, port, &["-r", "u@127.0.0.1:up", "down"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!err.contains("--parallel"), "down: {err}");
    assert_eq!(listing(&home.join("down")), listing(&many), "the tree down");
    let (rc, _, err) = cp(&home, port, &["-r", "--parallel", "1", "many", "u@127.0.0.1:up1"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!err.contains("--parallel"), "with --parallel 1: {err}");
    assert_eq!(listing(&home.join("up1")), listing(&many), "the tree up, one at a time");
}

/// A device, a FIFO or a socket of a tree is not copied and no failure
/// (T-476): a tree with a file and two FIFOs goes up and comes down with
/// exit 0, each FIFO named once on stderr and no line twice, the file
/// copied; `--jsonl` gives a `skipped` object for each; `-q` says nothing.
/// A failure is said once: a name that is not UTF-8 (Linux) still fails,
/// and two missing sources are each said once, with 66.
#[cfg(unix)]
#[test]
fn special_files_are_skipped_once_each_with_exit_0() {
    need_server!();
    let home = scratch("special");
    let (_runtime, port) = server(&home);
    let src = home.join("pipes");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/file"), b"kept").unwrap();
    for fifo in ["p1", "sub/p2"] {
        let path = std::ffi::CString::new(src.join(fifo).into_os_string().into_encoded_bytes()).unwrap();
        // SAFETY: a path with no NUL, and a mode.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0, "mkfifo {fifo}");
    }
    let once = |err: &str| {
        let lines: Vec<&str> = err.lines().collect();
        let unique: std::collections::BTreeSet<&str> = lines.iter().copied().collect();
        assert_eq!(lines.len(), unique.len(), "no line twice: {err}");
        assert_eq!(err.matches("p1: not copied: a FIFO").count(), 1, "{err}");
        assert_eq!(err.matches("p2: not copied: a FIFO").count(), 1, "{err}");
    };
    let (rc, _, err) = cp(&home, port, &["-r", "pipes", "u@127.0.0.1:up"]);
    assert_eq!(rc, 0, "{err}");
    once(&err);
    assert_eq!(std::fs::read(home.join("up/sub/file")).unwrap(), b"kept");
    assert!(!home.join("up/p1").exists() && !home.join("up/sub/p2").exists());
    // Down: the far tree's FIFOs, made where the server's tree is.
    for fifo in ["up/p1", "up/sub/p2"] {
        let path = std::ffi::CString::new(home.join(fifo).into_os_string().into_encoded_bytes()).unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0, "mkfifo {fifo}");
    }
    let (rc, _, err) = cp(&home, port, &["-r", "u@127.0.0.1:up", "down"]);
    assert_eq!(rc, 0, "{err}");
    once(&err);
    assert_eq!(std::fs::read(home.join("down/sub/file")).unwrap(), b"kept");
    let (rc, out, err) = cp(&home, port, &["-r", "--jsonl", "pipes", "u@127.0.0.1:up2"]);
    assert_eq!(rc, 0, "{err}");
    let skipped: Vec<serde_json::Value> = out
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event"] == "skipped")
        .collect();
    assert_eq!(skipped.len(), 2, "{out}");
    assert!(skipped.iter().all(|v| v["why"] == "a FIFO"), "{out}");
    let (rc, _, err) = cp(&home, port, &["-q", "-r", "pipes", "u@127.0.0.1:up3"]);
    assert_eq!((rc, err.as_str()), (0, ""), "-q");
    // A name that is not UTF-8 is still a failure, said once.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        std::fs::write(src.join(std::ffi::OsStr::from_bytes(b"bad\xff")), b"x").unwrap();
        let (rc, _, err) = cp(&home, port, &["-r", "pipes", "u@127.0.0.1:up4"]);
        assert_eq!(rc, 66, "{err}");
        assert_eq!(err.matches("not UTF-8").count(), 1, "said once: {err}");
    }
    // Two missing sources of one command line: each said once, 66.
    let (rc, _, err) = cp(&home, port, &["gone1", "gone2", "u@127.0.0.1:up"]);
    assert_eq!(rc, 66, "{err}");
    assert_eq!((err.matches("gone1").count(), err.matches("gone2").count()), (1, 1), "{err}");
}
