//! `podssh cp -n`, `-u` and `-b` (T-473), a module of `cp_tree`, whose server
//! (OpenSSH's `sftp-server` behind the test's SSH server) and helpers it
//! takes: up and down, with `-n` a destination that is there stays and the
//! copy says so once with exit 0, also one written while a copy under `-l`
//! runs; with `-u` an older destination is replaced, a newer one stays, and
//! one of the same second and another size is replaced; with `-b` the old
//! file is at `NAME~` and the new one at `NAME`, and `--delete` leaves the
//! backups; each also in `--dry-run` and in `--jsonl`.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use super::{cp, listing, podssh_in, scratch, server};
use crate::ssh_harness;

/// Give `path` the time of change `secs` after 1970.
fn at(path: &Path, secs: u64) {
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs)).unwrap();
}

/// A file with `bytes`, at the time `secs`.
fn file_at(path: &Path, bytes: &[u8], secs: u64) {
    std::fs::write(path, bytes).unwrap();
    at(path, secs);
}

/// The objects of `--jsonl` whose event is `event`.
fn objects(out: &str, event: &str) -> Vec<serde_json::Value> {
    out.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event"] == event)
        .collect()
}

/// Whether `dir` holds a temporary file of a copy.
fn has_part(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .is_ok_and(|names| names.filter_map(Result::ok).any(|e| e.file_name().to_string_lossy().ends_with(".part")))
}

/// `podssh cp` with `args`, started and not waited for.
fn started(home: &Path, port: u16, args: &[&str]) -> Child {
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["cp", "--timeout", "120s", "--direct", "-P", &port.to_string()])
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
    cmd.spawn().unwrap()
}

/// Wait until `dir` holds a copy's temporary file, 60 s at most.
fn wait_for_part(dir: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !has_part(dir) {
        assert!(child.try_wait().unwrap().is_none(), "the copy ended before its temporary file was seen");
        assert!(Instant::now() < deadline, "no temporary file in {} within 60 s", dir.display());
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The end of `child`, 150 s at most: its code and its stderr.
fn ended(mut child: Child) -> (i32, String) {
    let deadline = Instant::now() + Duration::from_secs(150);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the copy did not end within 150 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn clobber_no_clobber_keeps_a_destination_up_and_down() {
    need_server!();
    let home = scratch("noclobber");
    let (_runtime, port) = server(&home);
    std::fs::write(home.join("f"), b"new").unwrap();
    std::fs::create_dir_all(home.join("far")).unwrap();
    std::fs::write(home.join("far/f"), b"live").unwrap();
    // Up: the far file stays, said once; exit 0, and one skip.
    let (rc, _, err) = cp(&home, port, &["-n", "f", "u@127.0.0.1:far/f"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("far/f")).unwrap(), b"live");
    assert_eq!(err.matches("far/f: there, so not replaced").count(), 1, "{err}");
    assert!(err.contains("0 copied, 1 skipped"), "{err}");
    assert!(!has_part(&home.join("far")), "no temporary file: no byte went");
    // A name that is missing is copied.
    let (rc, _, err) = cp(&home, port, &["--no-clobber", "f", "u@127.0.0.1:far/g"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("far/g")).unwrap(), b"new");
    // Down: the same.
    std::fs::create_dir_all(home.join("here")).unwrap();
    std::fs::write(home.join("here/f"), b"mine").unwrap();
    let (rc, _, err) = cp(&home, port, &["-n", "u@127.0.0.1:far/f", "here/f"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("here/f")).unwrap(), b"mine");
    assert_eq!(err.matches("here/f: there, so not replaced").count(), 1, "{err}");
    let (rc, _, err) = cp(&home, port, &["-n", "u@127.0.0.1:far/f", "here/h"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("here/h")).unwrap(), b"live");
    // --jsonl: a skipped object, its why exists, and the summary counts it.
    let (rc, out, err) = cp(&home, port, &["-n", "--jsonl", "f", "u@127.0.0.1:far/f"]);
    assert_eq!(rc, 0, "{err}");
    let skipped = objects(&out, "skipped");
    assert_eq!(skipped.len(), 1, "{out}");
    assert_eq!((skipped[0]["why"].as_str(), skipped[0]["source"].as_str()), (Some("exists"), Some("f")), "{out}");
    assert!(objects(&out, "done").is_empty(), "{out}");
    assert_eq!(objects(&out, "summary")[0]["skipped"].as_u64(), Some(1), "{out}");
    // mv -n keeps the source that it did not move.
    let (rc, _, err) = podssh_in(&home, port, &["mv", "-n", "f", "u@127.0.0.1:far/f"]);
    assert_eq!(rc, 0, "{err}");
    assert!(home.join("f").exists(), "the source stays: {err}");
    assert_eq!(std::fs::read(home.join("far/f")).unwrap(), b"live");
    // A tree: the dry run says the skip, and mv -r leaves what it did not copy.
    std::fs::create_dir_all(home.join("t")).unwrap();
    std::fs::write(home.join("t/a"), b"a").unwrap();
    std::fs::write(home.join("t/b"), b"b").unwrap();
    std::fs::create_dir_all(home.join("far/t")).unwrap();
    std::fs::write(home.join("far/t/a"), b"kept").unwrap();
    let (rc, out, err) = cp(&home, port, &["-r", "-n", "--dry-run", "t", "u@127.0.0.1:far"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.lines().any(|l| l == "skip t/a: exists"), "{out}");
    assert!(out.lines().any(|l| l == "copy t/b -> far/t/b"), "{out}");
    let (rc, _, err) = podssh_in(&home, port, &["mv", "-r", "-n", "t", "u@127.0.0.1:far"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("far/t/a")).unwrap(), b"kept");
    assert_eq!(std::fs::read(home.join("far/t/b")).unwrap(), b"b");
    assert!(home.join("t/a").exists() && !home.join("t/b").exists(), "mv -r leaves what it did not copy: {err}");
}

/// A name that comes while a copy under `-l` runs stays: the verified file
/// takes its name by a hard link, which refuses a name that is there; the
/// rename that replaced it would let it go.
#[test]
fn clobber_a_name_written_during_the_copy_stays() {
    need_server!();
    let home = scratch("during");
    let (_runtime, port) = server(&home);
    // 40,000 bytes at 64 Kbit/s: some 5 s.
    let body: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(home.join("big"), &body).unwrap();
    std::fs::create_dir_all(home.join("far")).unwrap();
    let mut child = started(&home, port, &["-n", "-l", "64", "big", "u@127.0.0.1:far/big"]);
    wait_for_part(&home.join("far"), &mut child);
    std::fs::write(home.join("far/big"), b"came").unwrap();
    let (rc, err) = ended(child);
    assert_eq!(rc, 0, "up: {err}");
    assert_eq!(std::fs::read(home.join("far/big")).unwrap(), b"came", "up: {err}");
    assert_eq!(err.matches("far/big: there, so not replaced").count(), 1, "{err}");
    assert!(!has_part(&home.join("far")), "the temporary file went");
    // Down.
    std::fs::create_dir_all(home.join("here")).unwrap();
    let mut child = started(&home, port, &["-n", "-l", "64", "u@127.0.0.1:big", "here/big"]);
    wait_for_part(&home.join("here"), &mut child);
    std::fs::write(home.join("here/big"), b"came").unwrap();
    let (rc, err) = ended(child);
    assert_eq!(rc, 0, "down: {err}");
    assert_eq!(std::fs::read(home.join("here/big")).unwrap(), b"came", "down: {err}");
    assert!(!has_part(&home.join("here")), "the temporary file went");
}

#[test]
fn clobber_update_copies_only_what_is_newer() {
    need_server!();
    let home = scratch("update");
    let (_runtime, port) = server(&home);
    let t = 1_000_000_000;
    file_at(&home.join("f"), b"new", t);
    std::fs::create_dir_all(home.join("far")).unwrap();
    file_at(&home.join("far/older"), b"old", t - 100);
    file_at(&home.join("far/newer"), b"old", t + 100);
    file_at(&home.join("far/other"), b"other size", t);
    file_at(&home.join("far/same"), b"abc", t);
    for (name, replaced) in [("older", true), ("newer", false), ("other", true), ("same", false)] {
        let before = std::fs::read(home.join("far").join(name)).unwrap();
        let (rc, _, err) = cp(&home, port, &["-u", "-v", "f", &format!("u@127.0.0.1:far/{name}")]);
        assert_eq!(rc, 0, "{name}: {err}");
        let now = std::fs::read(home.join("far").join(name)).unwrap();
        if replaced {
            assert_eq!(now, b"new", "{name}: {err}");
        } else {
            assert_eq!(now, before, "{name}: {err}");
            assert!(err.contains(&format!("far/{name}: not older than the source")), "{name}: {err}");
            assert!(err.contains("0 copied, 1 skipped"), "{name}: {err}");
        }
    }
    // With no -v the skip is in the summary alone; with --jsonl, why not newer.
    let (rc, _, err) = cp(&home, port, &["-u", "f", "u@127.0.0.1:far/newer"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!err.contains("not older") && err.contains("1 skipped"), "{err}");
    let (rc, out, err) = cp(&home, port, &["-u", "--jsonl", "f", "u@127.0.0.1:far/newer"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(objects(&out, "skipped")[0]["why"], "not newer", "{out}");
    // Down: a newer file here stays, an older one is replaced.
    std::fs::create_dir_all(home.join("here")).unwrap();
    file_at(&home.join("far/src"), b"far", t);
    file_at(&home.join("here/newer"), b"mine", t + 100);
    file_at(&home.join("here/older"), b"mine", t - 100);
    let (rc, _, err) = cp(&home, port, &["-u", "u@127.0.0.1:far/src", "here/newer"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("here/newer")).unwrap(), b"mine");
    let (rc, _, err) = cp(&home, port, &["-u", "u@127.0.0.1:far/src", "here/older"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("here/older")).unwrap(), b"far");
    // A dry run of a tree says the skip.
    std::fs::create_dir_all(home.join("t")).unwrap();
    file_at(&home.join("t/a"), b"a", t);
    std::fs::create_dir_all(home.join("far/t")).unwrap();
    file_at(&home.join("far/t/a"), b"a", t + 100);
    let (rc, out, err) = cp(&home, port, &["-r", "-u", "--dry-run", "t", "u@127.0.0.1:far"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.lines().any(|l| l == "skip t/a: not newer"), "{out}");
}

#[test]
fn clobber_backup_keeps_the_old_file_beside_the_new() {
    need_server!();
    let home = scratch("backup");
    let (_runtime, port) = server(&home);
    std::fs::write(home.join("f"), b"new").unwrap();
    std::fs::create_dir_all(home.join("far")).unwrap();
    std::fs::write(home.join("far/f"), b"old").unwrap();
    // Up, with --jsonl: the done object names the backup.
    let (rc, out, err) = cp(&home, port, &["-b", "--jsonl", "f", "u@127.0.0.1:far/f"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("far/f")).unwrap(), b"new");
    assert_eq!(std::fs::read(home.join("far/f~")).unwrap(), b"old");
    assert_eq!(objects(&out, "done")[0]["backup"], "far/f~", "{out}");
    // Again: the older backup goes, and the one just replaced takes its name.
    std::fs::write(home.join("f"), b"newer").unwrap();
    let (rc, _, err) = cp(&home, port, &["-b", "f", "u@127.0.0.1:far/f"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("far/f~")).unwrap(), b"new");
    // --suffix, and nothing to keep when the name is missing.
    let (rc, _, err) = cp(&home, port, &["-b", "--suffix", ".bak", "f", "u@127.0.0.1:far/f"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("far/f.bak")).unwrap(), b"newer");
    let (rc, _, err) = cp(&home, port, &["-b", "f", "u@127.0.0.1:far/g"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!home.join("far/g~").exists(), "no old file, no backup");
    // Down.
    std::fs::create_dir_all(home.join("here")).unwrap();
    std::fs::write(home.join("here/f"), b"mine").unwrap();
    let (rc, _, err) = cp(&home, port, &["-b", "u@127.0.0.1:far/f", "here/f"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("here/f")).unwrap(), b"newer");
    assert_eq!(std::fs::read(home.join("here/f~")).unwrap(), b"mine");
    // A tree with --delete: the backups stay, what the source lacks goes.
    std::fs::create_dir_all(home.join("src")).unwrap();
    std::fs::write(home.join("src/a"), b"new a").unwrap();
    std::fs::create_dir_all(home.join("dest/src")).unwrap();
    std::fs::write(home.join("dest/src/a"), b"old a").unwrap();
    std::fs::write(home.join("dest/src/kept~"), b"an older backup").unwrap();
    std::fs::write(home.join("dest/src/extra"), b"x").unwrap();
    let (rc, out, err) = cp(&home, port, &["-r", "-b", "--delete", "--dry-run", "src", "u@127.0.0.1:dest"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.lines().any(|l| l == "backup dest/src/a -> dest/src/a~"), "{out}");
    assert!(out.lines().any(|l| l == "delete dest/src/extra") && !out.contains("kept~"), "{out}");
    let (rc, _, err) = cp(&home, port, &["-r", "-b", "--delete", "src", "u@127.0.0.1:dest"]);
    assert_eq!(rc, 0, "{err}");
    let tree = listing(&home.join("dest/src"));
    let names: Vec<&str> = tree.keys().map(String::as_str).collect();
    assert_eq!(names, ["a", "a~", "kept~"], "{err}");
    assert_eq!(tree["a"].as_deref(), Some(&b"new a"[..]));
    assert_eq!(tree["a~"].as_deref(), Some(&b"old a"[..]));
}
