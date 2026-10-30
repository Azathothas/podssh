//! What a copy keeps besides the bytes (T-146): the plan of the attributes
//! for each option, then against the test's SSH server on the loopback,
//! whose subsystem `sftp` is OpenSSH's `sftp-server` (`ssh_harness::sftp`):
//! `-p` keeps the times of a file and of each directory of a tree, up and
//! down, by `cp`, `scp`, and `sftp`'s `-p`, `get -p` and `put -p`, and
//! without it a copy has its own; `--sparse` leaves holes and each byte
//! arrives, with fewer blocks than the size where the file system has holes
//! (Unix); two hard-linked names arrive as one file with two names;
//! `--owner` keeps the owner, or says why not. The copy by exec and the far
//! disk's holes are measured against OpenSSH in the gate
//! (`scripts/interop-cp.sh`).

mod cleanup;
mod ssh_harness;

use std::fs::FileTimes;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_cli::cp::meta::{plan, Keep, Stamp};

/// Two times long past: 2001-09-09T01:46:40Z, and a minute later.
const MTIME: u64 = 1_000_000_000;
const ATIME: u64 = 1_000_000_060;

#[test]
fn the_attributes_follow_each_option() {
    let stamp = Stamp { mode: Some(0o640), atime: Some(5), mtime: Some(6), uid: Some(1000), gid: Some(100) };
    // The mode always; nothing else unless asked.
    let (owner, rest) = plan(&stamp, Keep::default());
    assert!(owner.is_none());
    assert_eq!((rest.permissions, rest.atime, rest.mtime, rest.uid), (Some(0o640), None, None, None));
    // -p: the times.
    let (owner, rest) = plan(&stamp, Keep { times: true, ..Keep::default() });
    assert!(owner.is_none());
    assert_eq!((rest.permissions, rest.atime, rest.mtime), (Some(0o640), Some(5), Some(6)));
    // --owner: both numbers, in a request of their own.
    let (owner, rest) = plan(&stamp, Keep { owner: true, ..Keep::default() });
    let owner = owner.expect("the owner");
    assert_eq!((owner.uid, owner.gid, owner.permissions, owner.mtime), (Some(1000), Some(100), None, None));
    assert_eq!(rest.uid, None);
    // A side with no owner by number, or no time: none asked for.
    let none = Stamp { mode: Some(0o600), ..Stamp::default() };
    let (owner, rest) = plan(&none, Keep { times: true, owner: true, sparse: false });
    assert!(owner.is_none());
    assert_eq!((rest.atime, rest.mtime), (None, None));
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cp-meta-{name}-{}", std::process::id()));
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
/// code, stdout and stderr. `scp` and `sftp` have no `--timeout`.
fn podssh(home: &Path, port: u16, verb: &str, args: &[&str]) -> (i32, String, String) {
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg(verb);
    if verb == "cp" || verb == "mv" {
        cmd.args(["--timeout", "120s"]);
    }
    cmd.args(["--direct", "-P", &port.to_string()])
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

macro_rules! need_server {
    () => {
        if ssh_harness::sftp::server_path().is_none() {
            eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
            return;
        }
    };
}

fn data(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 9) as u8 | 1).collect()
}

#[cfg(unix)]
fn for_times(path: &Path) -> std::fs::File {
    std::fs::File::open(path).unwrap()
}

#[cfg(windows)]
fn for_times(path: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_WRITE_ATTRIBUTES; FILE_FLAG_BACKUP_SEMANTICS opens a directory too.
    std::fs::OpenOptions::new().access_mode(0x100).custom_flags(0x0200_0000).open(path).unwrap()
}

/// Give `path`, a file or a directory, these times.
fn set_times(path: &Path, atime: u64, mtime: u64) {
    let at = |s| UNIX_EPOCH + Duration::from_secs(s);
    for_times(path).set_times(FileTimes::new().set_accessed(at(atime)).set_modified(at(mtime))).unwrap();
}

/// The access and the modification times of `path`, in seconds. A read of
/// a file may change its access time: each test reads the times first.
fn times(path: &Path) -> (u64, u64) {
    let meta = std::fs::metadata(path).unwrap();
    let secs = |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap().as_secs();
    (secs(meta.accessed().unwrap()), secs(meta.modified().unwrap()))
}

/// The times of a copy down of a far file whose times were `(atime, mtime)`.
/// On Windows the test's server is Cygwin's, whose stat reads the first
/// bytes of a file and so sets its access time (measured 2026-10-12): there
/// only the modification time comes down as it was.
fn assert_came_down(path: &Path, atime: u64, mtime: u64, what: &str) {
    let (got_atime, got_mtime) = times(path);
    assert_eq!(got_mtime, mtime, "{what}: the modification time");
    if cfg!(unix) {
        assert_eq!(got_atime, atime, "{what}: the access time");
    }
}

#[test]
fn p_keeps_the_times_of_a_file_up_and_down() {
    need_server!();
    let home = scratch("file");
    let (_runtime, port) = server(&home);
    let want = data(300_000);
    std::fs::write(home.join("here.bin"), &want).unwrap();
    set_times(&home.join("here.bin"), ATIME, MTIME);
    let (rc, _, err) = podssh(&home, port, "cp", &["-p", "here.bin", "u@127.0.0.1:up.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(times(&home.join("up.bin")), (ATIME, MTIME), "the times up");
    // Without -p, the copy's own time.
    let (rc, _, err) = podssh(&home, port, "cp", &["here.bin", "u@127.0.0.1:plain.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert!(times(&home.join("plain.bin")).1 > MTIME + 365 * 86_400, "a copy without -p has its own time");
    assert_eq!(std::fs::read(home.join("up.bin")).unwrap(), want);
    // Down, from a far file with times of its own.
    std::fs::write(home.join("far.bin"), &want).unwrap();
    set_times(&home.join("far.bin"), ATIME + 7, MTIME + 3);
    let (rc, _, err) = podssh(&home, port, "cp", &["-p", "u@127.0.0.1:far.bin", "down.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_came_down(&home.join("down.bin"), ATIME + 7, MTIME + 3, "cp -p down");
    assert_eq!(std::fs::read(home.join("down.bin")).unwrap(), want);
    #[cfg(unix)]
    {
        // The mode is kept with or without -p.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.join("here.bin"), std::fs::Permissions::from_mode(0o640)).unwrap();
        let (rc, _, err) = podssh(&home, port, "cp", &["-p", "here.bin", "u@127.0.0.1:mode.bin"]);
        assert_eq!(rc, 0, "{err}");
        let mode = std::fs::metadata(home.join("mode.bin")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }
}

#[test]
fn p_keeps_the_times_of_each_directory_of_a_tree() {
    need_server!();
    let home = scratch("tree");
    let (_runtime, port) = server(&home);
    let src = home.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/f"), b"f").unwrap();
    std::fs::write(src.join("g"), b"g").unwrap();
    // The files first: a file made in a directory changes the directory's.
    let each = [("sub/f", 0), ("g", 1), ("sub", 2), ("", 3)];
    for (rel, t) in each {
        set_times(&src.join(rel), ATIME + t, MTIME + t);
    }
    let (rc, _, err) = podssh(&home, port, "cp", &["-r", "-p", "src", "u@127.0.0.1:up"]);
    assert_eq!(rc, 0, "{err}");
    for (rel, t) in each {
        assert_eq!(times(&home.join("up").join(rel)).1, MTIME + t, "up/{rel}");
    }
    std::fs::create_dir_all(home.join("back")).unwrap();
    let (rc, _, err) = podssh(&home, port, "cp", &["-r", "-p", "u@127.0.0.1:up", "back"]);
    assert_eq!(rc, 0, "{err}");
    for (rel, t) in each {
        assert_eq!(times(&home.join("back/up").join(rel)).1, MTIME + t, "back/up/{rel}");
    }
}

#[test]
fn scp_and_sftp_keep_the_times_with_p() {
    need_server!();
    let home = scratch("verbs");
    let (_runtime, port) = server(&home);
    std::fs::write(home.join("local.bin"), b"some bytes").unwrap();
    set_times(&home.join("local.bin"), ATIME, MTIME);
    let (rc, _, err) = podssh(&home, port, "scp", &["-p", "local.bin", "u@127.0.0.1:scp.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(times(&home.join("scp.bin")), (ATIME, MTIME), "scp -p");
    // put -p, get -p, and a put with neither. scp read local.bin, which on
    // Linux moved its access time: it gets its times again first.
    set_times(&home.join("local.bin"), ATIME, MTIME);
    let batch = "put -p local.bin put.bin\nget -p put.bin get.bin\nput local.bin plain.bin\n";
    std::fs::write(home.join("batch"), batch).unwrap();
    let (rc, _, err) = podssh(&home, port, "sftp", &["-b", "batch", "u@127.0.0.1"]);
    assert_eq!(rc, 0, "{err}");
    // The get read put.bin, which may change its access time.
    assert_eq!(times(&home.join("put.bin")).1, MTIME, "put -p");
    assert_came_down(&home.join("get.bin"), ATIME, MTIME, "get -p");
    assert!(times(&home.join("plain.bin")).1 > MTIME + 365 * 86_400, "put without -p");
    // sftp -p: each put and get keeps them.
    std::fs::write(home.join("batch"), "put local.bin flagged.bin\n").unwrap();
    let (rc, _, err) = podssh(&home, port, "sftp", &["-p", "-b", "batch", "u@127.0.0.1"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(times(&home.join("flagged.bin")).1, MTIME, "sftp -p");
}

#[test]
fn sparse_leaves_holes_and_each_byte_arrives() {
    need_server!();
    let home = scratch("sparse");
    let (_runtime, port) = server(&home);
    // Holes at the start, in the middle and at the end, and runs of zeros
    // that do not end on a block.
    let block = 64 * 1024;
    let mut want = vec![0u8; 3 * block];
    want.extend(data(100_000));
    want.extend(vec![0u8; 40 * block + 123]);
    want.extend(data(10));
    want.extend(vec![0u8; 20 * block]);
    std::fs::write(home.join("holes.bin"), &want).unwrap();
    let (rc, _, err) = podssh(&home, port, "cp", &["--sparse", "holes.bin", "u@127.0.0.1:up.bin"]);
    assert_eq!(rc, 0, "{err}");
    let (rc, _, err) = podssh(&home, port, "cp", &["--sparse", "u@127.0.0.1:up.bin", "down.bin"]);
    assert_eq!(rc, 0, "{err}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let used = |name: &str| std::fs::metadata(home.join(name)).unwrap().blocks() * 512;
        // A sparse source, a file of 8 MiB with 6 bytes of data, made larger
        // than it was written as cp makes its holes: whether it has holes
        // tells whether this file system keeps any.
        let file = std::fs::File::create(home.join("auto.bin")).unwrap();
        file.set_len(8 << 20).unwrap();
        std::os::unix::fs::FileExt::write_at(&file, b"middle", 4 << 20).unwrap();
        drop(file);
        let (rc, _, err) = podssh(&home, port, "cp", &["auto.bin", "u@127.0.0.1:auto-up.bin"]);
        assert_eq!(rc, 0, "{err}");
        let same = std::fs::read(home.join("auto.bin")).unwrap() == std::fs::read(home.join("auto-up.bin")).unwrap();
        assert!(same, "each byte of the sparse source");
        if used("auto.bin") < 1 << 20 {
            let half = want.len() as u64 / 2;
            assert!(used("up.bin") < half && used("down.bin") < half, "{} {}", used("up.bin"), used("down.bin"));
            // A sparse source makes holes with no flag.
            assert!(used("auto-up.bin") < 1 << 20, "{}", used("auto-up.bin"));
        } else {
            // macOS on a runner of GitHub allocated each copy (T-218); with
            // no hole in the source either, no copy could keep one there.
            eprintln!(
                "this file system keeps no hole: the source of 8 MiB with 6 bytes uses {} bytes; each byte is \
                 checked, and the holes are not",
                used("auto.bin")
            );
        }
    }
    assert_eq!(std::fs::read(home.join("up.bin")).unwrap(), want, "each byte up");
    assert_eq!(std::fs::read(home.join("down.bin")).unwrap(), want, "each byte down");
}

#[test]
fn two_names_of_one_file_arrive_as_one_file_with_two_names() {
    need_server!();
    let home = scratch("links");
    let (_runtime, port) = server(&home);
    let src = home.join("src");
    std::fs::create_dir_all(src.join("d")).unwrap();
    std::fs::write(src.join("a"), b"one file, two names").unwrap();
    std::fs::hard_link(src.join("a"), src.join("d/b")).unwrap();
    std::fs::write(src.join("c"), b"one file, two names").unwrap();
    // Into a directory that is there: each run makes far/src.
    std::fs::create_dir_all(home.join("far")).unwrap();
    let up = home.join("far/src");
    for run in 0..2 {
        // The second run goes over the first.
        let (rc, _, err) = podssh(&home, port, "cp", &["-r", "-v", "src", "u@127.0.0.1:far"]);
        assert_eq!(rc, 0, "{err}");
        assert!(err.contains("a hard link to far/src/a"), "{err}");
        for name in ["a", "d/b", "c"] {
            assert_eq!(std::fs::read(up.join(name)).unwrap(), b"one file, two names", "{name}");
        }
        // One file: what is written through one name shows through the other.
        let more = format!("one file, two names, run {run}");
        std::fs::write(up.join("a"), &more).unwrap();
        assert_eq!(std::fs::read_to_string(up.join("d/b")).unwrap(), more, "one file");
        assert_eq!(std::fs::read(up.join("c")).unwrap(), b"one file, two names", "another file");
        for dir in ["far/src", "far/src/d"] {
            let left: Vec<_> = std::fs::read_dir(home.join(dir)).unwrap().flatten().collect();
            let temp = left.iter().any(|e| e.file_name().to_string_lossy().contains(".podssh-"));
            assert!(!temp, "a temporary name stayed in {dir}: {left:?}");
        }
    }
    let (rc, out, err) = podssh(&home, port, "cp", &["-r", "--dry-run", "src", "u@127.0.0.1:again"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.contains("hardlink again/d/b -> again/a"), "{out}");
    assert!(!home.join("again").exists(), "a dry run changed nothing");
}

#[test]
fn the_owner_is_kept_where_a_side_may_give_a_file_away_and_said_where_not() {
    need_server!();
    let home = scratch("owner");
    let (_runtime, port) = server(&home);
    std::fs::write(home.join("mine.bin"), b"mine").unwrap();
    let (rc, _, up) = podssh(&home, port, "cp", &["--owner", "mine.bin", "u@127.0.0.1:up.bin"]);
    assert_eq!(rc, 0, "{up}");
    let (rc, _, down) = podssh(&home, port, "cp", &["--owner", "u@127.0.0.1:up.bin", "down.bin"]);
    assert_eq!(rc, 0, "{down}");
    #[cfg(unix)]
    {
        // One user on both sides: each side may keep it, with no note.
        use std::os::unix::fs::MetadataExt;
        let owner = |name: &str| {
            let meta = std::fs::metadata(home.join(name)).unwrap();
            (meta.uid(), meta.gid())
        };
        assert_eq!(owner("up.bin"), owner("mine.bin"));
        assert_eq!(owner("down.bin"), owner("mine.bin"));
        assert!(!up.contains("not kept") && !down.contains("not kept"), "{up}{down}");
    }
    #[cfg(windows)]
    {
        assert!(up.contains("the owner was not kept: this system has no owner by number"), "{up}");
        assert!(down.contains("the owner was not kept: this system has no owner by number"), "{down}");
    }
}
