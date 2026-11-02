//! `podssh cp` and `podssh sftp` with requests in flight together (T-140),
//! against the test's SSH server on the loopback, whose subsystem `sftp` is
//! OpenSSH's `sftp-server` (`ssh_harness::sftp`): a file goes there and back
//! with each byte, by `cp` and by `sftp`'s put and get, and `-v` says the size
//! of each request, how many are in flight, and the rate of each copy; a tree
//! goes there and back by `sftp`'s `put -r` and `get -r` (T-298); `sftp`'s
//! `ls` prints OpenSSH's long form and orders (T-471). With no `sftp-server`
//! on this machine, each test says that it did not run.

mod cleanup;
mod ssh_harness;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-copy-pipeline-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The test's server, with a new host key in `home`, where its
/// `sftp-server` runs; on a runtime of its own.
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

/// `podssh VERB` with `args`, in the test's home, and its code and stderr.
fn podssh(home: &Path, args: &[String]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).current_dir(home).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The options of each run against the server on `port`.
fn options(home: &Path) -> Vec<String> {
    let known = home.join("known_hosts").display().to_string();
    ["--direct", "-v", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"]
        .iter()
        .map(|s| s.to_string())
        .chain([format!("UserKnownHostsFile={known}")])
        .collect()
}

fn data(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect()
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
fn cp_copies_up_and_down_with_requests_in_flight() {
    need_server!();
    let home = scratch("cp");
    let (_runtime, port) = server(&home);
    let want = data(3_000_000);
    std::fs::write(home.join("here.bin"), &want).unwrap();
    let mut up = vec!["cp".to_string(), "--timeout".into(), "120s".into(), "-P".into(), port.to_string()];
    up.extend(options(&home));
    up.extend(["here.bin".to_string(), "u@127.0.0.1:there.bin".to_string()]);
    let (rc, err) = podssh(&home, &up);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("in flight") && err.contains("MiB/s"), "{err}");
    assert_eq!(std::fs::read(home.join("there.bin")).unwrap(), want, "the server's copy");
    let mut down = vec!["cp".to_string(), "--timeout".into(), "120s".into(), "-P".into(), port.to_string()];
    down.extend(options(&home));
    down.extend(["u@127.0.0.1:there.bin".to_string(), "back.bin".to_string()]);
    let (rc, err) = podssh(&home, &down);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("back.bin")).unwrap(), want, "the copy back");
}

#[test]
fn sftp_puts_and_gets_with_the_requests_and_the_size_that_it_is_given() {
    need_server!();
    let home = scratch("sftp");
    let (_runtime, port) = server(&home);
    let want = data(2_000_000);
    std::fs::write(home.join("local.bin"), &want).unwrap();
    std::fs::write(home.join("batch"), "put local.bin remote.bin\nget remote.bin back.bin\n").unwrap();
    for (flags, says) in [
        (vec!["-R", "4", "-B", "32768"], "32768 bytes, 4 in flight"),
        (vec!["-X", "nrequests=2", "-X", "buffer=16K"], "16384 bytes, 2 in flight"),
        (vec!["-R", "64", "-B", "64K"], "65536 bytes, 8 in flight"),
    ] {
        let _ = std::fs::remove_file(home.join("back.bin"));
        let mut args = vec!["sftp".to_string(), "-P".into(), port.to_string(), "-b".into(), "batch".into()];
        args.extend(flags.iter().map(|f| f.to_string()));
        args.extend(options(&home));
        args.push("u@127.0.0.1".into());
        let (rc, err) = podssh(&home, &args);
        assert_eq!(rc, 0, "{flags:?}: {err}");
        assert!(err.contains(&format!("writes of {says}")), "{flags:?}: {err}");
        assert!(err.contains(&format!("reads of {says}")), "{flags:?}: {err}");
        assert_eq!(std::fs::read(home.join("remote.bin")).unwrap(), want, "{flags:?}: the server's copy");
        assert_eq!(std::fs::read(home.join("back.bin")).unwrap(), want, "{flags:?}: the copy back");
    }
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

/// `sftp`'s `put -r` and `get -R` (T-298): a tree with levels, an empty
/// directory and names with a space goes there and comes back in one batch,
/// each file equal to its source; `sftp -r` makes each put so, into a
/// directory that exists under it; without either, a directory ends the
/// batch.
#[test]
fn sftp_puts_and_gets_a_tree_with_r() {
    need_server!();
    let home = scratch("tree");
    let (_runtime, port) = server(&home);
    let src = home.join("dir");
    std::fs::create_dir_all(src.join("a/b c/d")).unwrap();
    std::fs::create_dir_all(src.join("empty")).unwrap();
    std::fs::write(src.join("top.txt"), b"top").unwrap();
    std::fs::write(src.join("a/one two.bin"), data(70_000)).unwrap();
    std::fs::write(src.join("a/b c/d/deep"), b"deep").unwrap();
    let sftp = |flags: &[&str], batch: &str| {
        std::fs::write(home.join("batch"), batch).unwrap();
        let mut args = vec!["sftp".to_string(), "-P".into(), port.to_string(), "-b".into(), "batch".into()];
        args.extend(flags.iter().map(|f| f.to_string()));
        args.extend(options(&home));
        args.push("u@127.0.0.1".into());
        podssh(&home, &args)
    };
    // Into new names: there, then back here.
    let (rc, err) = sftp(&[], "put -r dir far\nget -R far back\n");
    assert_eq!(rc, 0, "{err}");
    assert_eq!(listing(&home.join("far")), listing(&src), "the tree there");
    assert_eq!(listing(&home.join("back")), listing(&src), "the tree back");
    assert!(home.join("back/empty").is_dir(), "the empty directory");
    // sftp -r, into a directory that exists: the tree goes under it.
    std::fs::create_dir_all(home.join("into")).unwrap();
    let (rc, err) = sftp(&["-r"], "put dir into\n");
    assert_eq!(rc, 0, "{err}");
    assert_eq!(listing(&home.join("into/dir")), listing(&src), "the tree under a directory that exists");
    // Without -r a directory is no file to copy, and the batch ends there.
    let (rc, err) = sftp(&[], "put dir again\n");
    assert_eq!(rc, 66, "{err}");
    assert!(err.contains("-r copies it") && !home.join("again").exists(), "{err}");
}

/// `podssh sftp -b batch` as `user`, in UTC: its code, each command's lines
/// of stdout under the command's echo, and stderr.
#[cfg(unix)]
fn sftp_batch(home: &Path, port: u16, user: &str, batch: &str) -> (i32, BTreeMap<String, Vec<String>>, String) {
    std::fs::write(home.join("batch"), batch).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["sftp", "-P", &port.to_string(), "-b", "batch"]).args(options(home)).arg(format!("{user}@127.0.0.1"));
    cmd.current_dir(home).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("TZ", "UTC");
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    let mut each: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut at = String::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        match line.strip_prefix("sftp> ") {
            Some(command) => at = command.to_string(),
            None => each.entry(at.clone()).or_default().push(line.to_string()),
        }
    }
    (out.status.code().unwrap_or(-1), each, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The name of the user `uid` in `/etc/passwd`, where it is there.
#[cfg(unix)]
fn user_name(uid: u32) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 2 && f[2] == uid.to_string()).then(|| f[0].to_string())
    })
}

/// The last word of each line: the names, in the order shown.
#[cfg(unix)]
fn names(lines: &[String]) -> Vec<String> {
    lines.iter().filter_map(|l| l.split_whitespace().last().map(str::to_string)).collect()
}

/// `sftp`'s `ls` against OpenSSH's `sftp-server` (T-471): `-l` of a
/// directory and of a file gives OpenSSH's seven columns (the time of three
/// words), `?` for the link count, each kind's letter, the owner by name; `-n`
/// by number; `-t`, `-S` and `-r` their orders; `-1` one name a line. With
/// `users-groups-by-id@openssh.com` hidden from the version reply, `ls -l`
/// of a directory prints the server's own long names, with their link counts.
#[cfg(unix)]
#[test]
fn sftp_ls_gives_openssh_s_long_form_and_orders() {
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, SystemTime};
    need_server!();
    let home = scratch("ls");
    let (_runtime, port) = server(&home);
    let dir = home.join("lsdir");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    // Three files of their own sizes and times: c the newest, b the largest.
    let day = Duration::from_secs(86_400);
    for (name, size, days) in [("a.txt", 10usize, 400u32), ("b.bin", 3000, 20), ("c", 200, 2)] {
        std::fs::write(dir.join(name), vec![b'x'; size]).unwrap();
        let file = std::fs::File::options().write(true).open(dir.join(name)).unwrap();
        file.set_modified(SystemTime::now() - day * days).unwrap();
    }
    std::fs::write(dir.join(".hidden"), b"h").unwrap();
    std::os::unix::fs::symlink("a.txt", dir.join("link")).unwrap();
    let fifo = std::ffi::CString::new(dir.join("fifo").into_os_string().into_encoded_bytes()).unwrap();
    // SAFETY: a path with no NUL, and a mode.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0, "mkfifo");
    let uid = std::fs::metadata(dir.join("c")).unwrap().uid();
    let batch = concat!(
        "ls -l lsdir\nls -l lsdir/c\nls -ln lsdir\nls -lt lsdir\n",
        "ls -lS lsdir\nls -lr lsdir\nls -1 lsdir\nls -la lsdir\n"
    );
    let (rc, each, err) = sftp_batch(&home, port, "u", batch);
    assert_eq!(rc, 0, "{err}");
    let long = &each["ls -l lsdir"];
    assert_eq!(long.len(), 6, "a.txt, b.bin, c, fifo, link and sub, no dot name: {long:?}");
    for line in long {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(words.len(), 9, "seven columns, the time of three words: {line}");
        assert_eq!(words[1], "?", "SFTP gives no link count: {line}");
        assert!(words[8].starts_with("lsdir/"), "the path as given, then the name: {line}");
        if let Some(name) = user_name(uid) {
            assert_eq!(words[2], name, "the owner by name: {line}");
        }
    }
    let kind = |name: &str| long.iter().find(|l| l.ends_with(&format!(" lsdir/{name}"))).map(|l| &l[..1]);
    assert_eq!(
        (kind("a.txt"), kind("sub"), kind("link"), kind("fifo")),
        (Some("-"), Some("d"), Some("l"), Some("p")),
        "{long:?}"
    );
    let one = &each["ls -l lsdir/c"];
    assert!(one.len() == 1 && one[0].starts_with("-rw") && one[0].ends_with(" lsdir/c"), "{one:?}");
    assert_eq!(one[0].split_whitespace().nth(4), Some("200"), "the size: {one:?}");
    for line in &each["ls -ln lsdir"] {
        assert_eq!(line.split_whitespace().nth(2), Some(uid.to_string().as_str()), "-n: the number: {line}");
    }
    // The order of the three files in each listing.
    let files = |command: &str| -> Vec<String> {
        let shown = names(&each[command]);
        shown.into_iter().filter(|n| ["lsdir/a.txt", "lsdir/b.bin", "lsdir/c"].contains(&n.as_str())).collect()
    };
    assert_eq!(files("ls -l lsdir"), ["lsdir/a.txt", "lsdir/b.bin", "lsdir/c"], "by name");
    assert_eq!(files("ls -lt lsdir"), ["lsdir/c", "lsdir/b.bin", "lsdir/a.txt"], "the newest first");
    assert_eq!(files("ls -lS lsdir"), ["lsdir/b.bin", "lsdir/c", "lsdir/a.txt"], "the largest first");
    assert_eq!(files("ls -lr lsdir"), ["lsdir/c", "lsdir/b.bin", "lsdir/a.txt"], "by name, turned round");
    assert_eq!(each["ls -1 lsdir"], ["lsdir/a.txt", "lsdir/b.bin", "lsdir/c", "lsdir/fifo", "lsdir/link", "lsdir/sub"]);
    // The old year form for a time of more than half a year ago.
    let a = long.iter().find(|l| l.ends_with(" lsdir/a.txt")).unwrap();
    assert!(a.split_whitespace().nth(7).is_some_and(|y| y.len() == 4 && !y.contains(':')), "{a}");
    assert!(names(&each["ls -la lsdir"]).contains(&"lsdir/.hidden".to_string()), "-a");
    // No names by number from the server: its own long names.
    let (rc, each, err) = sftp_batch(&home, port, "noids-u", "ls -l lsdir\n");
    assert_eq!(rc, 0, "{err}");
    let own = &each["ls -l lsdir"];
    assert_eq!(own.len(), 6, "{own:?}");
    for line in own {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(words[1].parse::<u64>().is_ok(), "the server's line has a link count: {line}");
        assert!(!words[words.len() - 1].contains('/'), "the server's line names the entry alone: {line}");
    }
}
