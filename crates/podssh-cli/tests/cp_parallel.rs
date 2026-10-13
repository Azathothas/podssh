//! `podssh cp --parallel K` (T-141), against the test's SSH server on the
//! loopback, whose subsystem `sftp` is OpenSSH's `sftp-server`: a file of
//! more than one chunk goes up and comes back down as chunks, K at once, each
//! over an SFTP session of its own in the one connection, and agrees with the
//! disk; `-v` says the chunks and the tasks. A count out of range is refused.
//! With no `sftp-server` on this machine, the copies say that they did not
//! run.
//!
//! Several small files (T-297, the tests named `small`): 50 files go up and
//! come back down 8 at once, with at most 8 SFTP sessions at once on the
//! connection (the server counts them), and the report lists them in the
//! order of the sources; so do the files of a tree with `-r`. A connection
//! cut in the middle goes on over the next one, and a run that ends there
//! goes on in the next run from each side file. A failure early in the
//! order of the sources sets the code, though a later one came first.

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ssh_harness::watch::Watch;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cp-parallel-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// A new host key in `home`, for the test's server.
fn host_key(home: &Path) -> PathBuf {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    key
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
}

fn server(home: &Path) -> (tokio::runtime::Runtime, u16) {
    let key = host_key(home);
    let runtime = runtime();
    let port = runtime.block_on(ssh_harness::start(&key));
    (runtime, port)
}

/// The test's server with a watch of its SFTP sessions (T-297): its runtime,
/// its port, the count of its connections, and the watch.
fn watched(home: &Path) -> (tokio::runtime::Runtime, u16, Arc<AtomicUsize>, Arc<Watch>) {
    let key = host_key(home);
    let runtime = runtime();
    let (port, connections, watch) = runtime.block_on(ssh_harness::watch::start_watched(&key));
    (runtime, port, connections, watch)
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

/// What a run of `podssh cp --jsonl` gave.
struct Ran {
    code: i32,
    /// The source of each `done` object, in their order.
    done: Vec<String>,
    /// The code of its `error` object, if one came.
    error: Option<i64>,
    stderr: String,
}

/// `podssh cp --jsonl -v` with `args` in `home`, its side files in
/// `home/cache`.
fn cp_jsonl(home: &Path, port: u16, args: &[&str]) -> Ran {
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["cp", "--jsonl", "--timeout", "300s", "--direct", "-v", "-P", &port.to_string()])
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={known}"))
        .args(args)
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
    cmd.env("PODSSH_CACHE_DIR", home.join("cache"));
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let mut ran = Ran { code: out.status.code().unwrap_or(-1), done: Vec::new(), error: None, stderr };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        match event["event"].as_str() {
            Some("done") => ran.done.push(event["source"].as_str().unwrap_or_default().to_string()),
            Some("error") => ran.error = event["code"].as_i64(),
            _ => {}
        }
    }
    ran
}

/// Bytes of a file of its own: no two files of a test have the same.
fn bytes_of(seed: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| ((j * 31 + seed * 7919 + j / 251) % 251) as u8).collect()
}

/// `count` files in `dir` under `home`, `fNN.bin` from `first` on, each of
/// its own bytes and about `len` of them: their paths from `home`, in order.
fn small_files(home: &Path, dir: &str, first: usize, count: usize, len: usize) -> Vec<String> {
    std::fs::create_dir_all(home.join(dir)).unwrap();
    (first..first + count)
        .map(|i| {
            let name = format!("{dir}/f{i:02}.bin");
            std::fs::write(home.join(&name), bytes_of(i, len + i * 997)).unwrap();
            name
        })
        .collect()
}

/// `--parallel 8`, each of `sources`, then `dest`.
fn eight<'a>(sources: &'a [String], dest: &'a str) -> Vec<&'a str> {
    let mut args = vec!["--parallel", "8"];
    args.extend(sources.iter().map(String::as_str));
    args.push(dest);
    args
}

fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `copy` holds the bytes of `source`.
fn same(source: &Path, copy: &Path) {
    let want = std::fs::read(source).unwrap();
    let got = std::fs::read(copy).ok();
    assert!(got.as_ref() == Some(&want), "{} is not a copy of {}", copy.display(), source.display());
}

/// What a copy leaves in `dir` only when it did not end: a temporary file
/// (`.NAME.podssh-RANDOM.part`) or a side file (`podssh-cp-*.resume`).
fn leftovers(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let names = entries.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned());
    names.filter(|name| name.ends_with(".part") || name.ends_with(".resume")).collect()
}

/// The side files in `home/cache` whose temporary file is still on the
/// server, whose directory is `home`.
fn live_records(home: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(home.join("cache")) else { return 0 };
    entries
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".resume"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .filter(|record| record["temp"].as_str().is_some_and(|temp| home.join(temp).is_file()))
        .count()
}

fn no_sftp_server() -> bool {
    let none = ssh_harness::sftp::server_path().is_none();
    if none {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
    }
    none
}

#[test]
fn small_files_go_eight_at_once_in_the_order_of_their_sources() {
    if no_sftp_server() {
        return;
    }
    let home = scratch("small");
    let (_runtime, port, connections, watch) = watched(&home);
    let names = small_files(&home, "src", 0, 50, 20_000);
    std::fs::create_dir(home.join("far")).unwrap();
    let ran = cp_jsonl(&home, port, &eight(&names, "u@127.0.0.1:far/"));
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(ran.stderr.contains("50 files, 8 at once"), "{}", ran.stderr);
    assert_eq!(ran.done, names, "the report keeps the order of the sources");
    for name in &names {
        same(&home.join(name), &home.join("far").join(leaf(name)));
    }
    let most = watch.most.load(Ordering::SeqCst);
    assert!((2..=8).contains(&most), "{most} SFTP sessions at once on the connection");
    assert_eq!(connections.load(Ordering::SeqCst), 1, "one connection");
    // Down, into a directory here, the same.
    std::fs::create_dir(home.join("back")).unwrap();
    let far: Vec<String> = names.iter().map(|name| format!("far/{}", leaf(name))).collect();
    let operands: Vec<String> = far.iter().map(|path| format!("u@127.0.0.1:{path}")).collect();
    let ran = cp_jsonl(&home, port, &eight(&operands, "back"));
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert_eq!(ran.done, far, "the report keeps the order of the sources");
    for name in &names {
        same(&home.join(name), &home.join("back").join(leaf(name)));
    }
    let most = watch.most.load(Ordering::SeqCst);
    assert!(most <= 8, "{most} SFTP sessions at once on the connection");
    for dir in ["far", "back", "cache"] {
        assert_eq!(leftovers(&home.join(dir)), Vec::<String>::new(), "{dir}");
    }
}

#[test]
fn small_files_and_a_large_one_go_in_the_order_of_their_sources() {
    if no_sftp_server() {
        return;
    }
    let home = scratch("small-large");
    let (_runtime, port, _connections, _watch) = watched(&home);
    let names = small_files(&home, "src", 0, 6, 20_000);
    // The fourth is of two chunks: it waits, then goes in chunks.
    std::fs::write(home.join(&names[3]), bytes_of(77, 9 << 20)).unwrap();
    std::fs::create_dir(home.join("far")).unwrap();
    let ran = cp_jsonl(&home, port, &eight(&names, "u@127.0.0.1:far/"));
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(ran.stderr.contains("6 files, 6 at once"), "{}", ran.stderr);
    let chunked = format!("{}: chunks of 8388608 bytes, 8 at once", names[3]);
    assert!(ran.stderr.contains(&chunked), "{}", ran.stderr);
    assert_eq!(ran.done, names, "the report keeps the order of the sources");
    for name in &names {
        same(&home.join(name), &home.join("far").join(leaf(name)));
    }
}

#[test]
fn small_files_go_on_after_a_break_over_the_next_connection() {
    if no_sftp_server() {
        return;
    }
    let home = scratch("small-break");
    let (_runtime, port, connections, _watch) = watched(&home);
    let names = small_files(&home, "src", 0, 50, 100_000);
    std::fs::create_dir(home.join("far")).unwrap();
    // The first connection ends after 1,500,000 bytes of SFTP input, with
    // files in flight.
    let ran = cp_jsonl(&home, port, &eight(&names, "cut-1500000-u@127.0.0.1:far/"));
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(connections.load(Ordering::SeqCst) >= 2, "a new connection after the cut");
    let continued = ran.stderr.matches(": continuing ").count();
    assert!(continued >= 2, "the files in flight go on where they were: {}", ran.stderr);
    assert_eq!(ran.done, names, "the report keeps the order of the sources");
    for name in &names {
        same(&home.join(name), &home.join("far").join(leaf(name)));
    }
    for dir in ["far", "cache"] {
        assert_eq!(leftovers(&home.join(dir)), Vec::<String>::new(), "{dir}");
    }
}

#[test]
fn small_files_go_on_in_the_next_run_from_each_side_file() {
    if no_sftp_server() {
        return;
    }
    let home = scratch("small-resume");
    let (_runtime, port, _connections, watch) = watched(&home);
    let names = small_files(&home, "src", 0, 50, 100_000);
    std::fs::create_dir(home.join("far")).unwrap();
    // The first connection is cut, and each later login refused: the run
    // ends, and leaves a side file for each file in flight.
    watch.refuse.store(true, Ordering::SeqCst);
    let args = eight(&names, "cut-1500000-u@127.0.0.1:far/");
    let first = cp_jsonl(&home, port, &args);
    assert_ne!(first.code, 0, "{}", first.stderr);
    let live = live_records(&home);
    assert!(live >= 1, "a side file and its temporary file for each file in flight: {}", first.stderr);
    // The same command again: each of them goes on from its side file.
    watch.refuse.store(false, Ordering::SeqCst);
    let again = cp_jsonl(&home, port, &args);
    assert_eq!(again.code, 0, "{}", again.stderr);
    let continued = again.stderr.matches(": continuing ").count();
    assert!(continued >= live, "{live} side files, {continued} copies went on: {}", again.stderr);
    assert_eq!(again.done, names, "the report keeps the order of the sources");
    for name in &names {
        same(&home.join(name), &home.join("far").join(leaf(name)));
    }
    for dir in ["far", "cache"] {
        assert_eq!(leftovers(&home.join(dir)), Vec::<String>::new(), "{dir}");
    }
}

#[test]
fn small_files_report_the_first_failure_in_the_order_of_their_sources() {
    if no_sftp_server() {
        return;
    }
    let home = scratch("small-failure");
    let (_runtime, port, _connections, _watch) = watched(&home);
    let names = small_files(&home, "src", 0, 10, 20_000);
    // The first is long to copy, and fails late, at its rename onto a
    // directory there (73); the sixth is missing, and fails at once (66).
    std::fs::write(home.join(&names[0]), bytes_of(99, 7 << 20)).unwrap();
    std::fs::create_dir_all(home.join("far").join(leaf(&names[0]))).unwrap();
    std::fs::remove_file(home.join(&names[5])).unwrap();
    let ran = cp_jsonl(&home, port, &eight(&names, "u@127.0.0.1:far/"));
    assert_eq!((ran.code, ran.error), (73, Some(73)), "{}", ran.stderr);
    let copied: Vec<String> = [&names[1..5], &names[6..]].concat();
    assert_eq!(ran.done, copied, "each other file, in the order of the sources");
    for name in &copied {
        same(&home.join(name), &home.join("far").join(leaf(name)));
    }
    assert_eq!(leftovers(&home.join("far")), Vec::<String>::new());
}

#[test]
fn small_files_of_a_tree_go_eight_at_once() {
    if no_sftp_server() {
        return;
    }
    let home = scratch("small-tree");
    let (_runtime, port, _connections, watch) = watched(&home);
    let mut names = small_files(&home, "tree/a", 0, 12, 20_000);
    names.extend(small_files(&home, "tree/a/b", 12, 12, 20_000));
    names.extend(small_files(&home, "tree/c", 24, 12, 20_000));
    std::fs::create_dir(home.join("far")).unwrap();
    let ran = cp_jsonl(&home, port, &["-r", "--parallel", "8", "tree", "u@127.0.0.1:far/"]);
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(ran.stderr.contains("36 files, 8 at once"), "{}", ran.stderr);
    assert_eq!(ran.done.len(), 36, "{}", ran.stderr);
    for name in &names {
        same(&home.join(name), &home.join("far").join(name));
    }
    let most = watch.most.load(Ordering::SeqCst);
    assert!((2..=8).contains(&most), "{most} SFTP sessions at once on the connection");
    // Down, under a directory here.
    std::fs::create_dir(home.join("back")).unwrap();
    let ran = cp_jsonl(&home, port, &["-r", "--parallel", "8", "u@127.0.0.1:far/tree", "back"]);
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(ran.stderr.contains("36 files, 8 at once"), "{}", ran.stderr);
    for name in &names {
        same(&home.join(name), &home.join("back").join(name));
    }
    assert!(watch.most.load(Ordering::SeqCst) <= 8);
}
