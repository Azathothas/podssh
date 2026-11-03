//! The progress, the bandwidth limit and the interruption of a copy (T-145):
//! the line and its rate, the token bucket, and against the test's SSH
//! server on the loopback (`ssh_harness`, with OpenSSH's `sftp-server`): a
//! copy under `-l` takes its time, the line goes to stderr and never to
//! stdout, and `--jsonl` gives `progress` objects. The interruption by
//! SIGINT is measured on Unix, here and in the gate. The summary and the
//! run's progress (T-472): a run in a pipe ends with one summary line on
//! stderr, none with `-q`, and one `summary` object with `--jsonl`; a copy
//! that lasts 12 s writes a plain line in the pipe, one of 1 s none; the
//! files of a tree at once draw one line for the run.

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use podssh_cli::cp::gauge::{bytes, line};
use podssh_cli::cp::rate::{request_len, requests, Bucket};

#[test]
fn the_line_says_the_bytes_the_percent_the_rate_and_the_time_left() {
    let text = line("big.iso", 5 << 20, 20 << 20, Duration::from_secs(5));
    assert_eq!(text, "big.iso  5.0 MiB of 20.0 MiB  25%  1.0 MiB/s  0:15 left");
    assert_eq!(line("x", 0, 0, Duration::ZERO), "x  0 B of 0 B  100%  0 B/s  --:-- left");
    assert_eq!(bytes(1023), "1023 B");
    assert_eq!(bytes(1536), "1.5 KiB");
    assert_eq!(bytes(3 << 30), "3.00 GiB");
}

#[test]
fn the_bucket_lets_the_limit_s_bytes_through_each_second() {
    // 8000 Kbit/s: 1,000,000 bytes a second, from the test's own start: a
    // second reading of the clock gave the bucket the bytes of the time
    // between the two (CI at ebde017).
    let start = Instant::now();
    let mut bucket = Bucket::of_kbits_at(8000, start);
    assert_eq!(bucket.take_at(250_000, start), Duration::from_millis(250), "an empty bucket waits");
    // A second on, a quarter of a second of bytes at most is saved up.
    let later = start + Duration::from_secs(1);
    assert_eq!(bucket.take_at(250_000, later), Duration::ZERO);
    assert_eq!(bucket.take_at(500_000, later), Duration::from_millis(500));
    // Under 8 Kbit/s a request holds 10 s of bytes at most, 1 KiB at least.
    assert_eq!(request_len(1000.0, 261_120), 10_000);
    assert_eq!(request_len(10.0, 261_120), 1024);
    assert_eq!(request_len(1e9, 261_120), 261_120);
    assert_eq!(requests(1_000_000.0, 32_768), 31);
    assert_eq!(requests(10.0, 1024), 1);
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cp-progress-{name}-{}", std::process::id()));
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

fn cp(home: &Path, port: u16, args: &[&str], progress: Option<&str>) -> Command {
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
    for name in
        ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "PODSSH_PROGRESS"]
    {
        cmd.env_remove(name);
    }
    if let Some(mode) = progress {
        cmd.env("PODSSH_PROGRESS", mode);
    }
    cmd
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
fn a_limited_copy_takes_its_time_and_its_line_goes_to_stderr_only() {
    need_server!();
    let home = scratch("limit");
    let (_runtime, port) = server(&home);
    let data: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(home.join("f.bin"), &data).unwrap();
    // 8000 Kbit/s: 1,000,000 bytes a second, so 1.5 s at least.
    let start = Instant::now();
    let out = cp(&home, port, &["-l", "8000", "f.bin", "u@127.0.0.1:up.bin"], Some("line")).output().unwrap();
    let took = start.elapsed();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(took >= Duration::from_millis(1400), "{took:?}");
    assert!(out.stdout.is_empty(), "the line never goes to stdout: {:?}", String::from_utf8_lossy(&out.stdout));
    assert!(err.contains("\rf.bin  ") && err.contains(" of 1.4 MiB"), "{err:?}");
    assert_eq!(std::fs::read(home.join("up.bin")).unwrap(), data);
    // --jsonl: progress objects, then the done one, on stdout.
    let out = cp(&home, port, &["--jsonl", "-l", "8000", "f.bin", "u@127.0.0.1:up2.bin"], None).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(text.contains(r#""event":"progress""#) && text.contains(r#""event":"done""#), "{text}");
    // A limit of 0 is refused.
    let out = cp(&home, port, &["-l", "0", "f.bin", "u@127.0.0.1:x"], None).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("-l 0: give the limit in Kbit/s"));
}

/// The lines of `err` that start as the summary does: `podssh: N copied`.
fn summaries(err: &str) -> Vec<&str> {
    err.lines()
        .filter_map(|l| l.strip_prefix("podssh: "))
        .filter(|l| l.split_once(" copied").is_some_and(|(n, _)| n.parse::<u64>().is_ok()))
        .collect()
}

/// Three files in a pipe, with no -v (T-472): one summary line on stderr and
/// nothing on stdout; none with -q; with --jsonl one summary object on
/// stdout and no line; after a failure, the summary counts it.
#[test]
fn a_run_in_a_pipe_ends_with_one_summary_line() {
    need_server!();
    let home = scratch("summary");
    let (_runtime, port) = server(&home);
    std::fs::create_dir_all(home.join("far")).unwrap();
    for (name, len) in [("a.bin", 1000), ("b.bin", 2000), ("c.bin", 3000)] {
        std::fs::write(home.join(name), vec![7u8; len]).unwrap();
    }
    let three = ["a.bin", "b.bin", "c.bin", "u@127.0.0.1:far/"];
    let out = cp(&home, port, &three, None).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(out.stdout.is_empty(), "the summary never goes to stdout");
    let said = summaries(&err);
    assert_eq!(said.len(), 1, "{err}");
    assert!(said[0].starts_with("3 copied (5.9 KiB), in ") && said[0].ends_with("/s)"), "{err}");
    let mut quiet = vec!["-q"];
    quiet.extend(three);
    let out = cp(&home, port, &quiet, None).output().unwrap();
    assert_eq!((out.status.code(), out.stderr.as_slice()), (Some(0), &b""[..]), "-q");
    let mut jsonl = vec!["--jsonl"];
    jsonl.extend(three);
    let out = cp(&home, port, &jsonl, None).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(summaries(&err).is_empty(), "the object takes the line's place: {err}");
    let text = String::from_utf8_lossy(&out.stdout);
    let objects: Vec<serde_json::Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let sums: Vec<&serde_json::Value> = objects.iter().filter(|o| o["event"] == "summary").collect();
    assert_eq!(sums.len(), 1, "{text}");
    assert_eq!((sums[0]["copied"].as_u64(), sums[0]["bytes"].as_u64()), (Some(3), Some(6000)), "{text}");
    assert_eq!(objects.last().map(|o| &o["event"]), Some(&serde_json::json!("summary")), "the last object: {text}");
    // A missing source: said when it came, and counted.
    let out = cp(&home, port, &["a.bin", "gone.bin", "u@127.0.0.1:far/"], None).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(66), "{err}");
    let said = summaries(&err);
    assert!(said.len() == 1 && said[0].starts_with("1 copied (1000 B), 1 failed, in "), "{err}");
}

/// In a pipe (T-472): a copy under -l that lasts 12 s writes a plain line or
/// more, with no carriage return and no escape; a copy of 1 s writes none.
#[test]
fn a_long_copy_in_a_pipe_says_that_it_lives_and_a_short_one_does_not() {
    need_server!();
    let home = scratch("pipe-line");
    let (_runtime, port) = server(&home);
    // 8000 Kbit/s: 1,000,000 bytes a second.
    std::fs::write(home.join("long.bin"), vec![3u8; 12_000_000]).unwrap();
    std::fs::write(home.join("short.bin"), vec![4u8; 1_000_000]).unwrap();
    let out = cp(&home, port, &["-l", "8000", "long.bin", "u@127.0.0.1:long.bin"], None).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    let lines: Vec<&str> = err.lines().filter(|l| l.starts_with("podssh: 0 of 1 file, ")).collect();
    assert!(!lines.is_empty(), "a plain line past 10 s: {err:?}");
    assert!(lines.iter().all(|l| l.contains("; now long.bin, ")), "{err:?}");
    assert!(!err.contains(['\r', '\x1b']), "no carriage return and no escape in a pipe: {err:?}");
    let out = cp(&home, port, &["-l", "8000", "short.bin", "u@127.0.0.1:short.bin"], None).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(!err.contains(" of 1 file, "), "a copy of 1 s writes no line: {err:?}");
    assert_eq!(summaries(&err).len(), 1, "{err}");
}

/// The files of a tree at once (T-472): with the terminal's line asked for,
/// each line drawn is the run's, with its count of files, not a file's own.
#[test]
fn the_files_of_a_tree_at_once_draw_one_line_for_the_run() {
    need_server!();
    let home = scratch("run-line");
    let (_runtime, port) = server(&home);
    std::fs::create_dir_all(home.join("tree")).unwrap();
    for i in 0..8u8 {
        std::fs::write(home.join("tree").join(format!("f{i}")), vec![i; 300_000]).unwrap();
    }
    let args = ["-r", "--parallel", "4", "-l", "8000", "tree", "u@127.0.0.1:up"];
    let out = cp(&home, port, &args, Some("line")).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    // Each piece after a carriage return, to its erase: what was drawn.
    let drawn: Vec<&str> =
        err.split('\r').filter_map(|piece| piece.split_once("\x1b[K")).map(|(text, _)| text).collect();
    let drawn: Vec<&str> = drawn.into_iter().filter(|text| !text.is_empty()).collect();
    assert!(!drawn.is_empty(), "{err:?}");
    assert!(drawn.iter().all(|text| text.contains(" of 8 files ")), "one line for the run: {drawn:?}");
}

/// SIGINT in the middle: exit 130, the temporary file and the side file
/// named and kept, and the same command goes on from them.
#[cfg(unix)]
#[test]
fn an_interrupted_copy_keeps_and_names_its_partial_file() {
    need_server!();
    let home = scratch("interrupt");
    let (_runtime, port) = server(&home);
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();
    std::fs::write(home.join("f.bin"), &data).unwrap();
    // 4000 Kbit/s: 0.5 MB/s, 6 s in all.
    let child = cp(&home, port, &["-l", "4000", "f.bin", "u@127.0.0.1:up.bin"], None).spawn().unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    let killed = Command::new("kill").args(["-INT", &child.id().to_string()]).status().unwrap();
    assert!(killed.success());
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(130), "{err}");
    assert!(err.contains("interrupted; the partial copy stays at"), "{err}");
    let partial = std::fs::read_dir(&home)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().contains(".podssh-"));
    assert!(partial, "the temporary file stays");
    let out = cp(&home, port, &["-v", "f.bin", "u@127.0.0.1:up.bin"], None).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("continuing"), "the second run goes on: {err}");
    assert_eq!(std::fs::read(home.join("up.bin")).unwrap(), data);
}
