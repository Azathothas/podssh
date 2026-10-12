//! The progress, the bandwidth limit and the interruption of a copy (T-145):
//! the line and its rate, the token bucket, and against the test's SSH
//! server on the loopback (`ssh_harness`, with OpenSSH's `sftp-server`): a
//! copy under `-l` takes its time, the line goes to stderr and never to
//! stdout, and `--jsonl` gives `progress` objects. The interruption by
//! SIGINT is measured on Unix, here and in the gate.

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
    // 8000 Kbit/s: 1,000,000 bytes a second.
    let mut bucket = Bucket::of_kbits(8000);
    let start = Instant::now();
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
