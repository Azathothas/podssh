//! The exit code of `podssh ssh` when a session does not end with its
//! status on stdout (T-026), against the test's SSH server on the loopback:
//! a closed stdout waits for the status, 5 s at most, and never reads as a
//! success; `-N` that the server ends is 255, with the server's words; a
//! link cut after the status and before the output's end is 255 (T-461).

mod cleanup;
mod ssh_harness;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-exit-status-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The test's server, with a new host key, on a runtime of its own.
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

/// `podssh ssh --direct` to the server as `user`.
fn ssh(home: &Path, port: u16, args: &[&str]) -> Command {
    let known = home.join("known_hosts");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", known.display()));
    cmd.args(args);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd
}

/// Read some of stdout, then close it; the code and stderr, within the limit.
/// stdin stays open, so that the remote writes until podssh itself sends the
/// end of input when its stdout closes. With no stdin, the end of input went
/// out at once, and a remote that stops there could stop before 64 KiB came
/// (CI at `615c415`).
fn close_early(mut cmd: Command) -> (i32, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    stdout.read_exact(&mut buf).expect("the remote's bytes come");
    drop(stdout);
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh did not end within {LIMIT:?} after its stdout closed");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    drop(stdin);
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_closed_stdout_waits_for_the_status_and_gives_it() {
    let home = scratch("status");
    let (_runtime, port) = server(&home);
    let (code, err) = close_early(ssh(&home, port, &["tester@127.0.0.1", "spew"]));
    assert_eq!(code, 7, "the remote's status after its end of input: {err}");
}

#[test]
fn a_closed_stdout_with_no_status_is_never_a_success() {
    let home = scratch("mute");
    let (_runtime, port) = server(&home);
    let (code, err) = close_early(ssh(&home, port, &["tester@127.0.0.1", "spew-mute"]));
    assert_eq!(code, 255, "{err}");
}

#[test]
fn a_dash_n_session_that_the_server_ends_is_255_with_its_words() {
    let home = scratch("dash-n");
    let (_runtime, port) = server(&home);
    let mut cmd = ssh(&home, port, &["-N", "kick@127.0.0.1"]);
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh -N did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert!(err.contains("the server ended the connection") && err.contains("kicked by the test"), "{err}");
}

/// Run `cmd` with no stdin, its stdout and stderr read as they come, so that
/// a large output never stops it, within the limit: its code, stdout and
/// stderr.
fn finished(mut cmd: Command) -> (Option<i32>, Vec<u8>, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (mut stdout, mut stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (out, err) = (out.join().unwrap(), err.join().unwrap());
    (status.code(), out, String::from_utf8_lossy(&err).into_owned())
}

/// The status 0, then 1000000 bytes, then a link cut with no EOF and no
/// Close (GitHub #84, where 0 came with 67010560 bytes of 70000000): no
/// success, and the line says the status that came.
#[test]
fn a_cut_after_the_status_and_before_the_output_ends_is_255() {
    let home = scratch("cut");
    let (_runtime, port) = server(&home);
    let started = Instant::now();
    let (code, _, err) = finished(ssh(&home, port, &["tester@127.0.0.1", "cut", "1000000"]));
    assert_eq!(code, Some(255), "{err}");
    let line = format!(
        "the connection to 127.0.0.1:{port} was lost before the output ended (the remote command had exited with 0)"
    );
    assert!(err.contains(&line), "{err}");
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
}

/// The same with the EOF after the bytes, then the cut: the output ended,
/// so the status holds, and each byte came.
#[test]
fn a_cut_after_the_status_and_the_output_end_keeps_the_status() {
    let home = scratch("cut-eof");
    let (_runtime, port) = server(&home);
    let (code, out, err) = finished(ssh(&home, port, &["tester@127.0.0.1", "cut-eof", "1000000"]));
    assert_eq!((code, out.len()), (Some(0), 1_000_000), "{err}");
    assert!(!err.contains("was lost"), "{err}");
}

/// What a connection that ended before its session may mean (T-464).
const MEANING: &str =
    "the far host may be stopped, the login may no longer be valid, or the server takes no more sessions";

/// GitHub #104: the server logs in, then ends the connection with its words
/// when the session is asked for. No refusal is said: the order of the
/// events, the server's words, then what it may mean.
#[test]
fn the_server_ending_after_login_is_no_refused_session() {
    let home = scratch("gone-said");
    let (_runtime, port) = server(&home);
    let (code, _, err) = finished(ssh(&home, port, &["gone-said-tester@127.0.0.1", "echo", "hi"]));
    assert_eq!(code, Some(255), "{err}");
    let line = "the server ended the connection right after the login, before a session opened: the server said: \
                the far host stopped (ByApplication)";
    assert!(err.contains(line), "{err}");
    assert!(err.contains(MEANING), "{err}");
    assert!(!err.contains("refused"), "no refusal: {err}");
}

/// The same with a connection cut with no word: still no refusal.
#[test]
fn a_cut_after_login_is_no_refused_session() {
    let home = scratch("gone-cut");
    let (_runtime, port) = server(&home);
    let (code, _, err) = finished(ssh(&home, port, &["gone-tester@127.0.0.1", "echo", "hi"]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("the server ended the connection right after the login, before a session opened"), "{err}");
    assert!(err.contains(MEANING), "{err}");
    assert!(!err.contains("refused"), "no refusal: {err}");
}

/// A server that refuses the session: its reason, in OpenSSH's words.
#[test]
fn a_session_refused_after_login_names_its_reason() {
    let home = scratch("nosession");
    let (_runtime, port) = server(&home);
    let (code, _, err) = finished(ssh(&home, port, &["nosession-tester@127.0.0.1", "echo", "hi"]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("the server refused to open a session: open failed: administratively prohibited"), "{err}");
    assert!(!err.contains(MEANING), "a refusal is no ended connection: {err}");
}

/// GitHub #85: the connection ends at `-R`'s `tcpip-forward`, and the line
/// names the cause, the server's words.
#[test]
fn a_forward_ended_after_login_names_the_cause() {
    let home = scratch("gone-fwd");
    let (_runtime, port) = server(&home);
    let args = ["-N", "-R", "12345:127.0.0.1:9", "gone-fwd-tester@127.0.0.1"];
    let (code, _, err) = finished(ssh(&home, port, &args));
    assert_eq!(code, Some(255), "{err}");
    let line = "the connection was lost while the forwards were asked for: the server said: the far host stopped \
                (ByApplication)";
    assert!(err.contains(line), "{err}");
}
