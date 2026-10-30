//! `podssh ssh --direct` through a proxy that answers `200` to CONNECT and
//! then carries no SSH (T-317), as the agent proxy of a Claude Code cloud
//! container does for a name whose TLS it intercepts: the failure names the
//! proxy as the cause, whether it resets or stays silent; a proxy that
//! carries the server's bytes is not blamed for what fails after them.

mod cleanup;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What the stand-in does after its 200.
#[derive(Clone, Copy)]
enum After {
    /// Closes with the client's banner unread, which resets the connection.
    Reset,
    /// Sends nothing, and holds the connection longer than the client waits.
    Silent,
    /// Sends a server's banner, then closes.
    Banner,
}

/// A proxy on the loopback that answers each CONNECT with 200, then does
/// `after`. Its port.
fn stand_in(after: After) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                match after {
                    After::Reset => std::thread::sleep(Duration::from_millis(500)),
                    After::Silent => std::thread::sleep(Duration::from_secs(15)),
                    After::Banner => {
                        let _ = conn.write_all(b"SSH-2.0-stand-in\r\n");
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            });
        }
    });
    port
}

/// `podssh ssh --direct` to a name, through the stand-in on `port`, with a
/// connect timeout of 3 s: its exit code, its stderr and how long it took.
fn ssh_direct(port: u16, dir: &Path) -> (Option<i32>, String, Duration) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.args(["tester@ssh.example", "true"]);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", dir).env("USERPROFILE", dir);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd.env("https_proxy", format!("http://127.0.0.1:{port}"));
    let started = Instant::now();
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = started + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh ssh --direct still ran after 60 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = started.elapsed();
    let out = child.wait_with_output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned(), took)
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-direct-proxy-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

const CAUSE: &str = "took the CONNECT, and no byte of an SSH server came back";

#[test]
fn a_proxy_that_resets_after_its_200_is_named() {
    let port = stand_in(After::Reset);
    let (code, err, _) = ssh_direct(port, &scratch("reset"));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains(&format!("the proxy 127.0.0.1:{port} {CAUSE}")), "{err}");
    assert!(err.contains("Without --direct, the relay carries SSH over HTTPS"), "{err}");
}

#[test]
fn a_proxy_silent_after_its_200_is_named_within_the_connect_timeout() {
    let port = stand_in(After::Silent);
    let (code, err, took) = ssh_direct(port, &scratch("silent"));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains(CAUSE), "{err}");
    assert!(took < Duration::from_secs(12), "{took:?}: {err}");
}

#[test]
fn a_proxy_that_carries_the_server_banner_is_not_blamed() {
    let port = stand_in(After::Banner);
    let (code, err, _) = ssh_direct(port, &scratch("banner"));
    assert_eq!(code, Some(255), "{err}");
    assert!(!err.contains(CAUSE), "the banner came, and the proxy was blamed: {err}");
}
