//! The ends of a session while podssh waits on the channel's window (T-269):
//! the far end takes no more input, so a send waits, and then the command
//! exits (`quit`, as `head` or `true` with a large file on stdin) or the
//! connection ends with no word (`hold`). podssh must give the command's
//! status, or 255. russh wakes a send that waits when a channel or a direct
//! connection ends, so these pass with or without the change of T-269; the
//! hang that it repairs came through the relay's pipe, where the control of
//! T-156 for a stopped relay host finds it (`tests/m6_exit.rs`).

mod ssh_harness;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `podssh ARGS` with HOME under `home`, and none of the machine's settings.
fn podssh(home: &std::path::Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args);
    // The ssh_config of the machine that runs the test must not change it.
    cmd.env("PODSSH_SSH_CONFIG", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_TIMEOUT", "SSH_AUTH_SOCK", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// `podssh ssh --direct` to `COMMAND` on the tests' server, with more input
/// than it takes: the exit code, and stderr.
fn send_to(command: &str) -> (Option<i32>, String) {
    let home = std::env::temp_dir().join(format!("podssh-window-{command}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let key = home.join("host_key").to_string_lossy().into_owned();
    let made = podssh(&home, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &key]).stdin(Stdio::null()).status();
    assert!(made.expect("podssh keygen runs").success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(std::path::Path::new(&key))).to_string();
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let args = ["ssh", "--direct", "-p", &port, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"];
    let mut child = podssh(&home, &args)
        .args(["-o", &known, "tester@127.0.0.1", command])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh ssh runs");
    let mut stdin = child.stdin.take().unwrap();
    std::thread::spawn(move || {
        let block = vec![7u8; 64 * 1024];
        while stdin.write_all(&block).is_ok() {}
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("podssh still waits on the window of a channel that ended ({command})");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut err = String::new();
    let _ = std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err);
    drop(runtime);
    let _ = std::fs::remove_dir_all(&home);
    (code, err)
}

/// The command exits with no more of its input read, and closes its
/// channel; the connection stays.
#[test]
fn a_command_that_exits_while_the_window_is_spent_gives_its_status() {
    let (code, err) = send_to("quit");
    assert_eq!(code, Some(3), "{err}");
}

/// The connection ends with no word while the window is spent.
#[test]
fn a_connection_that_ends_while_the_window_is_spent_ends_the_session() {
    let (code, err) = send_to("hold");
    assert_eq!(code, Some(255), "{err}");
}
