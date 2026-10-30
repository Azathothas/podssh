//! `podssh session` as processes (T-186), against the test's SSH server on
//! the loopback, which gives a user named `pty-...` a pty and echoes the
//! input of `cat`: `start` returns once the session is ready, with its
//! socket (mode 0600 in a directory of mode 0700 on Unix); `send` types,
//! `wait` returns at 1 s of quiet, at a text, or with 75 at its limit;
//! `capture` reads the screen and the raw bytes; `list` names the session;
//! `stop` ends it and its socket goes. A session whose command ended says
//! its status, and its screen is still read. The refusals come before
//! anything listens: 64, and 78 with `PODSSH_LISTEN=no` or no cache; a
//! login that fails is start's 255, and leaves no socket. Against OpenSSH
//! and Dropbear, and a client of another user, it runs in the gate
//! (`scripts/interop-session.sh`).

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(60);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-session-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// podssh with a clean environment, its cache, and so the sockets, in
/// `home`, and a pty of 80 by 24.
fn podssh(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", "none")
        .env("PODSSH_CACHE_DIR", home.join("cache"))
        .env("COLUMNS", "80")
        .env("LINES", "24");
    for name in [
        "PODSSH_OFFLINE",
        "PODSSH_LISTEN",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "SSH_AUTH_SOCK",
        "SSH_ASKPASS",
    ] {
        cmd.env_remove(name);
    }
    cmd
}

/// Run to the end, within the limit.
fn ran(mut cmd: Command) -> Output {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

/// `podssh session ARGS...`: its exit code, stdout and stderr.
fn session(home: &Path, args: &[&str]) -> (i32, String, String) {
    let mut all = vec!["session"];
    all.extend_from_slice(args);
    let out = ran(podssh(home, &all));
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// A session that is stopped when the test ends, also when it fails.
struct Stopped<'a>(&'a Path, &'a str);

impl Drop for Stopped<'_> {
    fn drop(&mut self) {
        let mut cmd = podssh(self.0, &["session", "stop", self.1]);
        let _ = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

/// The test's server on a runtime of its own, and a port where nothing
/// listens.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16, u16) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    (runtime, port, closed)
}

/// `start NAME` to `destination`, on the loopback, a new host key taken.
fn start(home: &Path, name: &str, destination: &str, command: &str) -> (i32, String, String) {
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let accept = "StrictHostKeyChecking=accept-new";
    session(home, &["start", name, "--direct", "-o", known.as_str(), "-o", accept, destination, command])
}

/// Wait until `path` is gone, a few seconds at most: the daemon removes its
/// socket as it ends, after its answer.
fn gone(path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while path.exists() {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

#[test]
fn a_session_holds_its_pty_between_the_calls() {
    let home = scratch("calls");
    let (_runtime, port, _) = server(&home);
    let destination = format!("pty-u@127.0.0.1:{port}");
    let (code, out, err) = start(&home, "w", &destination, "cat");
    assert_eq!(code, 0, "{err}");
    let _stopped = Stopped(&home, "w");
    let socket = PathBuf::from(out.trim());
    assert!(socket.ends_with("w.sock") && socket.starts_with(home.join("cache")), "{out}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&socket), 0o600, "the socket");
        assert_eq!(mode(socket.parent().unwrap()), 0o700, "its directory");
    }

    // The Prove's run: a line typed, 1 s of quiet, and the screen holds it.
    assert_eq!(session(&home, &["send", "w", "echo hi"]).0, 0);
    let (code, out, err) = session(&home, &["wait", "w", "--idle", "1s"]);
    assert_eq!((code, out.as_str()), (0, "idle\n"), "{err}");
    let (code, screen, err) = session(&home, &["capture", "w"]);
    assert_eq!(code, 0, "{err}");
    assert!(screen.lines().next().is_some_and(|row| row.contains("echo hi")), "{screen:?}");
    let raw = ran(podssh(&home, &["session", "capture", "--raw", "w"]));
    assert!(raw.stdout.windows(8).any(|w| w == b"echo hi\r"), "{:?}", String::from_utf8_lossy(&raw.stdout));

    // A text in what came after the send; and a limit that passes first.
    assert_eq!(session(&home, &["send", "w", "printf done-marker"]).0, 0);
    let (code, out, err) = session(&home, &["wait", "w", "--match", "done-marker", "--timeout", "20s"]);
    assert_eq!((code, out.as_str()), (0, "match\n"), "{err}");
    let (code, _, err) = session(&home, &["wait", "w", "--match", "never-there", "--timeout", "1s"]);
    assert_eq!(code, 75, "{err}");

    let (code, out, err) = session(&home, &["list"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, format!("w\trunning\t{destination}\n"));
    // A second start of the name is refused, and the first runs on.
    let (code, _, err) = start(&home, "w", &destination, "cat");
    assert_eq!(code, 69, "{err}");
    assert!(err.contains("is there already"), "{err}");

    let (code, _, err) = session(&home, &["stop", "w"]);
    assert_eq!(code, 0, "{err}");
    assert!(gone(&socket), "the socket stayed after stop");
    let (code, _, err) = session(&home, &["send", "w", "echo late"]);
    assert_eq!(code, 69, "{err}");
}

#[test]
fn a_session_whose_command_ended_says_its_status_and_keeps_its_screen() {
    let home = scratch("ended");
    let (_runtime, port, _) = server(&home);
    let destination = format!("pty-u@127.0.0.1:{port}");
    // `exit 3` writes out and err!, then exits 3.
    let (code, _, err) = start(&home, "e", &destination, "exit 3");
    assert_eq!(code, 0, "{err}");
    let _stopped = Stopped(&home, "e");
    let (code, _, err) = session(&home, &["wait", "e", "--idle", "1s"]);
    assert_eq!(code, 69, "{err}");
    assert!(err.contains("status 3"), "{err}");
    let (code, screen, err) = session(&home, &["capture", "e"]);
    assert_eq!(code, 0, "{err}");
    assert!(screen.contains("out") && screen.contains("err!"), "{screen:?}");
    let (_, out, _) = session(&home, &["list"]);
    assert_eq!(out, format!("e\tended 3\t{destination}\n"));
    let (code, _, err) = session(&home, &["send", "e", "echo late"]);
    assert_eq!(code, 69, "{err}");
}

#[test]
fn a_bad_command_line_or_no_listener_refuses_before_anything_listens() {
    let home = scratch("refused");
    let socket = home.join("cache").join("sessions").join("w.sock");
    for (args, code, says) in [
        (&["start", "w"][..], 64, "give the host"),
        (&["start", "w", "--match", "x", "h"][..], 64, "--match is for wait"),
        (&["wait", "w", "--idle", "nope"][..], 64, "--idle"),
        (&["send", "nosuch", "text"][..], 69, "no session nosuch"),
    ] {
        let (got, out, err) = session(&home, args);
        assert_eq!(got, code, "{args:?}: {err}");
        assert!(err.contains(says) && out.is_empty(), "{args:?}: {err}");
    }
    for sub in ["start", "serve"] {
        let mut cmd = podssh(&home, &["session", sub, "w", "--direct", "127.0.0.1"]);
        cmd.env("PODSSH_LISTEN", "no");
        let out = ran(cmd);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(78), "{sub}: {err}");
        assert!(err.contains("PODSSH_LISTEN=no"), "{sub}: {err}");
        assert!(!socket.exists(), "{sub}: a socket was made");
    }
    let mut cmd = podssh(&home, &["session", "start", "w", "--direct", "127.0.0.1"]);
    cmd.env("PODSSH_CACHE_DIR", "none");
    let out = ran(cmd);
    assert_eq!(out.status.code(), Some(78));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--socket"));
}

#[test]
fn a_start_that_cannot_connect_exits_255_and_leaves_no_socket() {
    let home = scratch("closed");
    let (_runtime, _, closed) = server(&home);
    let (code, out, err) = start(&home, "c", &format!("pty-u@127.0.0.1:{closed}"), "cat");
    assert_eq!(code, 255, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("podssh: "), "the session's podssh said why: {err}");
    assert!(!home.join("cache").join("sessions").join("c.sock").exists(), "a socket stayed");
    assert_eq!(session(&home, &["list"]).1, "");
}
