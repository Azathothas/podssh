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
#[cfg(windows)]
mod conpty_harness;
#[cfg(target_os = "linux")]
mod pty_harness;
mod ssh_harness;
#[cfg(windows)]
mod win_job;

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
    cmd.args(args);
    clean(&mut cmd, home);
    cmd
}

/// The environment of [`podssh`], on another command that starts podssh.
fn clean(cmd: &mut Command, home: &Path) {
    cmd.current_dir(home)
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

/// T-382: a login that asks a password on the terminal starts a session:
/// the child keeps the starter's terminal until it is ready, and leaves its
/// session then, so a hangup of that terminal reaches it no more.
#[cfg(target_os = "linux")]
#[test]
fn start_asks_a_password_on_the_terminal_then_leaves_it() {
    use std::os::unix::process::CommandExt;
    let home = scratch("prompt");
    let (_runtime, port, _) = server(&home);
    let destination = format!("pass-pty-u@127.0.0.1:{port}");
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let accept = "StrictHostKeyChecking=accept-new";
    let mut cmd =
        podssh(&home, &["session", "start", "p", "--direct", "-o", &known, "-o", accept, &destination, "cat"]);
    // The pty is the starter's controlling terminal, as a terminal's window
    // makes it.
    // SAFETY: setsid and an ioctl on stdin, both async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::ioctl(0, libc::TIOCSCTTY, 0);
            Ok(())
        });
    }
    let mut pty = pty_harness::Pty::start(cmd, 24, 80);
    let _stopped = Stopped(&home, "p");
    assert!(pty.expect("password:", LIMIT), "no prompt on the terminal: {}", pty.text());
    pty.send(format!("{}\r", ssh_harness::pass::PASSWORD).as_bytes());
    assert_eq!(pty.wait(LIMIT), Some(0), "{}", pty.text());
    let (code, out, err) = session(&home, &["list"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains('p'), "{out}");
    // The daemon left the starter's session: its own session now.
    let pid = daemon_pid(&home, "p");
    // SAFETY: reads of session ids.
    let (daemon, starter) = unsafe { (libc::getsid(pid), libc::getsid(0)) };
    assert_eq!(daemon, pid, "the daemon leads no session of its own");
    assert_ne!(daemon, starter);
}

/// The pid of the podssh that serves session `name`, from the processes'
/// command lines.
#[cfg(target_os = "linux")]
fn daemon_pid(home: &Path, name: &str) -> i32 {
    let want = home.join("cache").display().to_string();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else { continue };
        let words: Vec<String> = cmdline.split(|b| *b == 0).map(|w| String::from_utf8_lossy(w).into_owned()).collect();
        let serving = words.iter().any(|w| w == "serve") && words.iter().any(|w| w == name);
        let ours = std::fs::read(format!("/proc/{pid}/environ"))
            .map(|e| String::from_utf8_lossy(&e).contains(&want))
            .unwrap_or(false);
        if serving && ours {
            return pid;
        }
    }
    panic!("no daemon of {name}");
}

/// T-383: on Windows, `start` in a job of Win32-OpenSSH's kind (it kills its
/// processes when it closes): where the job allows breakaway, the session's
/// podssh leaves it and serves after the job closed; where it does not,
/// `start` says so, and the session ends with the job.
#[cfg(windows)]
#[test]
fn on_windows_the_session_leaves_a_job_that_allows_it() {
    for breakaway in [true, false] {
        let home = scratch(if breakaway { "job-out" } else { "job-in" });
        let (_runtime, port, _) = server(&home);
        let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
        let line = format!(
            "\"{}\" session start j --direct -o \"{known}\" -o StrictHostKeyChecking=accept-new pty-u@127.0.0.1:{port} cat",
            env!("CARGO_BIN_EXE_podssh")
        );
        let mut cmd = Command::new("cmd");
        clean(&mut cmd, &home);
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let job = win_job::Job::new(breakaway);
        let mut child = job.run(cmd, &line);
        let _stopped = Stopped(&home, "j");
        let deadline = Instant::now() + LIMIT;
        // Its few lines fit in the pipes: they are read once it ended.
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("session start did not return within {LIMIT:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(0), "{err}");
        assert_eq!(err.contains("allows no process to leave it"), !breakaway, "{err}");
        drop(job);
        std::thread::sleep(Duration::from_millis(500));
        let (code, _, said) = session(&home, &["capture", "j"]);
        if breakaway {
            assert_eq!(code, 0, "the session ended with the job: {said}");
        } else {
            assert_ne!(code, 0, "the session outlived a job that allows no breakaway");
        }
    }
}

/// T-383, as T-382 on Linux: in a pseudo console, `start` asks a password
/// there, as the session's podssh shares the console until it is ready; it
/// frees the console then, and the session outlives the console's close.
#[cfg(windows)]
#[test]
fn on_windows_start_asks_a_password_in_the_console_then_frees_it() {
    let home = scratch("console");
    let (_runtime, port, _) = server(&home);
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let line = format!(
        "\"{}\" session start c --direct -o \"{known}\" -o StrictHostKeyChecking=accept-new pass-pty-u@127.0.0.1:{port} cat",
        env!("CARGO_BIN_EXE_podssh")
    );
    let (home_text, cache) = (home.display().to_string(), home.join("cache").display().to_string());
    let changes = [
        ("HOME", Some(home_text.as_str())),
        ("USERPROFILE", Some(home_text.as_str())),
        ("PODSSH_SSH_CONFIG", Some("none")),
        ("PODSSH_SETTINGS", Some("none")),
        ("PODSSH_CACHE_DIR", Some(cache.as_str())),
        ("PODSSH_OFFLINE", None),
        ("PODSSH_LISTEN", None),
        ("HTTPS_PROXY", None),
        ("https_proxy", None),
        ("ALL_PROXY", None),
        ("all_proxy", None),
        ("SSH_AUTH_SOCK", None),
        ("SSH_ASKPASS", None),
    ];
    let mut console = conpty_harness::Console::start(&line, &changes, 24, 80);
    let _stopped = Stopped(&home, "c");
    assert!(console.expect("password:", LIMIT), "no prompt in the console: {}", console.text());
    console.send(format!("{}\r", ssh_harness::pass::PASSWORD).as_bytes());
    assert_eq!(console.wait(LIMIT), Some(0), "{}", console.text());
    drop(console);
    std::thread::sleep(Duration::from_millis(500));
    let (code, _, err) = session(&home, &["capture", "c"]);
    assert_eq!(code, 0, "the session ended with the console: {err}");
}
