//! `--detach` and `-f` (T-380) as processes, against the test's SSH server:
//! the parent returns once the child's forward works, the child is in a
//! session of its own and outlives a kill of the parent's group, the
//! caller's pipes (an extra descriptor too) end when the parent does, and a
//! failure before ready is the parent's code.
#![cfg(unix)]

mod cleanup;
#[cfg(target_os = "linux")]
mod pty_harness;
mod ssh_harness;

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-detach-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The detached child, ended when the test ends.
struct Detached(i32);

impl Drop for Detached {
    fn drop(&mut self) {
        // SAFETY: a signal to the test's own child's pid.
        unsafe { libc::kill(self.0, libc::SIGKILL) };
    }
}

struct Setup {
    home: PathBuf,
    port: u16,
    target: SocketAddr,
    _runtime: tokio::runtime::Runtime,
}

fn setup(name: &str) -> Setup {
    let home = scratch(name);
    let key = home.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (port, _) = runtime.block_on(ssh_harness::start_counting(&key));
    let target = runtime.block_on(async {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"target says hi\n").await;
            }
        });
        at
    });
    Setup { home, port, target, _runtime: runtime }
}

impl Setup {
    fn podssh(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        let known = self.home.join("known_hosts");
        cmd.args(["ssh", "--direct", "-p", &self.port.to_string(), "-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=accept-new", "-o"])
            .arg(format!("UserKnownHostsFile={}", known.display()))
            .args(args)
            .arg("podtest@127.0.0.1")
            .env("HOME", &self.home)
            .env("PODSSH_CACHE_DIR", self.home.join("cache"))
            .env("PODSSH_SSH_CONFIG", "none")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
            cmd.env_remove(name);
        }
        cmd
    }

    /// `podssh detached WORDS`, with the cache of the runs of [`Setup::podssh`].
    fn detached(&self, words: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.arg("detached")
            .args(words)
            .env("HOME", &self.home)
            .env("PODSSH_CACHE_DIR", self.home.join("cache"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn ran(mut cmd: Command) -> Output {
    let mut child = cmd.spawn().unwrap();
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

/// The child's pid from the parent's line.
fn pid_of(stderr: &str) -> i32 {
    let at = stderr.find("in the background, pid ").unwrap_or_else(|| panic!("no line of the background: {stderr}"));
    let rest = &stderr[at + "in the background, pid ".len()..];
    rest.split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 checks for the process, and sends nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// The session of `pid`, as POSIX's `getsid` gives it on Linux and macOS.
fn session_of(pid: i32) -> i32 {
    // SAFETY: a read of a process's session id.
    unsafe { libc::getsid(pid) }
}

fn greeting(port: u16) -> String {
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream.set_read_timeout(Some(LIMIT)).unwrap();
            let mut buf = [0u8; 15];
            if stream.read_exact(&mut buf).is_ok() {
                return String::from_utf8_lossy(&buf).into_owned();
            }
        }
        assert!(Instant::now() < deadline, "the forward on {port} gave nothing within {LIMIT:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `-f -N -L`: the parent returns 0 with the child's pid and log, and the
/// forward works from the child.
#[test]
fn f_returns_once_the_forward_works_and_the_child_serves_it() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let s = setup("serves");
    let port = free_port();
    let forward = format!("{port}:{}", s.target);
    let out = ran(s.podssh(&["-f", "-N", "-L", &forward]));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let child = Detached(pid_of(&err));
    assert!(err.contains("its log ") && err.contains("detached"), "{err}");
    assert!(alive(child.0), "the child ended: {err}");
    assert_eq!(greeting(port), "target says hi\n");
}

/// The child is in a session of its own, and a kill of the parent's group
/// after ready leaves it.
#[test]
fn the_child_leaves_the_session_and_outlives_the_parent_s_group() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let s = setup("group");
    let port = free_port();
    let forward = format!("{port}:{}", s.target);
    let mut cmd = s.podssh(&["--detach", "-N", "-L", &forward]);
    cmd.process_group(0);
    let mut parent = cmd.spawn().unwrap();
    let group = parent.id() as i32;
    let mut err = String::new();
    parent.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    assert!(parent.wait().unwrap().success(), "{err}");
    let child = Detached(pid_of(&err));
    assert_ne!(session_of(child.0), session_of(std::process::id() as i32), "the child kept the caller's session");
    assert_eq!(session_of(child.0), child.0, "the child leads no session of its own");
    // SAFETY: a signal to the group that the test made for the parent.
    unsafe { libc::kill(-group, libc::SIGKILL) };
    std::thread::sleep(Duration::from_millis(300));
    assert!(alive(child.0), "a kill of the parent's group ended the child");
    assert_eq!(greeting(port), "target says hi\n");
}

/// The caller's stdout, stderr and an extra descriptor end once the parent
/// exits: the child holds none of them.
#[test]
fn the_caller_s_pipes_end_with_the_parent() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let s = setup("pipes");
    let port = free_port();
    let forward = format!("{port}:{}", s.target);
    let mut fds = [0i32; 2];
    // SAFETY: a pipe of the test, its descriptors closed below.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (extra_read, extra_write) = (fds[0], fds[1]);
    let mut cmd = s.podssh(&["-f", "-N", "-L", &forward]);
    // SAFETY: dup2 in the child before exec, of a descriptor that it has.
    unsafe {
        cmd.pre_exec(move || {
            libc::dup2(extra_write, 5);
            Ok(())
        });
    }
    let started = Instant::now();
    let out = ran(cmd);
    // SAFETY: the test's own descriptor.
    unsafe { libc::close(extra_write) };
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let child = Detached(pid_of(&err));
    // The extra pipe sees its end at once: neither process holds it now.
    let mut extra = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(extra_read) };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = tx.send(extra.read_to_end(&mut sink).map(|_| sink.len()));
    });
    let ended = rx.recv_timeout(Duration::from_secs(2));
    assert!(matches!(ended, Ok(Ok(0))), "the extra descriptor stayed open in the child: {ended:?}");
    assert!(alive(child.0));
    assert!(started.elapsed() < LIMIT);
}

/// A connection that fails before ready is the parent's 255, with the
/// child's lines on the caller's stderr; `-f` with neither a command nor
/// `-N` refuses, as OpenSSH's.
#[test]
fn a_failure_before_ready_is_the_parent_s_code_and_f_needs_work() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let mut s = setup("fails");
    s.port = free_port();
    let out = ran(s.podssh(&["-f", "-N"]));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert!(!err.contains("in the background"), "{err}");
    let out = ran(s.podssh(&["-f"]));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(64), "{err}");
    assert!(err.contains("with a command or -N"), "{err}");
}

/// `-f` asks a password on the terminal before it goes to the background,
/// as OpenSSH's does after its login: the child keeps the caller's terminal
/// until it is ready.
#[cfg(target_os = "linux")]
#[test]
fn f_asks_a_password_on_the_terminal_before_it_detaches() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let s = setup("prompt");
    let port = free_port();
    let forward = format!("{port}:{}", s.target);
    let known = format!("UserKnownHostsFile={}", s.home.join("known_hosts").display());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &s.port.to_string(), "-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(&known)
        .args(["-f", "-N", "-L", &forward, "pass-u@127.0.0.1"])
        .env("HOME", &s.home)
        .env("PODSSH_CACHE_DIR", s.home.join("cache"))
        .env("PODSSH_SSH_CONFIG", "none");
    for name in
        ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "SSH_ASKPASS"]
    {
        cmd.env_remove(name);
    }
    // The pty is the caller's controlling terminal, as a terminal's window
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
    assert!(pty.expect("password:", LIMIT), "no prompt on the terminal: {}", pty.text());
    pty.send(format!("{}\r", ssh_harness::pass::PASSWORD).as_bytes());
    assert_eq!(pty.wait(LIMIT), Some(0), "{}", pty.text());
    let child = Detached(pid_of(&pty.text()));
    assert!(alive(child.0));
    assert_eq!(greeting(port), "target says hi\n");
}

/// The directory of the runs, from the parent's line that names the log.
fn runs_dir(stderr: &str) -> PathBuf {
    let log = stderr.split("its log ").nth(1).and_then(|rest| rest.lines().next()).expect("the log is named");
    PathBuf::from(log.trim()).parent().expect("the log's directory").to_path_buf()
}

/// Wait until `pid` is gone, within `LIMIT`.
fn gone(pid: i32) {
    let deadline = Instant::now() + LIMIT;
    while alive(pid) {
        assert!(Instant::now() < deadline, "pid {pid} is still there");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A name runs once (T-392): a second start of it refuses with 75 and names
/// the pid that runs, before it connects; two runs with no name both start,
/// each under its verb and its pid; once the first is stopped, its name
/// starts again.
#[test]
fn a_second_start_of_a_name_refuses_while_the_first_runs() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let s = setup("named");
    let forward = |port: u16| format!("{port}:{}", s.target);
    let out = ran(s.podssh(&["-f", "-N", "--detach-name", "web", "-L", &forward(free_port())]));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let first = Detached(pid_of(&err));
    assert!(err.contains("named web"), "{err}");
    let out = ran(s.podssh(&["-f", "-N", "--detach-name", "web", "-L", &forward(free_port())]));
    let again = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(75), "{again}");
    assert!(again.contains(&format!("pid {}", first.0)) && again.contains("runs already"), "{again}");
    assert!(!again.contains("in the background"), "{again}");
    assert!(alive(first.0), "the refused start touched the first run");
    let mut unnamed = Vec::new();
    for _ in 0..2 {
        let out = ran(s.podssh(&["-f", "-N", "-L", &forward(free_port())]));
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(0), "a run with no name was refused: {err}");
        let pid = pid_of(&err);
        assert!(err.contains(&format!("named ssh-{pid}")), "{err}");
        unnamed.push(Detached(pid));
    }
    let out = ran(s.detached(&["stop", "web"]));
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    gone(first.0);
    std::mem::forget(first);
    let out = ran(s.podssh(&["-f", "-N", "--detach-name", "web", "-L", &forward(free_port())]));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "the name stayed taken after its stop: {err}");
    let _second = Detached(pid_of(&err));
}

/// `podssh detached` reads the lock, never a pid alone (T-392): a run says
/// its pid and stops; a record whose pid lives but holds no lock (here, the
/// test's own pid, as a reused pid would) reads as ended, and its stop sends
/// no signal, or this test would end.
#[test]
fn status_and_stop_read_the_lock_not_the_pid() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let s = setup("status");
    let forward = format!("{}:{}", free_port(), s.target);
    let out = ran(s.podssh(&["-f", "-N", "--detach-name", "web", "-L", &forward]));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let child = Detached(pid_of(&err));
    let out = ran(s.detached(&["status", "web"]));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "{text}{}", String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("state: running") && text.contains(&format!("pid: {}", child.0)), "{text}");
    assert!(text.contains("verb: ssh") && text.contains("--detach-name web"), "{text}");
    let out = ran(s.detached(&["list"]));
    let list = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(list.lines().any(|l| l.starts_with(&format!("web\trunning\t{}\t", child.0))), "{list}");
    let dir = runs_dir(&err);
    let me = std::process::id();
    std::fs::write(dir.join("ghost.json"), format!("{{\"name\":\"ghost\",\"verb\":\"ssh\",\"pid\":{me}}}\n")).unwrap();
    std::fs::write(dir.join("ghost.lock"), format!("{me}\n")).unwrap();
    let out = ran(s.detached(&["status", "ghost"]));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(69), "{text}");
    assert!(text.contains("state: ended"), "{text}");
    let out = ran(s.detached(&["stop", "ghost"]));
    assert_eq!(out.status.code(), Some(69), "{}", String::from_utf8_lossy(&out.stderr));
    let out = ran(s.detached(&["stop", "web"]));
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    gone(child.0);
    std::mem::forget(child);
    let out = ran(s.detached(&["status", "web"]));
    assert_eq!(out.status.code(), Some(69));
    assert!(String::from_utf8_lossy(&out.stdout).contains("state: ended"));
}
