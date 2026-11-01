//! `--detach` and `-f` (T-380) as processes, against the test's SSH server:
//! the parent returns once the child's forward works, the child is in a
//! session of its own and outlives a kill of the parent's group, the
//! caller's pipes (an extra descriptor too) end when the parent does, and a
//! failure before ready is the parent's code.
#![cfg(unix)]

mod cleanup;
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
