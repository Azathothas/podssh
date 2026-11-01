//! `--detach` on Windows (T-383), in a job of the test's own that kills its
//! processes when it closes, as Win32-OpenSSH's job of a session does:
//! where the job allows breakaway, the detached child leaves it and
//! outlives its close; where it does not, the parent says so, and the child
//! ends with the job. In a pseudo console, as a terminal's window runs it:
//! the child frees the console at ready, and outlives its close.
#![cfg(windows)]

mod conpty_harness;
mod win_job;

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use win_job::Job;

const LIMIT: Duration = Duration::from_secs(60);

/// A service on the loopback that greets each client.
fn target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            use std::io::Write;
            let _ = stream.write_all(b"target says hi\n");
        }
    });
    port
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// `podssh pipe --detach` in `job`, to the target: its exit code and
/// stderr, once it returned.
fn detached_in(job: &Job, home: &std::path::Path, listen: u16, to: u16) -> (Option<i32>, String) {
    let podssh = env!("CARGO_BIN_EXE_podssh");
    let mut cmd = Command::new("cmd");
    cmd.env("PODSSH_CACHE_DIR", home.join("cache"))
        .env("USERPROFILE", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_LISTEN"] {
        cmd.env_remove(name);
    }
    let line = format!("\"{podssh}\" pipe --detach tcp-listen:127.0.0.1:{listen} tcp:127.0.0.1:{to}");
    let mut child = job.run(cmd, &line);
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh pipe --detach did not return within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // The caller's stderr ends with the parent: a child that kept it open
    // would hold a caller that reads it to its end, as a CI's step does.
    let mut stderr = child.stderr.take().unwrap();
    let (sent, got) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut err = String::new();
        let _ = stderr.read_to_string(&mut err);
        let _ = sent.send(err);
    });
    let err = got
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| panic!("the caller's stderr did not end with the parent: the detached child kept it open"));
    (child.wait().unwrap().code(), err)
}

fn greeting(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let mut buf = [0u8; 15];
    stream.read_exact(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// The child's pid, from the parent's line, stopped when the test ends.
struct Stopped(Option<u32>);

impl Stopped {
    fn of(stderr: &str) -> Stopped {
        let pid = stderr
            .split("in the background, pid ")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next().and_then(|digits| digits.parse().ok()));
        Stopped(pid)
    }
}

impl Drop for Stopped {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-detach-win-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A job that allows breakaway: the detached child leaves it, and serves
/// after the job closed.
#[test]
fn the_child_leaves_a_job_that_allows_it_and_outlives_its_close() {
    let home = scratch("breakaway");
    let (to, listen) = (target(), free_port());
    let job = Job::new(true);
    let (code, err) = detached_in(&job, &home, listen, to);
    let _stopped = Stopped::of(&err);
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("in the background"), "{err}");
    assert!(!err.contains("allows no process to leave it"), "{err}");
    drop(job);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(greeting(listen).as_deref(), Some("target says hi\n"), "the child ended with the job: {err}");
    let _ = std::fs::remove_dir_all(&home);
}

/// In a pseudo console: the parent returns 0 there, and the child serves
/// after the console closed, as a terminal's window closes.
#[test]
fn a_console_closed_after_ready_leaves_the_child() {
    let home = scratch("console");
    let (to, listen) = (target(), free_port());
    let line =
        format!("\"{}\" pipe --detach tcp-listen:127.0.0.1:{listen} tcp:127.0.0.1:{to}", env!("CARGO_BIN_EXE_podssh"));
    let cache = home.join("cache");
    let changes = [
        ("PODSSH_CACHE_DIR", cache.to_str()),
        ("HTTPS_PROXY", None),
        ("https_proxy", None),
        ("ALL_PROXY", None),
        ("all_proxy", None),
        ("PODSSH_LISTEN", None),
    ];
    let console = conpty_harness::Console::start(&line, &changes, 24, 80);
    let code = console.wait(LIMIT);
    let text = console.text();
    let _stopped = Stopped::of(&text.split_whitespace().collect::<Vec<_>>().join(" "));
    assert_eq!(code, Some(0), "{text}");
    drop(console);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(greeting(listen).as_deref(), Some("target says hi\n"), "the child ended with the console: {text}");
    let _ = std::fs::remove_dir_all(&home);
}

/// A job that allows no breakaway: the parent says so, and the child ends
/// with the job.
#[test]
fn a_job_that_allows_no_breakaway_is_said_and_ends_the_child() {
    let home = scratch("kept");
    let (to, listen) = (target(), free_port());
    let job = Job::new(false);
    let (code, err) = detached_in(&job, &home, listen, to);
    let _stopped = Stopped::of(&err);
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("allows no process to leave it"), "{err}");
    drop(job);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(greeting(listen), None, "the child outlived a job that allows no breakaway: {err}");
    let _ = std::fs::remove_dir_all(&home);
}
