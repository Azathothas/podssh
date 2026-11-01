//! `podssh node --detach` (T-380) through the stand-in relay's reverse road
//! on the loopback: the parent returns 0 once the node is online, with the
//! child's pid, and a client then logs in through the node that runs in the
//! background. The check says that it did not run when this host has no
//! Python or no openssl for the stand-in.
#![cfg(unix)]

mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;

use throughput_harness::{Cell, Session};

/// The parent's run to its end, within a minute: a node that never says
/// that it is ready must fail the test, not hold it.
fn within(cmd: &mut std::process::Command) -> std::process::Output {
    let mut child = cmd.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("the parent of --detach did not return within 60 s");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn a_detached_node_returns_once_online_and_serves_in_the_background() {
    let session = Session::start("detach");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[String]| session.stand_in(args, &ca);
    let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay];
    args.extend(pins.iter().cloned());
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port), "--detach".into()];
    args.extend(pins.iter().cloned());
    let out = within(command(&args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let online = err.find("online").expect("the node said online before the parent returned");
    let background = err.find("in the background, pid ").expect("the parent names the child");
    assert!(online < background, "{err}");
    let pid: i32 = err[background + "in the background, pid ".len()..]
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    struct Ends(i32);
    impl Drop for Ends {
        fn drop(&mut self) {
            // SAFETY: a signal to the test's own detached node.
            unsafe { libc::kill(self.0, libc::SIGTERM) };
        }
    }
    let _node = Ends(pid);
    let mut args = vec!["ssh".to_string(), "-v".into()];
    args.extend(session.common());
    args.extend(pins);
    args.extend(["node://tester@lab".to_string(), "greet".into()]);
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(text, ssh_harness::GREETING);
}

/// Where a node's stderr goes when its every write fails: a pipe whose
/// reader is closed (EPIPE, as a journal that went away), and on Linux
/// `/dev/full` (ENOSPC, as a full disk).
fn failing_sinks() -> Vec<(&'static str, Stdio)> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [0; 2];
    // SAFETY: pipe() fills two descriptors that this test then owns.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: each descriptor is open and owned by nothing else.
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    drop(reader);
    let mut sinks = vec![("a pipe whose reader is closed", Stdio::from(writer))];
    if let Ok(full) = std::fs::OpenOptions::new().write(true).open("/dev/full") {
        sinks.push(("/dev/full", Stdio::from(full)));
    }
    sinks
}

/// A node whose every line fails to write goes on serving (T-389): a failed
/// write of `eprintln!` panics, and the release build aborts on a panic, so
/// such a node ended at its first line ("online").
#[test]
fn a_node_whose_stderr_fails_goes_on_serving() {
    let session = Session::start("stderr");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[String]| session.stand_in(args, &ca);
    let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay];
    args.extend(pins.iter().cloned());
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let mut login = vec!["ssh".to_string()];
    login.extend(session.common());
    login.extend(pins.iter().cloned());
    login.extend(["node://tester@lab".to_string(), "greet".into()]);
    for (sink_name, sink) in failing_sinks() {
        let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port)];
        args.extend(pins.iter().cloned());
        let mut node = command(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(sink).spawn().unwrap();
        struct Kill<'a>(&'a mut std::process::Child);
        impl Drop for Kill<'_> {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let node = Kill(&mut node);
        // Two logins: the first once the node is online, the second after
        // the lines of the first session.
        for nth in 1..=2 {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
            loop {
                if let Some(status) = node.0.try_wait().unwrap() {
                    panic!("with stderr on {sink_name}, the node ended before login {nth}: {status:?}");
                }
                let out = command(&login).stdin(Stdio::null()).output().unwrap();
                if out.status.code() == Some(0) {
                    assert_eq!(String::from_utf8_lossy(&out.stdout), ssh_harness::GREETING);
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "with stderr on {sink_name}, login {nth} did not pass within 40 s: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
        assert!(node.0.try_wait().unwrap().is_none(), "with stderr on {sink_name}, the node ended after two logins");
    }
}

/// Whether a process of this pid lives (a zombie counts until it is reaped).
fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 checks for the process and sends nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// The number after `word` in `text`.
fn number_after(text: &str, word: &str) -> Option<i32> {
    let at = text.find(word)? + word.len();
    text[at..].split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

/// `--detach --restart` (T-390): a supervisor in the background starts the
/// node again after a kill, and a client logs in through the new node; a
/// SIGTERM to the supervisor ends both.
#[test]
fn a_restarted_node_comes_back_after_a_kill() {
    let session = Session::start("restart");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[String]| session.stand_in(args, &ca);
    let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay];
    args.extend(pins.iter().cloned());
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port)];
    args.extend(["--detach".into(), "--restart".into()]);
    args.extend(pins.iter().cloned());
    let out = within(command(&args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let supervisor = number_after(&err, "in the background, pid ").expect("the parent names the supervisor");
    let first = number_after(&err, "which restarts the run of pid ").expect("and the run");
    let log = err.split("its log ").nth(1).map(|l| l.lines().next().unwrap_or("").trim().to_string());
    struct Ends(Vec<i32>);
    impl Drop for Ends {
        fn drop(&mut self) {
            for pid in &self.0 {
                // SAFETY: a signal to the test's own detached processes.
                unsafe { libc::kill(*pid, libc::SIGKILL) };
            }
        }
    }
    let mut ends = Ends(vec![supervisor, first]);
    let mut login = vec!["ssh".to_string()];
    login.extend(session.common());
    login.extend(pins.iter().cloned());
    login.extend(["node://tester@lab".to_string(), "greet".into()]);
    let logs_in = |within: std::time::Duration| {
        let deadline = std::time::Instant::now() + within;
        loop {
            let out = command(&login).stdin(Stdio::null()).output().unwrap();
            if out.status.code() == Some(0) && String::from_utf8_lossy(&out.stdout) == ssh_harness::GREETING {
                return;
            }
            assert!(std::time::Instant::now() < deadline, "no login: {}", String::from_utf8_lossy(&out.stderr));
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    };
    logs_in(std::time::Duration::from_secs(20));
    // SAFETY: a signal to the test's own detached node.
    unsafe { libc::kill(first, libc::SIGKILL) };
    logs_in(std::time::Duration::from_secs(60));
    assert!(alive(supervisor), "the supervisor goes on");
    let text = log.as_deref().and_then(|l| std::fs::read_to_string(l).ok()).unwrap_or_default();
    let second = number_after(&text, "run 2 started, pid ").expect("the log names the new run");
    ends.0.push(second);
    assert!(text.contains("the run ended (signal 9)"), "{text}");
    // A stop of the supervisor ends the run too.
    // SAFETY: as above.
    unsafe { libc::kill(supervisor, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while alive(second) || alive(supervisor) {
        assert!(std::time::Instant::now() < deadline, "a stopped supervisor ends its run within 20 s");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// A supervisor that dies leaves its run serving: no PDEATHSIG, so the
/// supervisor is never one more way to lose the tunnel (T-390).
#[test]
fn a_killed_supervisor_leaves_its_node_serving() {
    let session = Session::start("orphan");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[String]| session.stand_in(args, &ca);
    let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay];
    args.extend(pins.iter().cloned());
    assert!(command(&args).stdin(Stdio::null()).output().unwrap().status.success());
    let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port)];
    args.extend(["--detach".into(), "--restart".into()]);
    args.extend(pins.iter().cloned());
    let out = within(command(&args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let supervisor = number_after(&err, "in the background, pid ").unwrap();
    let run = number_after(&err, "which restarts the run of pid ").unwrap();
    struct Ends([i32; 2]);
    impl Drop for Ends {
        fn drop(&mut self) {
            for pid in self.0 {
                // SAFETY: a signal to the test's own detached processes.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }
    let _ends = Ends([supervisor, run]);
    // SAFETY: as above.
    unsafe { libc::kill(supervisor, libc::SIGKILL) };
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(alive(run), "the run outlives its supervisor");
    let mut login = vec!["ssh".to_string()];
    login.extend(session.common());
    login.extend(pins.iter().cloned());
    login.extend(["node://tester@lab".to_string(), "greet".into()]);
    let out = command(&login).stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
}

/// A node that the relay closes for a fault of its bytes (1003) connects
/// again and serves (T-409): it ended for good before, and a server that
/// only it reached was locked out.
#[test]
fn a_node_closed_for_a_fault_comes_back() {
    let session = Session::start("fault");
    let cell = match Cell::fake_relay_mode(&session, "fault1003", "the stand-in relay, a fault at the first socket") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[String]| session.stand_in(args, &ca);
    let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay];
    args.extend(pins.iter().cloned());
    assert!(command(&args).stdin(Stdio::null()).output().unwrap().status.success());
    let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port)];
    args.extend(pins.iter().cloned());
    let mut node = command(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let err = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    {
        let (err, mut from) = (err.clone(), node.stderr.take().unwrap());
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = [0u8; 4096];
            while let Ok(n) = from.read(&mut buf) {
                if n == 0 {
                    break;
                }
                err.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
    }
    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut node = Kill(node);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !err.lock().unwrap().contains("online again") {
        if let Some(status) = node.0.try_wait().unwrap() {
            panic!("the node ended after the fault: {status:?}: {}", err.lock().unwrap());
        }
        assert!(std::time::Instant::now() < deadline, "not online again: {}", err.lock().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(err.lock().unwrap().contains("1003 unknown session id; connecting again"), "{}", err.lock().unwrap());
    let mut login = vec!["ssh".to_string()];
    login.extend(session.common());
    login.extend(pins.iter().cloned());
    login.extend(["node://tester@lab".to_string(), "greet".into()]);
    let out = command(&login).stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn restart_without_detach_is_a_usage_error() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["node", "lab", "127.0.0.1:22", "--restart"])
        .env("PODSSH_CACHE_DIR", "none")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("give --detach too"));
}
