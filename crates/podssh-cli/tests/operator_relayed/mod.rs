//! The tests of `podssh operator` through the stand-in relay of the reverse
//! road (Python and openssl), apart from `operator.rs` for its length: a
//! TARGET that counts its connections, an operator that its parent hangs up
//! (T-586), and an operator of `--no-resume` whose link is lost (T-612).
//! The tests themselves are in `operator.rs`, which runs these.

/// The TARGET of a node of the tests through the stand-in relay, which
/// counts its connections.
pub(crate) mod target {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// The line that the target writes to each connection.
    pub(crate) const TARGET_LINE: &[u8] = b"the target's last line\n";

    /// A TCP service that writes [`TARGET_LINE`] to each connection, then
    /// reads it to its end, a minute at most: its port, the connections that
    /// it took, and those that ended.
    pub(crate) struct Target {
        pub(crate) port: u16,
        pub(crate) opened: Arc<AtomicUsize>,
        pub(crate) closed: Arc<AtomicUsize>,
    }

    pub(crate) fn target() -> Target {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (opened, closed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (took, ended) = (opened.clone(), closed.clone());
        std::thread::spawn(move || {
            for mut stream in listener.incoming().map_while(Result::ok) {
                took.fetch_add(1, Ordering::SeqCst);
                let ended = ended.clone();
                std::thread::spawn(move || {
                    let _ = stream.write_all(TARGET_LINE);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
                    let mut buf = [0u8; 1024];
                    while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
                    ended.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        Target { port, opened, closed }
    }
}

#[cfg(unix)]
pub(crate) mod hung_up {
    use std::io::Read;
    use std::process::Stdio;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::target::{target, TARGET_LINE};
    use crate::throughput_harness::{lines_of, wait_for, Cell, Session};

    /// The bound on each wait for the operator: its bytes, its exit.
    const LIMIT: Duration = Duration::from_secs(60);
    /// How soon the node lets the target go after the signal.
    const LET_GO: Duration = Duration::from_secs(3);

    pub(crate) fn run() {
        let s = Session::start("op-hangup");
        let target = target();
        let cell = match Cell::fake_relay_mode(&s, "normal", "the stand-in relay") {
            Ok(cell) => cell,
            Err((_, why)) => {
                eprintln!("did not run: {why}");
                return;
            }
        };
        let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
        let (relay, ca) = (at("--relay-host"), at("--ca-file"));
        let command = |args: &[&str]| {
            let words: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            // The pins go before the verb's own words.
            let mut cmd = s.stand_in(&words[..1], &ca);
            cmd.args(["--relay-addr", "relay-a.test=127.0.0.1"]).args(&words[1..]);
            cmd
        };
        let pairing = ["relay", "pair", "lab", "--relay-host", relay.as_str()];
        let out = command(&pairing).stdin(Stdio::null()).output().unwrap();
        assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
        let at_target = format!("127.0.0.1:{}", target.port);
        let mut node = command(&["node", "lab", at_target.as_str()]);
        let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let node_lines = lines_of(&mut node);
        s.keep(node);
        wait_for(&node_lines, "online").expect("the node is online");

        let mut operator = command(&["operator", "lab"]);
        // SIGHUP at its default, as under OpenSSH: a test run under nohup
        // would hand it on ignored.
        // SAFETY: signal(2) is async-signal-safe, as pre_exec asks.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut operator, || {
                libc::signal(libc::SIGHUP, libc::SIG_DFL);
                Ok(())
            });
        }
        let mut operator =
            operator.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        // Its stdin stays open: only the signal ends the session.
        let _stdin = operator.stdin.take().expect("stdin");
        let said = lines_of(&mut operator);
        let mut stdout = operator.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = vec![0u8; TARGET_LINE.len()];
            let _ = tx.send(stdout.read_exact(&mut line).map(|()| line));
        });
        let line = rx.recv_timeout(LIMIT).expect("the target's line within the limit").expect("the target's line");
        assert_eq!(line, TARGET_LINE);
        // The preflight's connection and the session's.
        let took = target.opened.load(Ordering::SeqCst);

        let pid = i32::try_from(operator.id()).unwrap();
        assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
        let hung_up = Instant::now();
        while target.closed.load(Ordering::SeqCst) < took {
            if hung_up.elapsed() > LET_GO {
                let _ = operator.kill();
                let lines: Vec<String> = said.try_iter().collect();
                panic!("the node still held its connection to the target {LET_GO:?} after the SIGHUP: {lines:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let status = loop {
            if let Some(status) = operator.try_wait().expect("wait") {
                break status;
            }
            if hung_up.elapsed() > LIMIT {
                let _ = operator.kill();
                panic!("the operator did not exit within {LIMIT:?} of the SIGHUP");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let lines: Vec<String> = said.try_iter().collect();
        assert_eq!(status.code(), Some(0), "the exit of a session that the node took: {lines:?}");
    }
}

pub(crate) mod no_resume {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::target::{target, Target, TARGET_LINE};
    use crate::throughput_harness::{lines_of, wait_for, Cell, Session};

    /// The bound on the wait for the target's line.
    const LIMIT: Duration = Duration::from_secs(60);
    /// How soon the node lets the target go after the loss of a session of
    /// --no-resume, and how long the control's connection stays held.
    const LET_GO: Duration = Duration::from_secs(3);

    /// Run `operator` until the target's line came on its stdout, then kill
    /// it: the connections that the target took by then, the node's preflight
    /// among them.
    fn killed_after_the_line(operator: &mut Command, target: &Target) -> usize {
        let mut child = operator.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        // Its stdin stays open: only the kill ends the session.
        let _stdin = child.stdin.take().expect("stdin");
        let said = lines_of(&mut child);
        let mut stdout = child.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = vec![0u8; TARGET_LINE.len()];
            let _ = tx.send(stdout.read_exact(&mut line).map(|()| line));
        });
        let line = match rx.recv_timeout(LIMIT) {
            Ok(Ok(line)) => line,
            other => {
                let _ = child.kill();
                panic!("no line of the target ({other:?}): {:?}", said.try_iter().collect::<Vec<_>>());
            }
        };
        assert_eq!(line, TARGET_LINE);
        let took = target.opened.load(Ordering::SeqCst);
        // The acknowledgements of the handshakes go out first, so that the
        // node has nothing more to send on the session.
        std::thread::sleep(Duration::from_millis(300));
        child.kill().expect("the kill");
        let _ = child.wait();
        took
    }

    pub(crate) fn run() {
        let s = Session::start("op-no-resume");
        let target = target();
        let cell = match Cell::fake_relay_mode(&s, "normal", "the stand-in relay") {
            Ok(cell) => cell,
            Err((_, why)) => {
                eprintln!("did not run: {why}");
                return;
            }
        };
        let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
        let (relay, ca) = (at("--relay-host"), at("--ca-file"));
        let command = |args: &[&str]| {
            let words: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            // The pins go before the verb's own words.
            let mut cmd = s.stand_in(&words[..1], &ca);
            cmd.args(["--relay-addr", "relay-a.test=127.0.0.1"]).args(&words[1..]);
            cmd
        };
        let pairing = ["relay", "pair", "lab", "--relay-host", relay.as_str()];
        let out = command(&pairing).stdin(Stdio::null()).output().unwrap();
        assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
        let at_target = format!("127.0.0.1:{}", target.port);
        let mut node = command(&["node", "lab", at_target.as_str()]);
        let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let node_lines = lines_of(&mut node);
        s.keep(node);
        wait_for(&node_lines, "online").expect("the node is online");

        // --no-resume: the node lets the target go at once.
        let took = killed_after_the_line(&mut command(&["operator", "--no-resume", "lab"]), &target);
        let lost = Instant::now();
        while target.closed.load(Ordering::SeqCst) < took {
            if lost.elapsed() > LET_GO {
                let lines: Vec<String> = node_lines.try_iter().collect();
                panic!("the node still held its connection to the target {LET_GO:?} after the loss: {lines:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // The control: with no ask, the node keeps the session and its
        // connection, for a resume that does not come here.
        let took = killed_after_the_line(&mut command(&["operator", "lab"]), &target);
        std::thread::sleep(LET_GO);
        let closed = target.closed.load(Ordering::SeqCst);
        assert!(closed < took, "the node keeps a session of no --no-resume: {closed} of {took} connections closed");
    }
}
