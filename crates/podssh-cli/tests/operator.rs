//! `podssh operator` and `podssh ssh node://NAME` (T-084) as processes,
//! offline, with a scratch HOME and cache: each refusal and its code, a pair
//! file of either form, stdout that stays empty, and no token in any output.
//! Through the stand-in relay of the reverse road (Python and openssl), an
//! operator that its parent hangs up closes its session (T-586), the bound
//! of `--ConnectTimeout` ends a wait for `ready` that the relay's own limit
//! would not (T-589), and an operator of `--no-resume` whose link is lost
//! leaves the node nothing (T-612).

mod pair_harness;
mod ssh_harness;
mod throughput_harness;

use podssh_relay::pair;

use pair_harness::*;

#[test]
fn with_no_stored_pair_each_names_the_remedy_and_opens_nothing() {
    let home = scratch("op-none");
    let (rc, out, err) = podssh(&home, &["operator", "lab"], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("podssh relay pair lab") && err.contains("--pair-file"), "{err}");
    assert!(out.is_empty());
    let (rc, out, err) = podssh(&home, &["ssh", "-T", "node://lab", "true"], &[]);
    assert_eq!(rc, 255, "OpenSSH's code for a failure of podssh: {err}");
    assert!(err.contains("node://lab") && err.contains("podssh relay pair lab"), "{err}");
    assert!(!err.contains("PODSSH_OFFLINE"), "refused before any connection: {err}");
    assert!(out.is_empty());
}

#[test]
fn an_expired_pair_is_refused_with_its_remedy() {
    let home = scratch("op-expired");
    store(&home, "lab", EXPIRED);
    let (rc, _, err) = podssh(&home, &["operator", "lab"], &[]);
    assert_eq!(rc, 77, "{err}");
    assert!(err.contains("expired") && err.contains("podssh relay pair lab"), "{err}");
    let (rc, _, err) = podssh(&home, &["ssh", "-T", "node://lab", "true"], &[]);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("expired"), "{err}");
}

/// A stored pair gets each command as far as the network, which
/// `PODSSH_OFFLINE` stops, and no output holds a token.
#[test]
fn a_stored_pair_reaches_the_network_and_no_token_is_shown() {
    let home = scratch("op-redact");
    store(&home, "lab", 0);
    let set = [("PODSSH_RELAY_TOKEN", FORWARD)];
    for (args, code) in [(vec!["operator", "lab"], 69), (vec!["ssh", "-T", "node://lab", "true"], 255)] {
        let (rc, out, err) = podssh(&home, &args, &set);
        assert_eq!(rc, code, "{args:?}: {err}");
        assert!(err.contains("PODSSH_OFFLINE"), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout carries the node's bytes alone: {out:?}");
        no_token(&err);
    }
}

#[test]
fn a_pair_file_of_either_form_gives_the_operator_its_part() {
    let home = scratch("op-file");
    let operator_file = home.join("operator.json");
    pair::write_operator_file(&operator_file, &test_pair(0)).unwrap();
    let whole = pair::store_in_first(&[home.join("elsewhere")], "carried", &test_pair(0)).unwrap();
    for file in [&operator_file, &whole] {
        let path = file.to_str().unwrap();
        for args in
            [vec!["operator", "lab", "--pair-file", path], vec!["ssh", "-T", "--pair-file", path, "node://lab", "true"]]
        {
            let (rc, out, err) = podssh(&home, &args, &[]);
            assert!(
                err.contains("PODSSH_OFFLINE"),
                "{args:?}: the part was read, and only the network stopped it: {err}"
            );
            assert!(rc == 69 || rc == 255, "{args:?}: {rc}");
            no_token(&out);
            no_token(&err);
        }
    }
    let junk = home.join("junk.json");
    std::fs::write(&junk, b"{}").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (rc, _, err) = podssh(&home, &["operator", "lab", "--pair-file", junk.to_str().unwrap()], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("no operator's part"), "{err}");
}

#[test]
fn operator_needs_a_name_and_takes_no_target() {
    let home = scratch("op-parse");
    let (rc, _, err) = podssh(&home, &["operator"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("missing NAME"), "{err}");
    let (rc, _, err) = podssh(&home, &["operator", "lab", "127.0.0.1:22"], &[]);
    assert_eq!(rc, 64, "the node, not the operator, names the TARGET: {err}");
    let (rc, _, err) = podssh(&home, &["operator", "../x"], &[]);
    assert_eq!(rc, 64, "{err}");
}

/// `--ConnectTimeout` (T-589): 0, or no number, is refused (64) on each of
/// the three verbs, before a pair is read or anything dialled; `operator`
/// and `proxy` take no `-o`, so `-o ConnectTimeout=N` stays refused.
#[test]
fn a_connect_timeout_of_zero_is_refused() {
    let home = scratch("op-bound-zero");
    let cases: [&[&str]; 6] = [
        &["operator", "lab", "--ConnectTimeout", "0"],
        &["operator", "lab", "--ConnectTimeout", "soon"],
        &["proxy", "--ConnectTimeout", "0", "host.example", "22"],
        &["proxy", "--ConnectTimeout", "0", "node://lab"],
        &["pipe", "--ConnectTimeout", "0", "stdio", "relay:host.example:22"],
        &["pipe", "--ConnectTimeout", "0s", "stdio", "node:lab"],
    ];
    for args in cases {
        let (rc, out, err) = podssh(&home, args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains("--ConnectTimeout"), "{args:?}: {err}");
        assert!(!err.contains("PODSSH_OFFLINE"), "{args:?}: refused before any connection: {err}");
        assert!(out.is_empty(), "{args:?}");
    }
    for args in
        [&["operator", "-o", "ConnectTimeout=3", "lab"][..], &["proxy", "-o", "ConnectTimeout=3", "h", "22"][..]]
    {
        let (rc, _, err) = podssh(&home, args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
    }
    // A listening pipe opens a road for each client: no bound of one open.
    let (rc, _, err) =
        podssh(&home, &["pipe", "--ConnectTimeout", "3", "tcp-listen:127.0.0.1:0", "relay:host.example:22"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("a listening side"), "{err}");
}

/// `--ConnectTimeout` (T-589): through a stand-in relay that takes the
/// operator's socket and never sends `ready` (its mode `noready`), a bound of
/// 3 s ends the operator within 5 s, with 69 and a line that names `ready`;
/// with none, its own 20 s for `ready` would pass first. It says that it did
/// not run where this host cannot run the stand-in.
#[test]
fn operator_s_connect_timeout_ends_a_wait_for_ready() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let s = throughput_harness::Session::start("op-bound");
    let cell = match throughput_harness::Cell::fake_relay_mode(&s, "noready", "the stand-in relay, never ready") {
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
        // The pin of the stand-in's name goes after the verb.
        let mut cmd = s.stand_in(&words[..1], &ca);
        cmd.args(["--relay-addr", "relay-a.test=127.0.0.1"]).args(&words[1..]);
        cmd
    };
    let out = command(&["relay", "pair", "lab", "--relay-host", relay.as_str()]).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let started = Instant::now();
    let mut operator = command(&["operator", "lab", "--ConnectTimeout", "3"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Its stdin stays open: only the bound ends the wait.
    let _stdin = operator.stdin.take().expect("stdin");
    let said = throughput_harness::lines_of(&mut operator);
    let status = loop {
        if let Some(status) = operator.try_wait().expect("wait") {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = operator.kill();
            panic!("the operator did not end within 60 s: {:?}", said.try_iter().collect::<Vec<_>>());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let took = started.elapsed();
    std::thread::sleep(Duration::from_millis(100));
    let lines: Vec<String> = said.try_iter().collect();
    assert_eq!(status.code(), Some(69), "{lines:?}");
    assert!(took < Duration::from_secs(5), "the bound of 3 s ended the wait after {took:?}: {lines:?}");
    let line = lines.iter().find(|l| l.contains("(--ConnectTimeout)"));
    assert!(line.is_some_and(|l| l.contains("ready") && l.contains("within 3 s")), "{lines:?}");
}

/// GitHub #112 (T-586): OpenSSH ends its ProxyCommand with SIGHUP and does
/// not wait for it. Through the stand-in relay, after the target's last
/// byte and with its stdin still open, the operator gets SIGHUP: it closes
/// the session, so the node keeps none, and shuts its connection to the
/// target within 3 s; the operator exits 0, as at the end of its stdin. An
/// operator that died of the signal left the session to the node as a loss,
/// held with that connection for 10 minutes. Windows has no SIGHUP. It says
/// that it did not run where this host cannot run the stand-in.
#[cfg(unix)]
#[test]
fn an_operator_that_its_parent_hangs_up_closes_the_session() {
    hung_up::run();
}

/// The TARGET of a node of the tests through the stand-in relay, which
/// counts its connections.
mod target {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// The line that the target writes to each connection.
    pub(super) const TARGET_LINE: &[u8] = b"the target's last line\n";

    /// A TCP service that writes [`TARGET_LINE`] to each connection, then
    /// reads it to its end, a minute at most: its port, the connections that
    /// it took, and those that ended.
    pub(super) struct Target {
        pub(super) port: u16,
        pub(super) opened: Arc<AtomicUsize>,
        pub(super) closed: Arc<AtomicUsize>,
    }

    pub(super) fn target() -> Target {
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
mod hung_up {
    use std::io::Read;
    use std::process::Stdio;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::target::{target, TARGET_LINE};
    use super::throughput_harness::{lines_of, wait_for, Cell, Session};

    /// The bound on each wait for the operator: its bytes, its exit.
    const LIMIT: Duration = Duration::from_secs(60);
    /// How soon the node lets the target go after the signal.
    const LET_GO: Duration = Duration::from_secs(3);

    pub(super) fn run() {
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

/// `--no-resume` (T-612): through the stand-in relay, an operator that asked
/// for no resume, killed with its session open (so that it sends nothing
/// more, as when its link is lost), leaves the node nothing: the relay tells
/// the node of the loss, and the node shuts its connection to the target
/// within 3 s. The control: an operator with no ask, killed the same way,
/// leaves the session to a resume, and the node keeps that connection for its
/// deadline. It says that it did not run where this host cannot run the
/// stand-in.
#[test]
fn an_operator_of_no_resume_leaves_the_node_nothing_at_a_loss() {
    no_resume::run();
}

mod no_resume {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::target::{target, Target, TARGET_LINE};
    use super::throughput_harness::{lines_of, wait_for, Cell, Session};

    /// The bound on the wait for the target's line.
    const LIMIT: Duration = Duration::from_secs(60);
    /// How soon the node lets the target go after the loss of a session of
    /// --no-resume, and how long the control's connection stays held.
    const LET_GO: Duration = Duration::from_secs(3);

    /// Run `operator` until the target's line came on its stdout, then kill
    /// it: the connections that the target took by then, the node's preflight
    /// among them.
    fn killed_after_the_line(operator: &mut Command, target: &Target) -> usize {
        let mut child =
            operator.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
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

    pub(super) fn run() {
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
