//! A bulk session through a node moves to a new link at 48 MiB (T-155),
//! through the stand-in relay's reverse road on the loopback, which, as the
//! live relay, closes the node's socket for a frame of a session that it
//! forgot (T-412). The race of T-410, a frame of the node after the relay
//! forgot the old link's id, showed only on the live relay before; here the
//! harness fails the test for it. And a session goes on across the node's
//! own upgrade in place (T-668), its bytes whole. The check says that it did
//! not run when this host has no Python or no openssl for the stand-in.
#![cfg(unix)]

mod ssh_harness;
mod throughput_harness;

use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{lines_of, wait_for, Cell, Session};

/// The stand-in relay's name, on the loopback.
const PINS: [&str; 2] = ["--relay-addr", "relay-a.test=127.0.0.1"];
/// Past two moves of 48 MiB.
const BYTES: u64 = 100 << 20;

#[test]
fn a_bulk_session_through_a_node_moves_with_no_frame_of_a_forgotten_id() {
    let session = Session::start("node-moves");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let mut pair = session.stand_in(&words(&["relay"]), &ca);
    let out = pair.args(["pair", "lab", "--relay-host", &relay]).args(PINS).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let target = format!("127.0.0.1:{}", session.port);
    let mut node = session.stand_in(&words(&["node"]), &ca);
    node.args(["lab", target.as_str()]).args(PINS);
    let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");

    // 100 MiB down from the test's server, through the node.
    let mut args = words(&["ssh", "-v"]);
    args.extend(session.common());
    args.extend(words(&["node://tester@lab", &format!("source {BYTES}")]));
    let mut ssh = session.stand_in(&args[..1], &ca);
    ssh.args(PINS).args(&args[1..]);
    let mut child = ssh.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let counted = std::thread::spawn(move || {
        let (mut buf, mut total) = (vec![0u8; 1 << 16], 0u64);
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            total += n as u64;
        }
        total
    });
    let mut stderr = child.stderr.take().unwrap();
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + Duration::from_secs(240);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("100 MiB through the node did not come within 240 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let (total, err) = (counted.join().unwrap(), said.join().unwrap());
    assert_eq!(status.code(), Some(0), "{err}");
    assert_eq!(total, BYTES, "{err}");
    let moves = err.lines().filter(|l| l.contains("moved")).count();
    assert!(moves >= 1, "the session moved at 48 MiB: {err}");
    // The session's end: each frame of a forgotten id is in the stand-in's
    // log, which the harness reads when `session` drops.
}

/// A session through a node goes on across the node's upgrade in place
/// (T-668): SIGUSR2 in the middle of 32 MiB down, and the node, the same
/// process, becomes its binary again (the test's own, which its probe takes)
/// with the session, whose client resumes; the bytes come whole, and the
/// test's server takes no new connection for the session, only the new
/// binary's look at TARGET as it starts.
#[test]
fn a_session_through_a_node_goes_on_across_the_node_s_upgrade_its_bytes_whole() {
    const DOWN: u64 = 32 << 20;
    let session = Session::start("node-upgrade");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let mut pair = session.stand_in(&words(&["relay"]), &ca);
    let out = pair.args(["pair", "lab", "--relay-host", &relay]).args(PINS).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let target = format!("127.0.0.1:{}", session.port);
    let mut node = session.stand_in(&words(&["node"]), &ca);
    node.args(["lab", target.as_str()]).args(PINS);
    let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = node.id() as libc::pid_t;
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");

    let mut args = words(&["ssh", "-v"]);
    args.extend(session.common());
    args.extend(words(&["node://tester@lab", &format!("source {DOWN}")]));
    let mut ssh = session.stand_in(&args[..1], &ca);
    ssh.args(PINS).args(&args[1..]);
    let mut child = ssh.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (quarter_tx, quarter_rx) = std::sync::mpsc::channel();
    let counted = std::thread::spawn(move || {
        let (mut buf, mut total) = (vec![0u8; 1 << 16], 0u64);
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            total += n as u64;
            if total >= DOWN / 4 {
                let _ = quarter_tx.send(());
            }
        }
        total
    });
    let mut stderr = child.stderr.take().unwrap();
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    quarter_rx.recv_timeout(Duration::from_secs(120)).expect("a quarter of the bytes came before the upgrade");
    let before = session.connections.load(std::sync::atomic::Ordering::SeqCst);
    // SAFETY: a signal to the node that this test started, which runs.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR2) }, 0);
    let went = wait_for(&lines, "sessions go to").expect("the node hands its sessions over");
    assert!(went.contains("1 of 1 sessions go to"), "{went}");
    let took = wait_for(&lines, "sessions over from").expect("the new binary takes them");
    assert!(took.contains("took 1 of 1 sessions over"), "{took}");

    let deadline = Instant::now() + Duration::from_secs(180);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("32 MiB through the node did not come within 180 s of the upgrade");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let (total, err) = (counted.join().unwrap(), said.join().unwrap());
    assert_eq!(status.code(), Some(0), "{err}");
    assert_eq!(total, DOWN, "{err}");
    // The same process serves on: an exec kept its pid.
    // SAFETY: a probe of a pid that this test started; no signal is sent.
    assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "the node runs on in its own process");
    let after = session.connections.load(std::sync::atomic::Ordering::SeqCst);
    assert!(after <= before + 1, "the session took no new connection to the server: {before} then {after}");
}
