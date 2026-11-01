//! A bulk session through a node moves to a new link at 48 MiB (T-155),
//! through the stand-in relay's reverse road on the loopback, which, as the
//! live relay, closes the node's socket for a frame of a session that it
//! forgot (T-412). The race of T-410, a frame of the node after the relay
//! forgot the old link's id, showed only on the live relay before; here the
//! harness fails the test for it. The check says that it did not run when
//! this host has no Python or no openssl for the stand-in.
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
