//! A node that starts while the relay still holds the socket of the pair's
//! last node (T-416), through the stand-in relay's reverse road on the
//! loopback: the relay answers `409`, and the new node connects again, with
//! a line for each `409`, until the old socket is gone; then it comes online
//! and serves. A node that exited at the first `409` would leave the server
//! with no node after a restart, which a service manager or a box's script
//! makes at once (box.yml's chat run met it). The stand-in answers `409`
//! while a node of the pair is connected, so the first node stands for the
//! socket that the relay holds. The check says that it did not run when this
//! host has no Python or no openssl for the stand-in.
#![cfg(unix)]

mod ssh_harness;
mod throughput_harness;

use std::io::{BufRead, BufReader};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

/// Wait until `text` holds `word`, within `limit`.
fn wait_for(text: &Arc<Mutex<String>>, word: &str, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if text.lock().unwrap().contains(word) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn a_node_that_meets_409_at_its_start_connects_again_and_serves_once_the_old_socket_ends() {
    let session = Session::start("restart");
    let cell = match Cell::fake_relay(&session) {
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

    let mut node_args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port)];
    node_args.extend(pins.iter().cloned());
    let start = || {
        let mut child = Kill(
            command(&node_args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap(),
        );
        let lines = Arc::new(Mutex::new(String::new()));
        read_lines(&mut child.0, &lines);
        (child, lines)
    };
    let (mut first, first_lines) = start();
    assert!(wait_for(&first_lines, "online", Duration::from_secs(30)), "{}", first_lines.lock().unwrap());

    // The second node meets 409 while the first holds the pair, and says so.
    let (mut second, second_lines) = start();
    let said = wait_for(&second_lines, "(409); connecting again", Duration::from_secs(15));
    if let Some(status) = second.0.try_wait().unwrap() {
        panic!("the second node ended at the 409: {status:?}: {}", second_lines.lock().unwrap());
    }
    assert!(said, "the second node said the 409: {}", second_lines.lock().unwrap());
    assert!(!second_lines.lock().unwrap().contains("online"), "{}", second_lines.lock().unwrap());

    // The first node ends: its socket goes, and the second node comes online.
    first.0.kill().unwrap();
    first.0.wait().unwrap();
    assert!(wait_for(&second_lines, "online", Duration::from_secs(30)), "{}", second_lines.lock().unwrap());

    // A client logs in through the second node.
    let mut login = vec!["ssh".to_string()];
    login.extend(session.common());
    login.extend(pins.iter().cloned());
    login.extend(["node://tester@lab".to_string(), "greet".into()]);
    let out = command(&login).stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), ssh_harness::GREETING);
    assert!(second.0.try_wait().unwrap().is_none(), "the node serves on");
}

/// Kill a node at the end of a test.
struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Each line of the child's stderr, into `lines`.
fn read_lines(child: &mut Child, lines: &Arc<Mutex<String>>) {
    let (lines, stderr) = (lines.clone(), child.stderr.take().unwrap());
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let mut text = lines.lock().unwrap();
            text.push_str(&line);
            text.push('\n');
        }
    });
}
