//! A pair's expiry (T-395), through the stand-in relay's reverse road on
//! the loopback: the node says the expiry before it comes, with the command
//! that makes the next pair; `podssh relay pair` makes that pair in the last
//! day of the first; and at the expiry the node goes on with it, with no new
//! start, so that a client logs in through the node after the expiry. The
//! stand-in's mode `expirefirst` gives the first pair 23 h, and ends it
//! early as the relay ends a pair at its expiry. The check says that it did
//! not run when this host has no Python or no openssl for the stand-in.
#![cfg(unix)]

mod ssh_harness;
mod throughput_harness;

use std::io::{BufRead, BufReader};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

/// The seconds after which the stand-in ends the first pair.
const FIRST_PAIR_ENDS: u64 = 12;

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
fn a_node_says_its_pairs_expiry_before_it_and_takes_the_next_pair() {
    let session = Session::start("expiry");
    let mode = format!("expirefirst:{FIRST_PAIR_ENDS}");
    let cell = match Cell::fake_relay_mode(&session, &mode, "the stand-in relay") {
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
    let pair = |extra: &[String]| {
        let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay.clone()];
        args.extend(pins.iter().cloned());
        args.extend(extra.iter().cloned());
        command(&args).stdin(Stdio::null()).output().unwrap()
    };
    let started = Instant::now();
    let out = pair(&[]);
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));

    let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port)];
    args.extend(pins.iter().cloned());
    let node = command(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut node = Kill(node);
    let lines = Arc::new(Mutex::new(String::new()));
    read_lines(&mut node.0, &lines);
    let said = |word: &str, limit: u64| wait_for(&lines, word, Duration::from_secs(limit));
    assert!(said("online", 30), "the node came online: {}", lines.lock().unwrap());
    // The first pair is in its last day: the node says so at once, with the
    // command that makes the next one.
    assert!(said("the pair expires in 22 h 59 min", 5), "{}", lines.lock().unwrap());
    assert!(
        said("`podssh relay pair lab --operator-file FILE` makes the next one now", 1),
        "{}",
        lines.lock().unwrap()
    );

    // The next pair, while the first lives: it takes the label's place.
    let file = session.home.join("operator-next.json");
    let out = pair(&["--operator-file".to_string(), file.display().to_string()]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "the next pair, in the last day of the first: {err}");
    assert!(err.contains("the next one takes its place in the store"), "{err}");
    assert!(file.exists(), "the operator's part of the next pair");
    assert!(
        started.elapsed() < Duration::from_secs(FIRST_PAIR_ENDS),
        "the next pair was made before the first ended; raise FIRST_PAIR_ENDS on a slow host"
    );

    // At the first pair's end the node takes the next one, and comes online
    // with it, with no new start.
    let limit = FIRST_PAIR_ENDS + 30;
    let taken = said("takes its place", limit);
    if let Some(status) = node.0.try_wait().unwrap() {
        panic!("the node ended at the expiry: {status:?}: {}", lines.lock().unwrap());
    }
    assert!(taken, "the node took the next pair: {}", lines.lock().unwrap());
    assert!(said("online again", 30), "{}", lines.lock().unwrap());

    // A client finds the node by the label, whose pair is the next one.
    let mut login = vec!["ssh".to_string()];
    login.extend(session.common());
    login.extend(pins.iter().cloned());
    login.extend(["node://tester@lab".to_string(), "greet".into()]);
    let out = command(&login).stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), ssh_harness::GREETING);
    assert!(node.0.try_wait().unwrap().is_none(), "the node serves on");
}

/// A node that the relay stops forgets its own pair, never the next one
/// that was stored under its label since: the next node needs it.
#[test]
fn a_stopped_node_leaves_the_next_pair_in_the_store() {
    let session = Session::start("expiry-stop");
    let cell = match Cell::fake_relay_mode(&session, "expirefirst:600", "the stand-in relay") {
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
    let run = |words: &[&str]| {
        let mut args: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        args.extend(pins.iter().cloned());
        command(&args).stdin(Stdio::null()).output().unwrap()
    };
    let store = session.home.join("cache").join("podssh");
    let file = |label: &str| store.join(podssh_relay::pair::file_name(label).unwrap());
    let out = run(&["relay", "pair", "lab", "--relay-host", &relay]);
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    // The first pair under a second label too, so that a test can stop it
    // once the next pair holds the label.
    std::fs::copy(file("lab"), file("first")).unwrap();
    let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port)];
    args.extend(pins.iter().cloned());
    let node = command(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut node = Kill(node);
    let lines = Arc::new(Mutex::new(String::new()));
    read_lines(&mut node.0, &lines);
    assert!(wait_for(&lines, "online", Duration::from_secs(30)), "{}", lines.lock().unwrap());
    let out = run(&["relay", "pair", "lab", "--relay-host", &relay]);
    assert!(out.status.success(), "the next pair: {}", String::from_utf8_lossy(&out.stderr));
    let next = std::fs::read(file("lab")).unwrap();
    let out = run(&["relay", "revoke", "first"]);
    assert!(out.status.success(), "the first pair stopped: {}", String::from_utf8_lossy(&out.stderr));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the stopped node ended: {}", lines.lock().unwrap());
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(status.code(), Some(69), "a stopped pair: {}", lines.lock().unwrap());
    assert_eq!(std::fs::read(file("lab")).ok(), Some(next), "the next pair stays under the label");
}

/// Kill a node at the end of a test.
struct Kill(std::process::Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Each line of the child's stderr, into `lines`.
fn read_lines(child: &mut std::process::Child, lines: &Arc<Mutex<String>>) {
    let (lines, stderr) = (lines.clone(), child.stderr.take().unwrap());
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let mut text = lines.lock().unwrap();
            text.push_str(&line);
            text.push('\n');
        }
    });
}
