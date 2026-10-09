//! The race between the iroh road and the pair's road (T-164), from end to
//! end. Live: a pair on the live relay; iroh's relay server on the
//! loopback, whose certificate the test puts beside the binary
//! (`podssh-ca.pem`, which the default trust store reads) for its run; and
//! `podssh node NAME TARGET --iroh` serving both roads in front of the
//! test's SSH server, which counts its connections. The rules of the race
//! are tested offline in `podssh-relay` (`tests/session_race.rs`).
#![cfg(feature = "iroh-test")]

mod ssh_harness;
mod throughput_harness;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use iroh::EndpointAddr;
use podssh_iroh::keys::{self, Place};
use podssh_relay::session::OsEntropy;
use ssh_harness::GREETING;
use throughput_harness::{lines_of, wait_for, Session};

const LIMIT: Duration = Duration::from_secs(120);

/// The test relay's certificate beside the binary, for the run.
struct Bundle(PathBuf);

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `podssh ARGS` to its end, within the limit: (code, stdout, stderr).
fn run(session: &Session, args: &[String]) -> (i32, String, String) {
    let mut child = session
        .command(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh {args:?} did not end within {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("output");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
#[ignore = "live: the pair's road goes through the live relay"]
fn the_iroh_road_wins_when_both_answer_and_the_pair_s_road_when_iroh_cannot() {
    let session = Session::start("race");
    let bundle = Path::new(env!("CARGO_BIN_EXE_podssh")).parent().unwrap().join("podssh-ca.pem");
    if bundle.exists() {
        eprintln!("skipped: {} exists, and this test does not replace it", bundle.display());
        return;
    }
    let relay = session.runtime.block_on(podssh_iroh::test_relay::spawn(&session.home)).expect("a relay");
    std::fs::copy(&relay.cert, &bundle).expect("the relay's certificate beside the binary");
    let _bundle = Bundle(bundle);

    // The pair, on the live relay.
    let label = format!("race{}", std::process::id());
    let (rc, _, err) = run(&session, &words(&["relay", "pair", &label]));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    session.revoke_later(&label);

    // This client's key, in the node's allowlist.
    let client_key = session.home.join("client.key");
    let key = keys::load(&Place::File(client_key.clone()), &mut OsEntropy).expect("the client's key");
    let allow = session.home.join("allow");
    std::fs::write(&allow, format!("{}\n", keys::fingerprint(&key.public()))).unwrap();

    // The node, on both roads.
    let url = relay.url.to_string();
    let target = format!("127.0.0.1:{}", session.port);
    let node_key = session.home.join("node.key").display().to_string();
    let allow_text = allow.display().to_string();
    let node_args = words(&[
        "node",
        &label,
        &target,
        "--iroh",
        "--iroh-relay",
        &url,
        "--iroh-allow",
        &allow_text,
        "--iroh-key",
        &node_key,
    ]);
    let mut node = session.command(&node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().expect("the node");
    let lines = lines_of(&mut node);
    session.keep(node);
    let serving = wait_for(&lines, "serving").expect("the node starts");
    assert!(serving.contains("the pair's road"), "the node serves both roads: {serving}");
    let ticket_line = wait_for(&lines, "ticket iroh:").expect("the node's ticket");
    let ticket = ticket_line[ticket_line.find("iroh:").unwrap()..].trim().to_string();
    // The node dialled TARGET once at its start.
    let before = session.connections.load(Ordering::SeqCst);

    let client_key_text = client_key.display().to_string();
    let destination = format!("node://tester@{label}");
    let ssh = |ticket: &str| {
        let mut args = words(&["ssh", "-v"]);
        args.extend(session.common());
        args.extend(words(&["--iroh-relay", &url, "--iroh-key", &client_key_text, "--iroh-ticket", ticket]));
        args.extend(words(&[&destination, "greet"]));
        run(&session, &args)
    };

    // Both roads answer: the iroh road, with its head start, wins, and the
    // pair's link, which lost, opened nothing at TARGET.
    let (rc, out, err) = ssh(&ticket);
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING);
    assert!(err.contains("the iroh road answered first"), "{err}");
    assert_eq!(session.connections.load(Ordering::SeqCst) - before, 1, "one connection to TARGET");

    // The iroh road cannot answer: the node's key at a relay where nothing
    // listens. The pair's road, after the head start, wins.
    let node_id = podssh_iroh::ticket::parse(&ticket).expect("the ticket").id;
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let nowhere = EndpointAddr::new(node_id).with_relay_url(format!("https://localhost:{silent}").parse().unwrap());
    let (rc, out, err) = ssh(&podssh_iroh::ticket::format(&nowhere));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING);
    assert!(err.contains("the pair's road answered first"), "{err}");
    assert_eq!(session.connections.load(Ordering::SeqCst) - before, 2, "one more connection to TARGET");
    drop(relay);
}
