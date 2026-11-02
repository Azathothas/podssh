//! The layer's window on the pair's road (T-443), through the stand-in
//! relay's reverse road in its mode `strict:RATE`, which keeps the bound of
//! the contract: a frame that would put more than 1 MiB in the queue of a
//! slow receiver is dropped, and the receiver's socket gets `1011 relay
//! backpressure`. The stand-in gives the operator 1 MiB a second, and
//! `podssh operator` takes 6 MB of a node's TARGET whole, with no close of
//! the stand-in and no lost link. With no SSH and no channel above the layer
//! (`podssh operator`, `--no-e2e`), nothing but the layer's window bounds
//! what waits: with the replay buffer's 4 MiB as the window, the stand-in
//! closes. The check says that it did not run when this host has no Python
//! or no openssl for the stand-in.
#![cfg(unix)]

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{lines_of, wait_for, Cell, Session};

/// The stand-in relay's name, on the loopback.
const PINS: [&str; 2] = ["--relay-addr", "relay-a.test=127.0.0.1"];
/// The stand-in's mode: 1 MiB a second to each operator.
const MODE: &str = "strict:1048576";
/// What TARGET sends: six seconds at the stand-in's rate, eight windows.
const BYTES: usize = 6_000_000;
const LIMIT: Duration = Duration::from_secs(120);

/// A TARGET on the loopback that sends [`BYTES`] to each connection, ends
/// its bytes, then reads until the connection ends.
fn source() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let chunk = vec![0x5au8; 64 * 1024];
                let mut left = BYTES;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if stream.write_all(&chunk[..n]).is_err() {
                        return;
                    }
                    left -= n;
                }
                let _ = stream.shutdown(Shutdown::Write);
                let mut sink = [0u8; 4096];
                while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
            });
        }
    });
    port
}

#[test]
fn a_slow_operator_takes_each_byte_with_no_close_for_backpressure() {
    let session = Session::start("node-window");
    let cell = match Cell::fake_relay_mode(&session, MODE, "the stand-in relay, strict") {
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
    let target = format!("127.0.0.1:{}", source());
    // No channel above the layer: a flow of its own would hide the window.
    let mut node = session.stand_in(&words(&["node"]), &ca);
    node.args(["lab", target.as_str(), "--no-e2e"]).args(PINS);
    let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");

    let mut operator = session.stand_in(&words(&["operator"]), &ca);
    operator.args(["lab", "--no-e2e"]).args(PINS);
    // stdin stays open: its end would end the session before TARGET's bytes.
    let mut child = operator.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let counted = std::thread::spawn(move || {
        let (mut buf, mut total) = (vec![0u8; 1 << 16], 0usize);
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            assert!(buf[..n].iter().all(|b| *b == 0x5a), "a byte that TARGET did not send");
            total += n;
        }
        total
    });
    let mut stderr = child.stderr.take().unwrap();
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{BYTES} bytes through the node did not come within {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    drop(stdin);
    let (total, err) = (counted.join().unwrap(), said.join().unwrap());
    let log = session.home.join(format!("fake-relay-{}.log", MODE.replace(':', "-")));
    let log = std::fs::read_to_string(log).unwrap_or_default();
    assert!(!log.contains("relay backpressure"), "the stand-in closed a socket for backpressure: {log}");
    assert_eq!(status.code(), Some(0), "{err}\nthe stand-in said: {log}");
    assert_eq!(total, BYTES, "{err}");
    assert!(!err.contains("resuming"), "no link was lost: {err}");
}
