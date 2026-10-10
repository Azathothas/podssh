//! The blocking facade (T-081) against the live relay, on request only:
//! `cargo test -p podssh-relay --features blocking --test blocking_live --
//! --ignored`. Plain `#[test]`s, with no runtime, as podbox calls the facade.
//! The forward session mints a relay token (self-service, cached per
//! machine). No test prints a token.
#![cfg(feature = "blocking")]

#[allow(dead_code)]
mod stand_in;

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::blocking::{Client, Config, Local, NodeChannel, NodeOptions, Operator, OperatorChannel, Stopper};
use podssh_relay::e2e::ends;
use podssh_relay::identity::{Identity, KeyName};
use podssh_relay::relay::{Relay, RelayList, DEFAULT_RELAY_HOST};
use podssh_relay::reverse::{Exit, Outcome};
use stand_in::{pipe, Shared};

const MIB: usize = 1024 * 1024;
const LIMIT: Duration = Duration::from_secs(60);

fn relay() -> Relay {
    Relay { host: DEFAULT_RELAY_HOST.into(), port: 443 }
}

fn pattern(seed: u8) -> Vec<u8> {
    (0..MIB).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// One operator session through an echo node: `payload` in, the same bytes
/// back; the input ends only after they came back, as an SSH client's does.
fn echo_session(client: &Client, to: &Operator<'_>, payload: Vec<u8>) -> (Vec<u8>, Outcome) {
    let (reader, mut feed) = pipe();
    let out = Shared::default();
    std::thread::scope(|s| {
        let writer = out.clone();
        let session = s.spawn(move || client.run_operator(to, reader, writer));
        feed.write_all(&payload).unwrap();
        let deadline = Instant::now() + LIMIT;
        while out.bytes().len() < payload.len() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(feed);
        let outcome = session.join().unwrap().expect("the operator's socket");
        (out.bytes(), outcome)
    })
}

#[test]
#[ignore = "the live relay: run with --ignored"]
fn a_node_and_two_operator_sessions_at_once_through_the_facade() {
    let client = Client::new(Config::default()).expect("a client");
    let relay = relay();
    let mut pair = client.pair(&relay).expect("a pair");
    // The operator's side holds the name and the connect token, as an
    // operator file does.
    let (name, connect) = (pair.name.clone(), pair.connect_token().to_string());
    // The end-to-end channel, with keys of the test's own, kept in no file.
    let node_key = Arc::new(Identity::from_seed(&[0x4e; 32]));
    let to = Operator::new(&relay, &name, &connect).with_channel(OperatorChannel::With {
        identity: Arc::new(Identity::from_seed(&[0x4f; 32])),
        node: KeyName::Key(node_key.public()),
    });
    let options = NodeOptions {
        channel: NodeChannel::With(ends::Node::open_to_all(node_key, Arc::new(|_: String| {}))),
        ..NodeOptions::default()
    };
    let stopper = Stopper::new();
    let echo = |_: &str| {
        let (reader, writer) = pipe();
        Ok(Local::new(reader, writer))
    };
    std::thread::scope(|s| {
        let node = s.spawn(|| client.run_node(&mut pair, echo, &options, &stopper));
        std::thread::sleep(Duration::from_secs(2));
        let sessions: Vec<_> = [1u8, 2]
            .into_iter()
            .map(|seed| {
                let (client, to) = (&client, &to);
                (seed, s.spawn(move || echo_session(client, to, pattern(seed))))
            })
            .collect();
        for (seed, session) in sessions {
            let (back, outcome) = session.join().unwrap();
            assert!(back == pattern(seed), "session {seed}: {} bytes came back, changed or short", back.len());
            assert!(outcome.is_success(), "session {seed}: {outcome:?}");
            eprintln!("session {seed}: 1 MiB each way came back whole: {outcome:?}");
        }
        stopper.stop();
        let exit = node.join().unwrap().expect("a node");
        assert!(matches!(exit, Exit::Stopped), "{exit:?}");
    });
    let stopped = client.stop(&pair).expect("the pair stops");
    eprintln!("pair: {stopped:?}");
}

/// GitHub's SSH server through a forward session: its identification line;
/// then ours, and the end of ours, after which its answer still comes, and
/// the relay's Close 1000 ends the reads (about 15 s later, when the server
/// is idle).
#[test]
#[ignore = "the live relay: run with --ignored"]
fn a_forward_session_through_the_facade_reads_on_after_a_half_close() {
    let client = Client::new(Config::default()).expect("a client");
    let relays = RelayList { hosts: vec![relay()], explicit: true };
    let mut forward = client.open_forward(&relays, "github.com", 22).expect("a session");
    let mut banner = Vec::new();
    let mut byte = [0u8; 1];
    while !banner.ends_with(b"\r\n") && banner.len() < 256 {
        forward.read_exact(&mut byte).expect("the banner");
        banner.push(byte[0]);
    }
    assert!(banner.starts_with(b"SSH-2.0-"), "{:?}", String::from_utf8_lossy(&banner));
    forward.write_all(b"SSH-2.0-podssh_facade_test\r\n").unwrap();
    forward.shutdown_write().expect("a Close sent");
    let started = Instant::now();
    let mut rest = Vec::new();
    forward.read_to_end(&mut rest).expect("a normal end");
    assert!(!rest.is_empty(), "the server answered after the half-close");
    eprintln!(
        "from {}: {}; then {} bytes, and the relay's Close after {:.1} s",
        forward.relay().host,
        String::from_utf8_lossy(&banner).trim_end(),
        rest.len(),
        started.elapsed().as_secs_f64()
    );
}
