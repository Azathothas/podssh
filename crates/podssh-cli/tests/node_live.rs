//! `podssh relay` and `podssh node` against the live relay (T-083), on request
//! only: `cargo test -p podssh-cli --test node_live -- --ignored`. The binary
//! makes a pair and runs a node in front of GitHub's SSH server; an operator
//! session that holds the operator's file alone reads GitHub's banner through
//! the node; then the binary stops the pair. No test prints a token. Two
//! tests take long, and run with the checks of the release (T-251): an idle
//! session of 10 minutes (T-154), and 200 MiB each way (T-155).

mod live_harness;

use std::process::Stdio;
use std::time::{Duration, Instant};

use live_harness::{command, echo_server, lines_of, run, scratch, Cleanup, LIMIT};
use podssh_relay::relay::parse_relay;
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome, Wire};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
#[ignore = "the live relay: run with --ignored"]
fn node_command_serves_a_tcp_target() {
    let home = scratch("serve");
    let operator_file = home.join("lab-operator.json");
    let (rc, out, err) = run(&home, &["relay", "pair", "lab", "--operator-file", operator_file.to_str().unwrap()]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.starts_with("lab: expires "), "{out}");
    let mut cleanup = Cleanup { home: &home, node: None };

    let mut node = command(&home, &["node", "lab", "github.com:22"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the node runs");
    let lines = lines_of(&mut node);
    cleanup.node = Some(node);
    let first = lines.recv_timeout(LIMIT).expect("the node says what it serves");
    assert!(first.contains("serving github.com:22"), "{first}");
    std::thread::sleep(Duration::from_secs(2));

    let part: serde_json::Value = serde_json::from_slice(&std::fs::read(&operator_file).unwrap()).unwrap();
    let relay = parse_relay(part["relay"].as_str().unwrap()).unwrap();
    let name = part["name"].as_str().unwrap().to_string();
    let token = part["connect_token"].as_str().unwrap().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    // The node greets with the resumable layer (T-153): its client goes
    // between the reader and the operator's leg, as in `podssh operator`.
    let (banner, carried) = runtime.block_on(async {
        let (app, mut user) = tokio::io::duplex(64 * 1024);
        let (link, leg_end) = tokio::io::duplex(64 * 1024);
        let config = OperatorConfig {
            relay: &relay,
            name: &name,
            connect_token: &token,
            trust: &Trust::Default,
            proxy: &ProxyChoice::FromEnvironment,
            timeout: Duration::from_secs(30),
            limits: OperatorLimits::default(),
            wire: Wire::Tls,
        };
        let first = operator::start(&config, leg_end).await.expect("the operator's socket");
        let read = async move {
            let mut got = Vec::new();
            let mut byte = [0u8; 1];
            while !got.ends_with(b"\r\n") && got.len() < 256 {
                if user.read_exact(&mut byte).await.is_err() {
                    break;
                }
                got.push(byte[0]);
            }
            // The end of the input ends the session.
            let _ = user.shutdown().await;
            got
        };
        let say = |_: podssh_cli::layered::Line| {};
        let carry = podssh_cli::layered::carry(&config, link, first, app, None, &say);
        let (carried, banner) = tokio::join!(tokio::time::timeout(LIMIT, carry), read);
        (banner, carried)
    });
    let carried = carried.expect("the session in time");
    let outcome = carried.leg.expect("the leg's end");
    eprintln!("through the node: {}; {outcome:?}", String::from_utf8_lossy(&banner).trim_end());
    assert!(banner.starts_with(b"SSH-2.0-"), "{:?}", String::from_utf8_lossy(&banner));
    assert_eq!(carried.why, None);
    assert!(matches!(outcome, Outcome::LocalEnd | Outcome::Ended { code: 1000, .. }), "{outcome:?}");

    let (rc, out, err) = run(&home, &["relay", "status", "lab"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.starts_with("lab: online"), "{out}");
    eprintln!("{}", out.trim_end());

    let mut node = cleanup.node.take().unwrap();
    let _ = node.kill();
    let _ = node.wait();
    let (rc, out, err) = run(&home, &["relay", "revoke", "lab"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.starts_with("lab: stopped"), "{out}");
    assert!(!home.join("cache").join("podssh").join("pair-lab.json").exists(), "the stored copy is gone");
    eprintln!("{}", out.trim_end());
}

/// `podssh ssh node://NAME` and `podssh operator NAME` (T-084) through a node
/// in front of railway.new's SSH service, which takes any key: a throwaway
/// one, deleted with the scratch directory. No output of the session is
/// printed: railway.new's holds a claim URL.
#[test]
#[ignore = "the live relay: run with --ignored"]
fn ssh_to_a_node() {
    let home = scratch("ssh");
    let operator_file = home.join("lab-operator.json");
    let op = operator_file.to_str().unwrap();
    let (rc, _, err) = run(&home, &["relay", "pair", "lab", "--operator-file", op]);
    assert_eq!(rc, 0, "{err}");
    let mut cleanup = Cleanup { home: &home, node: None };
    let mut node = command(&home, &["node", "lab", "railway.new:22"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the node runs");
    let lines = lines_of(&mut node);
    cleanup.node = Some(node);
    let first = lines.recv_timeout(LIMIT).expect("the node says what it serves");
    assert!(first.contains("serving railway.new:22"), "{first}");
    std::thread::sleep(Duration::from_secs(2));

    let key = home.join("throwaway_key");
    let (rc, _, err) = run(&home, &["keygen", "-t", "ed25519", "-N", "", "-f", key.to_str().unwrap()]);
    assert_eq!(rc, 0, "{err}");
    let known = home.join("known_hosts");
    let known_option = format!("UserKnownHostsFile={}", known.display());
    let (rc, out, err) = run(
        &home,
        &[
            "ssh",
            "-T",
            "-i",
            key.to_str().unwrap(),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            &known_option,
            "-o",
            "BatchMode=yes",
            "--pair-file",
            op,
            "node://test@lab",
            "exit 3",
        ],
    );
    // Withheld: railway.new's words hold a claim URL. Measured 2026-10-09:
    // railway.new can answer an anonymous visitor with its limit instead of
    // running the command; the login through the node then worked, and the
    // check cannot be made.
    assert!(
        !out.contains("visitors are limited"),
        "railway.new limited this anonymous visitor (its exit {rc}): the login through the node worked, but \
         `exit 3` did not run; try again later"
    );
    assert_eq!(rc, 3, "the remote status through the node ({} bytes out, {} bytes err)", out.len(), err.len());
    let recorded = std::fs::read_to_string(&known).expect("a host key recorded");
    assert!(recorded.starts_with("node://lab "), "the host key is recorded under node://lab");
    eprintln!("podssh ssh node://test@lab 'exit 3': exit {rc}; the host key is recorded under node://lab");

    let mut pipe = command(&home, &["operator", "lab", "--pair-file", op])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the operator runs");
    let mut stdout = pipe.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut got = Vec::new();
        let mut byte = [0u8; 1];
        while !got.ends_with(b"\r\n") && got.len() < 256 && std::io::Read::read_exact(&mut stdout, &mut byte).is_ok() {
            got.push(byte[0]);
        }
        let _ = tx.send(got);
    });
    let banner = rx.recv_timeout(LIMIT).expect("the node's TARGET answers through the pipe");
    assert!(banner.starts_with(b"SSH-2.0-"), "the banner of railway.new's SSH server");
    drop(pipe.stdin.take());
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = pipe.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the operator ends with its stdin");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(0), "the node took the session, and it ended normally");
    eprintln!("podssh operator lab: the SSH banner came through, then exit 0 at the end of stdin");

    let mut node = cleanup.node.take().unwrap();
    let _ = node.kill();
    let _ = node.wait();
    let (rc, _, err) = run(&home, &["relay", "revoke", "lab"]);
    assert_eq!(rc, 0, "{err}");
}

/// How long the idle session waits (T-154).
const IDLE: Duration = Duration::from_secs(600);

/// An idle session through a node for 10 minutes (T-154, T-153): a node in
/// front of an echo server on this machine's loopback, and the client of the
/// resumable layer over the library's operator leg. The layer's records keep
/// each link busy, and a link that the relay's side drops (T-255) is
/// replaced; after the wait the echo still answers. Each loss and resume is
/// printed.
#[test]
#[ignore = "the live relay, 10 minutes: run with --ignored"]
fn an_idle_session_through_a_node_lives_10_minutes() {
    let port = echo_server();

    let home = scratch("idle");
    let operator_file = home.join("lab-operator.json");
    let (rc, _, err) = run(&home, &["relay", "pair", "lab", "--operator-file", operator_file.to_str().unwrap()]);
    assert_eq!(rc, 0, "{err}");
    let mut cleanup = Cleanup { home: &home, node: None };
    let target = format!("127.0.0.1:{port}");
    let mut node = command(&home, &["node", "lab", &target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the node runs");
    let lines = lines_of(&mut node);
    cleanup.node = Some(node);
    let first = lines.recv_timeout(LIMIT).expect("the node says what it serves");
    assert!(first.contains(&format!("serving {target}")), "{first}");
    std::thread::sleep(Duration::from_secs(2));

    let part: serde_json::Value = serde_json::from_slice(&std::fs::read(&operator_file).unwrap()).unwrap();
    let relay = parse_relay(part["relay"].as_str().unwrap()).unwrap();
    let name = part["name"].as_str().unwrap().to_string();
    let token = part["connect_token"].as_str().unwrap().to_string();
    let notes = std::sync::Mutex::new(Vec::new());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let carried = runtime.block_on(async {
        let (app, mut user) = tokio::io::duplex(64 * 1024);
        let (link, leg_end) = tokio::io::duplex(64 * 1024);
        let config = OperatorConfig {
            relay: &relay,
            name: &name,
            connect_token: &token,
            trust: &Trust::Default,
            proxy: &ProxyChoice::FromEnvironment,
            timeout: Duration::from_secs(30),
            limits: OperatorLimits::default(),
            wire: Wire::Tls,
        };
        let first = operator::start(&config, leg_end).await.expect("the operator's socket");
        let say = |line: podssh_cli::layered::Line| {
            if let podssh_cli::layered::Line::Always(text) = line {
                eprintln!("{text}");
                notes.lock().unwrap().push(text);
            }
        };
        let user_side = async move {
            for word in [&b"before the wait\n"[..], &b"after the wait\n"[..]] {
                user.write_all(word).await.unwrap();
                let mut back = vec![0u8; word.len()];
                tokio::time::timeout(LIMIT, user.read_exact(&mut back)).await.expect("the echo in time").unwrap();
                assert_eq!(back, word);
                if word.starts_with(b"before") {
                    tokio::time::sleep(IDLE).await;
                }
            }
            let _ = user.shutdown().await;
        };
        let carry = podssh_cli::layered::carry(&config, link, first, app, None, &say);
        let (carried, ()) = tokio::join!(carry, user_side);
        carried
    });
    assert_eq!(carried.why, None);
    let notes = notes.lock().unwrap();
    eprintln!("an idle session of {} s through the node: {} lines of loss and resume", IDLE.as_secs(), notes.len());

    let mut node = cleanup.node.take().unwrap();
    let _ = node.kill();
    let _ = node.wait();
    let (rc, _, err) = run(&home, &["relay", "revoke", "lab"]);
    assert_eq!(rc, 0, "{err}");
}

/// The bytes that go each way through the node in the test of the move.
const MOVED: usize = 200 << 20;

/// Bytes from a fixed xorshift, made a block at a time, so that the test
/// needs no 200 MiB in memory.
struct Xorshift(u32);

impl Xorshift {
    fn fill(&mut self, block: &mut [u8]) {
        for byte in block {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            *byte = self.0 as u8;
        }
    }
}

/// A session through a node that carries 200 MiB each way (T-155), far more
/// than the relay's 64 MiB for one of its sessions: the resumable layer moves
/// the session to a new link before each link meets the cap, and the bytes
/// come back whole from an echo server on this machine's loopback. Each move
/// and each loss is printed.
#[test]
#[ignore = "the live relay, 200 MiB each way: run with --ignored"]
fn move_200mib_each_way_through_a_node() {
    use sha2::{Digest, Sha256};

    let port = echo_server();

    let home = scratch("move");
    let operator_file = home.join("lab-operator.json");
    let (rc, _, err) = run(&home, &["relay", "pair", "lab", "--operator-file", operator_file.to_str().unwrap()]);
    assert_eq!(rc, 0, "{err}");
    let mut cleanup = Cleanup { home: &home, node: None };
    let target = format!("127.0.0.1:{port}");
    let mut node = command(&home, &["node", "lab", &target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the node runs");
    let lines = lines_of(&mut node);
    cleanup.node = Some(node);
    let first = lines.recv_timeout(LIMIT).expect("the node says what it serves");
    assert!(first.contains(&format!("serving {target}")), "{first}");
    std::thread::sleep(Duration::from_secs(2));

    let part: serde_json::Value = serde_json::from_slice(&std::fs::read(&operator_file).unwrap()).unwrap();
    let relay = parse_relay(part["relay"].as_str().unwrap()).unwrap();
    let name = part["name"].as_str().unwrap().to_string();
    let token = part["connect_token"].as_str().unwrap().to_string();
    let lines_said = std::sync::Mutex::new(Vec::new());
    let started = Instant::now();
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (carried, sent, received) = runtime.block_on(async {
        let (app, user) = tokio::io::duplex(256 * 1024);
        let (link, leg_end) = tokio::io::duplex(256 * 1024);
        let config = OperatorConfig {
            relay: &relay,
            name: &name,
            connect_token: &token,
            trust: &Trust::Default,
            proxy: &ProxyChoice::FromEnvironment,
            timeout: Duration::from_secs(30),
            limits: OperatorLimits::default(),
            wire: Wire::Tls,
        };
        let first = operator::start(&config, leg_end).await.expect("the operator's socket");
        let say = |line: podssh_cli::layered::Line| {
            let text = match line {
                podssh_cli::layered::Line::Always(text) | podssh_cli::layered::Line::Verbose(text) => text,
            };
            eprintln!("{:.0} s: {text}", started.elapsed().as_secs_f64());
            lines_said.lock().unwrap().push(text);
        };
        let (mut user_r, mut user_w) = tokio::io::split(user);
        let write = async move {
            let (mut bytes, mut digest) = (Xorshift(0x5eed_0155), Sha256::new());
            let mut block = vec![0u8; 64 * 1024];
            for _ in 0..MOVED / block.len() {
                bytes.fill(&mut block);
                digest.update(&block);
                user_w.write_all(&block).await.expect("the session takes each byte");
            }
            digest.finalize()
        };
        let read = async move {
            let mut digest = Sha256::new();
            let mut block = vec![0u8; 64 * 1024];
            let mut left = MOVED;
            while left > 0 {
                let n = user_r.read(&mut block).await.expect("the session gives each byte");
                assert!(n > 0, "the session ended {left} bytes early");
                digest.update(&block[..n]);
                left -= n;
            }
            digest.finalize()
        };
        let user_side = async move {
            let (sent, received) = tokio::join!(write, read);
            (sent, received)
        };
        let carry = podssh_cli::layered::carry(&config, link, first, app, None, &say);
        tokio::pin!(carry);
        // The user's side ends its bytes once each came back, and the session
        // then ends.
        let (sent, received) = tokio::select! {
            sides = user_side => sides,
            carried = &mut carry => panic!("the session ended before its bytes: {:?}", carried.why),
        };
        (carry.await, sent, received)
    });
    assert_eq!(sent, received, "200 MiB came back whole");
    assert_eq!(carried.why, None);
    let said = lines_said.lock().unwrap();
    let moves = said.iter().filter(|text| text.contains("moved to a new link")).count();
    eprintln!("200 MiB each way through the node in {} s: {moves} moves", started.elapsed().as_secs());
    assert!(moves >= 6, "{moves} moves for 400 MiB through links of 64 MiB at most");

    let mut node = cleanup.node.take().unwrap();
    let _ = node.kill();
    let _ = node.wait();
    let (rc, _, err) = run(&home, &["relay", "revoke", "lab"]);
    assert_eq!(rc, 0, "{err}");
}
