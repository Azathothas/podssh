//! `podssh relay` and `podssh node` against the live relay (T-083), on request
//! only: `cargo test -p podssh-cli --test node_live -- --ignored`. The binary
//! makes a pair and runs a node in front of GitHub's SSH server; an operator
//! session that holds the operator's file alone reads GitHub's banner through
//! the node; then the binary stops the pair. No test prints a token.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use podssh_relay::relay::parse_relay;
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome, Wire};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: Duration = Duration::from_secs(60);

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-node-live-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, on the network.
fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args);
    for name in ["PODSSH_RELAY", "PODSSH_RELAY_ADDR", "PODSSH_RELAY_TOKEN", "PODSSH_OFFLINE"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

fn run(home: &Path, args: &[&str]) -> (i32, String, String) {
    let mut child = command(home, args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < deadline, "podssh {args:?} did not end in time");
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("output");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// Kills the node and stops the pair, if a test ends early, and deletes the
/// scratch directory, with its throwaway key, in each case.
struct Cleanup<'a> {
    home: &'a Path,
    node: Option<Child>,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if let Some(mut node) = self.node.take() {
            let _ = node.kill();
            let _ = node.wait();
        }
        if self.home.join("cache").join("podssh").join("pair-lab.json").exists() {
            let _ = run(self.home, &["relay", "revoke", "lab"]);
        }
        let _ = std::fs::remove_dir_all(self.home);
    }
}

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
    let stderr = node.stderr.take().unwrap();
    cleanup.node = Some(node);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let first = rx.recv_timeout(LIMIT).expect("the node says what it serves");
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
        let carry = podssh_cli::layered::carry(&config, link, first, app, &say);
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

/// The node's stderr, a line at a time.
fn lines_of(node: &mut Child) -> mpsc::Receiver<String> {
    let stderr = node.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
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
    let (tx, rx) = mpsc::channel();
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
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in echo.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut reader = stream.try_clone().unwrap();
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
            });
        }
    });

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
        let carry = podssh_cli::layered::carry(&config, link, first, app, &say);
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
