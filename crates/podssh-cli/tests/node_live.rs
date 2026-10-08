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

/// Kills the node, and stops the pair, if a test ends early.
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
    let (banner, outcome) = runtime.block_on(async {
        let (io, mut user) = tokio::io::duplex(64 * 1024);
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
        let (outcome, banner) = tokio::join!(tokio::time::timeout(LIMIT, operator::run(&config, io)), read);
        (banner, outcome)
    });
    let outcome = outcome.expect("the session in time").expect("the operator's socket");
    eprintln!("through the node: {}; {outcome:?}", String::from_utf8_lossy(&banner).trim_end());
    assert!(banner.starts_with(b"SSH-2.0-"), "{:?}", String::from_utf8_lossy(&banner));
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
