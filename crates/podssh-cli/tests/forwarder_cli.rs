//! `--forwarder` (T-369) as a process: `podssh ssh`, `podssh proxy` and
//! `podssh doctor` through stand-ins of WebSocket forwarders
//! (`forwarder_support`), behind a proxy that re-terminates TLS with the
//! test's own CA (`cloud_support`), to the test's SSH server on the
//! loopback (`ssh_harness`). Through a stand-in of each form, 1 MiB each way
//! comes back with an equal digest; a forwarder that closes gives way to the
//! next and is named; no request carries a token, and no relay host is
//! asked; each road that cannot go with a forwarder, and a template or a
//! target that cannot go, is refused before anything connects.

mod cloud_support;
mod forwarder_support;
mod ssh_harness;

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cloud_support::{command, scratch, Proxy, Scratch};
use forwarder_support::Stands;
use sha2::{Digest, Sha256};

// A run of doctor takes tens of seconds through the proxy.
const LIMIT: Duration = Duration::from_secs(120);
const MIB: usize = 1 << 20;
const QUERY: &str = "wss://fwd-query.test/?host={host}&port={port}";
const FRAME: &str = "wss://fwd-frame.test/p";

/// The test's SSH server, the stand-ins and the proxy in front of them.
struct World {
    dir: Scratch,
    sshd: u16,
    proxy: Proxy,
    stands: Arc<Stands>,
    // Dropped last: the server and the stand-ins run on it.
    _runtime: tokio::runtime::Runtime,
}

fn world(name: &str) -> World {
    let dir = scratch(&format!("forwarder-{name}"));
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let sshd = runtime.block_on(ssh_harness::start(&key));
    let stands = Stands::new(sshd);
    let proxy = runtime.block_on(Proxy::start(&dir, stands.handler()));
    World { dir, sshd, proxy, stands, _runtime: runtime }
}

/// `podssh ARGS` through the world's proxy, with no road of the
/// environment, no settings file and a cache of its own, and `set`.
fn podssh(w: &World, args: &[String], set: &[(&str, &str)]) -> Command {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut cmd = command(&w.dir, &args, Some(&w.proxy), &[]);
    for name in [
        "PODSSH_FORWARDER",
        "PODSSH_FORWARDER_FALLBACK",
        "PODSSH_RELAY",
        "PODSSH_RELAY_FAILOVER",
        "PODSSH_RELAY_ADDR",
        "PODSSH_RELAY_TOKEN",
        "PODSSH_SESSION_LOG",
        "SSH_AUTH_SOCK",
    ] {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_SETTINGS", "none").env("PODSSH_CACHE_DIR", w.dir.join("cache"));
    for (name, value) in set {
        cmd.env(name, value);
    }
    cmd
}

/// `podssh ssh` to the test's server with `road`, running `remote`.
fn ssh(w: &World, road: &[&str], remote: &str) -> Vec<String> {
    let known = format!("UserKnownHostsFile={}", w.dir.join("known_hosts").display());
    let mut args: Vec<String> =
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"].map(String::from).to_vec();
    args.push(known);
    args.extend(["--ca-file".to_string(), w.proxy.ca_file.display().to_string(), "-p".into(), w.sshd.to_string()]);
    args.extend(road.iter().map(|s| s.to_string()));
    args.extend(["u@127.0.0.1".to_string(), remote.to_string()]);
    args
}

/// Run `cmd` with `input` on its stdin, within the limit: its exit code,
/// its stdout and its stderr.
fn run(mut cmd: Command, input: Vec<u8>) -> (Option<i32>, Vec<u8>, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut all = Vec::new();
        let _ = stdout.read_to_end(&mut all);
        all
    });
    let mut stderr = child.stderr.take().unwrap();
    let err = std::thread::spawn(move || {
        let mut all = String::new();
        let _ = stderr.read_to_string(&mut all);
        all
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("podssh still ran after {LIMIT:?}: {}", err.join().unwrap());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = writer.join();
    (code, out.join().unwrap(), err.join().unwrap())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn mebibyte() -> Vec<u8> {
    (0..MIB as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

/// No stand-in saw a token, and no relay host was asked through the proxy.
fn no_token_and_no_relay(w: &World) {
    for seen in w.stands.seen.lock().unwrap().iter() {
        let names: Vec<&str> = seen.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(!names.contains(&"x-relay-token") && !names.contains(&"authorization"), "{names:?}");
    }
    let connects = w.proxy.connects.lock().unwrap().clone();
    assert!(connects.iter().all(|c| !c.contains("relay.ajam.dev")), "{connects:?}");
}

#[test]
fn each_form_carries_a_session_a_mebibyte_each_way() {
    let w = world("forms");
    for template in [QUERY, FRAME] {
        let data = mebibyte();
        let (code, out, err) = run(podssh(&w, &ssh(&w, &["--forwarder", template], "echo"), &[]), data.clone());
        assert_eq!(code, Some(0), "{template}: {err}");
        assert_eq!(out.len(), MIB, "{template}: {err}");
        assert_eq!(digest(&out), digest(&data), "{template}: equal digests");
    }
    let seen = w.stands.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].path, format!("/?host=127.0.0.1&port={}", w.sshd));
    assert_eq!((seen[1].path.as_str(), seen[1].target.1), ("/p", w.sshd));
    assert_eq!(seen[1].first_frame.as_deref(), Some(format!(r#"{{"Host":"127.0.0.1","Port":{}}}"#, w.sshd).as_str()));
    no_token_and_no_relay(&w);
}

#[test]
fn a_forwarder_that_closes_gives_way_to_the_next_and_is_named() {
    let w = world("closes");
    let list = format!("wss://fwd-close.test/?host={{host}}&port={{port}},{QUERY}");
    let (code, out, err) = run(podssh(&w, &ssh(&w, &["--forwarder", &list], "greet"), &[]), Vec::new());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out), ssh_harness::GREETING);
    let said = format!(
        "the forwarder wss://fwd-close.test/ closed the WebSocket before the target's bytes: 1011 Proxy: connect to \
         127.0.0.1:{} failed: refused",
        w.sshd
    );
    assert!(err.contains(&said), "{err}");
    assert_eq!(w.stands.hosts(), ["fwd-close.test", "fwd-query.test"], "in order");
    no_token_and_no_relay(&w);
}

#[test]
fn each_road_and_each_template_that_cannot_go_is_refused_before_anything_connects() {
    let w = world("refused");
    let cases: Vec<(Vec<&str>, Vec<(&str, &str)>, i32, &str)> = vec![
        (vec!["--forwarder", "wss://f.test/?host={host}"], vec![], 64, "--forwarder: a forwarder's template has"),
        (vec!["--forwarder", "wss://f.test/{port}?h={host}&p={port}"], vec![], 64, "{port} 2 times"),
        (vec!["--forwarder", QUERY, "--direct"], vec![], 64, "--forwarder cannot go with --direct"),
        (vec!["--forwarder", QUERY, "--relay-host", "r.test"], vec![], 64, "--forwarder and --relay-host name two roads"),
        (vec!["--forwarder", QUERY, "-4"], vec![], 64, "-4 and -6 choose the family"),
        (vec![], vec![("PODSSH_FORWARDER", "nope")], 78, "PODSSH_FORWARDER: "),
        (vec![], vec![("PODSSH_FORWARDER", QUERY), ("PODSSH_RELAY", "r.test")], 78, "name two roads"),
    ];
    for (road, set, want, says) in cases {
        let (code, _, err) = run(podssh(&w, &ssh(&w, &road, "greet"), &set), Vec::new());
        assert_eq!(code, Some(want), "{road:?} {set:?}: {err}");
        assert!(err.contains(says), "{road:?} {set:?}: {err}");
    }
    // A destination with a road of its own, which takes no -p.
    let node = ["ssh", "-o", "BatchMode=yes", "--forwarder", QUERY, "node://u@n", "greet"];
    let node: Vec<String> = node.map(String::from).to_vec();
    let (code, _, err) = run(podssh(&w, &node, &[]), Vec::new());
    assert_eq!(code, Some(64), "{err}");
    assert!(err.contains("--forwarder cannot go with a node:// destination"), "{err}");
    assert!(w.proxy.connects.lock().unwrap().is_empty(), "nothing was dialed");
}

#[test]
fn proxy_carries_the_pipe_and_refuses_a_target_that_cannot_go() {
    let w = world("proxy");
    let ca = w.proxy.ca_file.display().to_string();
    let args: Vec<String> =
        ["proxy", "--forwarder", QUERY, "--ca-file", &ca, "127.0.0.1", &w.sshd.to_string()].map(String::from).to_vec();
    let mut cmd = podssh(&w, &args, &[]);
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let banner = std::thread::spawn(move || {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\r\n") && stdout.read(&mut byte).unwrap_or(0) == 1 {
            line.push(byte[0]);
        }
        line
    });
    let started = Instant::now();
    while !banner.is_finished() && started.elapsed() < LIMIT {
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    let line = banner.join().unwrap();
    assert!(line.starts_with(b"SSH-2.0-"), "the server's banner through the forwarder: {line:?}");
    for (target, says) in [("a&b", "not a host name"), ("cf://h", "--forwarder cannot go with cf://")] {
        let args: Vec<String> = ["proxy", "--forwarder", QUERY, target, "22"].map(String::from).to_vec();
        let (code, _, err) = run(podssh(&w, &args, &[]), Vec::new());
        assert_eq!(code, Some(64), "{target}: {err}");
        assert!(err.contains(says), "{target}: {err}");
    }
    assert_eq!(w.stands.hosts(), ["fwd-query.test"], "the refused targets dialed nothing");
    no_token_and_no_relay(&w);
}

/// A process of the test, killed when the test ends, also by a panic.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// websockify, software that podssh did not write, as a forwarder whose
/// target is fixed on its command line: the query of the template is
/// ignored, and the session's bytes pass as binary frames (Inferred from
/// its documents). It says that it did not run where there is none.
#[test]
fn through_websockify_the_session_s_bytes_pass() {
    let here = Command::new("websockify").arg("--help").stdout(Stdio::null()).stderr(Stdio::null()).status();
    if !here.is_ok_and(|s| s.success()) {
        eprintln!("did not run: no websockify here (pip install websockify)");
        return;
    }
    let w = world("websockify");
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut cmd = Command::new("websockify");
    cmd.args([format!("127.0.0.1:{port}"), format!("127.0.0.1:{}", w.sshd)]);
    let _websockify = Running(cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let started = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(started.elapsed() < LIMIT, "websockify did not listen");
        std::thread::sleep(Duration::from_millis(50));
    }
    let template = format!("ws://127.0.0.1:{port}/?host={{host}}&port={{port}}");
    let data = mebibyte();
    let (code, out, err) = run(podssh(&w, &ssh(&w, &["--forwarder", &template], "echo"), &[]), data.clone());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(digest(&out), digest(&data), "equal digests through websockify");
}

/// `doctor --forwarder`: the upgrade, then github.com port 22 through the
/// stand-in, which reaches the test's server: its key is none of GitHub's,
/// and the line says so, with the forwarder's name.
#[test]
fn doctor_checks_each_forwarder_through_github_s_port() {
    let w = world("doctor");
    let ca = w.proxy.ca_file.display().to_string();
    let args: Vec<String> = ["doctor", "--forwarder", QUERY, "--ca-file", &ca].map(String::from).to_vec();
    let (code, out, err) = run(podssh(&w, &args, &[]), Vec::new());
    let text = String::from_utf8_lossy(&out);
    assert_eq!(code, Some(1), "{text}{err}");
    let line = text.lines().find(|l| l.contains(" forwarder ")).unwrap_or_else(|| panic!("{text}"));
    let named = "github.com:22 through the forwarder wss://fwd-query.test/: ED25519 host key SHA256:";
    assert!(line.contains(named), "{line}");
    assert!(line.starts_with("  FAIL  forwarder") && line.contains("not in podssh's list of GitHub's keys"), "{line}");
    let seen = w.stands.seen.lock().unwrap().clone();
    assert_eq!(seen[0].target, ("github.com".to_string(), 22), "the stand-in was asked for GitHub's port");
}
