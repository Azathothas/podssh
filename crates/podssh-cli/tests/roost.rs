//! A roost (T-166): `podssh node NAME [TARGET] --sshd`, a node in front of a
//! standard sshd. Before it registers, the roost reads TARGET's first line,
//! which must be SSH's version line: a port with nothing on it, a server that
//! answers `HTTP/1.1`, and one that says nothing make it exit, naming TARGET,
//! with no connection to the relay. The relay of these pairs is a port here
//! that counts its connections, so a registration is seen; a roost with no
//! preflight would register, and fail them. Through the stand-in relay of
//! the reverse road (Python and openssl), a roost carries `podssh ssh
//! node://` to the tests' SSH server, and a TARGET that stops answering as
//! sshd refuses the next session with the reason; each of those says that it
//! did not run when this host has neither.

mod pair_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pair_harness::{no_token, CONNECT, NAME, NODE, STOP};
use podssh_relay::pair;
use podssh_relay::relay::Relay;
use throughput_harness::{lines_of, wait_for, Cell, Session};

/// The name of the counting relay, pinned to the loopback.
const RELAY: &str = "relay-roost.test";
/// The bound on a roost that should end by itself: the check's 10 s and
/// more.
const END_LIMIT: Duration = Duration::from_secs(30);

/// A port that stands for the relay: it counts each connection, and drops
/// it.
struct Counted {
    port: u16,
    seen: Arc<AtomicUsize>,
}

fn counted() -> Counted {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    Counted { port, seen }
}

/// A TCP service that writes `first` to its first connection and `later` to
/// each other, and keeps each open for a while: its port and its count.
fn service(first: &'static str, later: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            let words = if counted.fetch_add(1, Ordering::SeqCst) == 0 { first } else { later };
            let _ = stream.write_all(words.as_bytes());
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(20));
                drop(stream);
            });
        }
    });
    (port, count)
}

/// A port of the loopback with nothing on it: bound, then let go.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// The test pair under the label lab, whose relay is `relay`.
fn store_pair(s: &Session, relay: &Counted) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let body = format!(
        r#"{{"name":"{NAME}","node_token":"{NODE}","connect_token":"{CONNECT}","stop_token":"{STOP}","expires":{}}}"#,
        now + 72 * 3600 * 1000
    );
    let pair = pair::parse(&Relay { host: RELAY.into(), port: relay.port }, body.as_bytes(), now).expect("a pair");
    let cache = s.home.join("cache");
    podssh_relay::cache::private_dir(&cache).unwrap();
    pair::store_in_first(&[cache.join("podssh")], "lab", &pair).expect("stored");
}

/// `podssh node lab WORDS --sshd`, its relay pinned to the counting port, and
/// no proxy, so that a registration reaches that port.
fn spawn_roost(s: &Session, words: &[String]) -> Child {
    let mut args = vec!["node".to_string(), "lab".into()];
    args.extend(words.iter().cloned());
    args.extend(["--sshd".to_string(), "--relay-addr".into(), format!("{RELAY}=127.0.0.1")]);
    let mut cmd = s.command(&args);
    for name in ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "PODSSH_RELAY_ADDR"] {
        cmd.env_remove(name);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs")
}

/// A roost that should end before it registers: its code, stdout and
/// stderr; -1 when it was still running after [`END_LIMIT`], and was ended.
fn roost_ends(s: &Session, words: &[String]) -> (i32, String, String) {
    let mut child = spawn_roost(s, words);
    let deadline = Instant::now() + END_LIMIT;
    let mut late = false;
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            late = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("output");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let code = if late { -1 } else { out.status.code().unwrap_or(-1) };
    (code, text(&out.stdout), text(&out.stderr))
}

#[test]
fn a_roost_with_nothing_at_target_exits_before_it_registers() {
    let s = Session::start("roost-none");
    let relay = counted();
    store_pair(&s, &relay);
    let port = closed_port();
    let (rc, out, err) = roost_ends(&s, &[format!("127.0.0.1:{port}")]);
    assert_eq!(rc, 69, "{err}");
    assert!(err.contains(&format!("TARGET 127.0.0.1:{port}")), "the roost names TARGET: {err}");
    assert!(out.is_empty(), "stdout: {out:?}");
    assert_eq!(relay.seen.load(Ordering::SeqCst), 0, "the roost reached the relay: {err}");
    no_token(&format!("{out}{err}"));
}

#[test]
fn a_roost_in_front_of_another_service_exits_with_its_first_line() {
    let s = Session::start("roost-http");
    let relay = counted();
    store_pair(&s, &relay);
    let http = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
    let (port, dialled) = service(http, http);
    let (rc, out, err) = roost_ends(&s, &[format!("127.0.0.1:{port}")]);
    assert_eq!(rc, 78, "another service is a TARGET set up wrong: {err}");
    assert!(err.contains(&format!("TARGET 127.0.0.1:{port} is not an SSH server")), "{err}");
    assert!(err.contains("\"HTTP/1.1 400 Bad Request\""), "the roost says what came back: {err}");
    assert!(out.is_empty(), "stdout: {out:?}");
    assert_eq!(dialled.load(Ordering::SeqCst), 1, "TARGET is dialled once: {err}");
    assert_eq!(relay.seen.load(Ordering::SeqCst), 0, "the roost reached the relay: {err}");
    no_token(&format!("{out}{err}"));
}

#[test]
fn a_roost_whose_target_says_nothing_exits_after_10_s() {
    let s = Session::start("roost-silent");
    let relay = counted();
    store_pair(&s, &relay);
    let (port, _) = service("", "");
    let started = Instant::now();
    let (rc, _, err) = roost_ends(&s, &[format!("127.0.0.1:{port}")]);
    assert_eq!(rc, 69, "{err}");
    assert!(err.contains("sent no line within 10 s"), "{err}");
    assert!(started.elapsed() >= Duration::from_secs(10), "the roost waits 10 s for the line");
    assert_eq!(relay.seen.load(Ordering::SeqCst), 0, "the roost reached the relay: {err}");
}

/// The control: an SSH server at TARGET (the tests' own, of russh) passes,
/// the first line names its version line, and the roost goes on to the
/// relay. Without it, each check above could pass for a roost that never
/// registers.
#[test]
fn a_roost_in_front_of_an_ssh_server_goes_on_to_the_relay() {
    let s = Session::start("roost-ssh");
    let relay = counted();
    store_pair(&s, &relay);
    let mut child = spawn_roost(&s, &[format!("127.0.0.1:{}", s.port)]);
    let lines = lines_of(&mut child);
    s.keep(child);
    let first = wait_for(&lines, "serving").expect("the roost starts");
    assert!(first.contains(&format!("serving the sshd 127.0.0.1:{} (SSH-2.0-", s.port)), "{first}");
    let deadline = Instant::now() + END_LIMIT;
    while relay.seen.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "the roost did not reach the relay");
        std::thread::sleep(Duration::from_millis(50));
    }
    // The preflight's connection, and no session's yet.
    assert_eq!(s.connections.load(Ordering::SeqCst), 1);
}

/// With no TARGET, a roost serves the sshd of this host: whatever is at
/// 127.0.0.1:22 here, the roost names it.
#[test]
fn a_roost_with_no_target_is_in_front_of_port_22() {
    let s = Session::start("roost-22");
    let relay = counted();
    store_pair(&s, &relay);
    let mut child = spawn_roost(&s, &[]);
    let lines = lines_of(&mut child);
    s.keep(child);
    wait_for(&lines, "127.0.0.1:22").expect("the roost names 127.0.0.1:22");
}

/// A pair on the stand-in relay, and a roost of it in front of TARGET: the
/// command for each run of podssh, with the relay's pins and trust, and the
/// roost's lines; `None` when this host cannot run the stand-in.
#[allow(clippy::type_complexity)]
fn through_the_stand_in(
    s: &Session,
    target: u16,
) -> Option<(impl Fn(&[String]) -> std::process::Command + '_, std::sync::mpsc::Receiver<String>)> {
    let cell = match Cell::fake_relay_mode(s, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let command = move |args: &[String]| {
        // The pins go before a command's words, as `ssh` takes each word
        // after its destination for the remote command.
        let mut cmd = s.command(&args[..1]);
        cmd.env("SSL_CERT_FILE", &ca).args(["--relay-addr", "relay-a.test=127.0.0.1"]).args(&args[1..]);
        cmd
    };
    let words = ["relay", "pair", "lab", "--relay-host", relay.as_str()].map(String::from);
    let out = command(&words).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let target = format!("127.0.0.1:{target}");
    let words = ["node", "lab", target.as_str(), "--sshd"].map(String::from);
    let mut node = command(&words).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    Some((command, lines))
}

#[test]
fn a_roost_carries_ssh_to_its_sshd_and_keeps_the_key_under_its_name() {
    let s = Session::start("roost-stand-in");
    let Some((command, lines)) = through_the_stand_in(&s, s.port) else { return };
    let first = wait_for(&lines, "serving").expect("the roost starts");
    assert!(first.contains("with the resumable layer") && first.contains("(SSH-2.0-"), "{first}");
    // The relay has the node's socket only from this line on.
    wait_for(&lines, "online").expect("the roost is online");
    let mut args = vec!["ssh".to_string()];
    args.extend(s.common());
    args.extend(["node://tester@lab".to_string(), "greet".into()]);
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), ssh_harness::GREETING, "{err}");
    // The roost's preflight, then one connection for the session.
    assert_eq!(s.connections.load(Ordering::SeqCst), 2, "{err}");
    let known = std::fs::read_to_string(s.home.join("known_hosts")).unwrap_or_default();
    assert!(known.contains("node://lab") || err.contains("node://lab"), "sshd's key, under the roost's name: {known}");
}

#[test]
fn a_target_that_stops_answering_as_sshd_refuses_the_next_session() {
    let s = Session::start("roost-changed");
    let (port, dialled) = service("SSH-2.0-roost-test\r\n", "HTTP/1.1 400 Bad Request\r\n\r\n");
    let Some((command, lines)) = through_the_stand_in(&s, port) else { return };
    wait_for(&lines, "online").expect("the roost is online");
    let out = command(&["operator".to_string(), "lab".into()]).stdin(Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{err}");
    assert!(out.stdout.is_empty(), "no byte of TARGET: {:?}", out.stdout);
    assert!(err.contains(&format!("127.0.0.1:{port} is not an SSH server")), "{err}");
    assert!(err.contains("HTTP/1.1 400 Bad Request"), "{err}");
    // The preflight, and the session's own dial after its handshake.
    assert_eq!(dialled.load(Ordering::SeqCst), 2, "{err}");
}
