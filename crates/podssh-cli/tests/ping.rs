//! `podssh ping` (T-053) as a process. A bad `--size`, `--count` or
//! `--target` refuses the run with 64 before anything connects, and
//! `PODSSH_OFFLINE` with 69. With `--direct` to the test's SSH server: the
//! login, the echo through `cat`, and the bytes down and up, each command
//! named, in lines and in one JSON document; a host with no `cat` ends with
//! its 127. Through the stand-in relay (`scripts/fake-relay.py`), a pong for
//! each ping, alone and with a destination; those checks say that they did
//! not run when this host has no Python or no openssl for the stand-in.

mod ssh_harness;
mod throughput_harness;

use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

/// The limit on each run of `podssh ping` here.
const LIMIT: Duration = Duration::from_secs(120);
const MIB: u64 = 1 << 20;

/// `podssh ping ARGS` with HOME and the cache in the session's scratch
/// directory, and no proxy: each end here is on the loopback.
fn ping(s: &Session, args: &[String]) -> Command {
    let mut all = vec!["ping".to_string()];
    all.extend(args.iter().cloned());
    let mut cmd = s.command(&all);
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
        cmd.env_remove(name);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

/// Run to the end, within [`LIMIT`]: the output, read directly.
fn ran(mut cmd: Command) -> Output {
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A listener on the loopback that counts its connections: a relay host
/// that must never be reached.
fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        for _ in listener.incoming() {
            counted.fetch_add(1, Ordering::SeqCst);
        }
    });
    (port, count)
}

/// The flags of a run to the test's server with `--direct`, with `extra`
/// before the destination `user@127.0.0.1`.
fn direct(s: &Session, extra: &[&str], user: &str) -> Vec<String> {
    let mut args = s.common();
    args.extend(["--direct", "-p", &s.port.to_string()].map(String::from));
    args.extend(extra.iter().map(|a| a.to_string()));
    args.push(format!("{user}@127.0.0.1"));
    args
}

/// The stand-in relay's flags, or `None` when it cannot run here.
fn relay_flags(s: &Session) -> Option<Vec<String>> {
    let cell = match Cell::fake_relay_mode(s, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let mut flags = vec!["--relay-host".to_string(), at("--relay-host"), "--ca-file".into(), at("--ca-file")];
    flags.extend(["--relay-addr".to_string(), "relay-a.test=127.0.0.1".into()]);
    Some(flags)
}

#[test]
fn bad_flags_are_refused_before_anything_connects() {
    let s = Session::start("ping-refuse");
    let (port, reached) = counting_listener();
    let relay = format!("127.0.0.1:{port}");
    let cases: [(&[&str], &str); 6] = [
        (&["--size", "40M"], "at most 30M"),
        (&["--size", "0"], "more than 0 bytes"),
        (&["--size", "lots"], "a number of bytes"),
        (&["--count", "0"], "from 1 to 100"),
        (&["--count", "101"], "from 1 to 100"),
        (&["--target", "example.org"], "missing PORT"),
    ];
    for (flags, says) in cases {
        let mut args: Vec<String> = flags.iter().map(|f| f.to_string()).collect();
        args.extend(["--relay-host".to_string(), relay.clone()]);
        let out = ran(ping(&s, &args));
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{flags:?}: {err}");
        assert!(err.contains(says), "{flags:?}: {err}");
        assert!(out.stdout.is_empty(), "{flags:?}: {}", text(&out.stdout));
    }
    // A target for a run that has no relay leg.
    let out = ran(ping(&s, &direct(&s, &["--target", "example.org:22"], "tester")));
    assert_eq!(out.status.code(), Some(64), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("--target"), "{}", text(&out.stderr));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(reached.load(Ordering::SeqCst), 0, "a refused run connected to the relay host");
    assert_eq!(s.connections.load(Ordering::SeqCst), 0, "a refused run connected to the SSH server");
}

#[test]
fn offline_connects_nowhere_and_exits_69() {
    let s = Session::start("ping-offline");
    let (port, reached) = counting_listener();
    let offline = |args: &[String]| {
        let mut cmd = ping(&s, args);
        cmd.env("PODSSH_OFFLINE", "1");
        ran(cmd)
    };
    let out = offline(&["--relay-host".to_string(), format!("127.0.0.1:{port}")]);
    assert_eq!(out.status.code(), Some(69), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("PODSSH_OFFLINE"), "{}", text(&out.stderr));
    let out = offline(&direct(&s, &[], "tester"));
    assert_eq!(out.status.code(), Some(69), "{}", text(&out.stderr));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    assert_eq!(s.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn direct_measures_the_login_the_echo_and_each_way() {
    let s = Session::start("ping-direct");
    let out = ran(ping(&s, &direct(&s, &["--size", "1M", "--count", "5"], "tester")));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 4, "{stdout}");
    assert!(lines[0].starts_with("ssh tester@127.0.0.1: login "), "{stdout}");
    assert!(lines[1].starts_with("echo (cat), 5 bytes: min "), "{stdout}");
    assert!(lines[2].starts_with(&format!("down (head -c {MIB} /dev/zero): 1.0 MiB in ")), "{stdout}");
    assert!(lines[3].starts_with("up (cat > /dev/null): 1.0 MiB in "), "{stdout}");
    assert!(!stdout.contains("relay"), "--direct has no relay leg: {stdout}");
}

#[test]
fn json_is_one_document_with_each_measure() {
    let s = Session::start("ping-json");
    let out = ran(ping(&s, &direct(&s, &["--size", "1M", "--count", "3", "--json"], "tester")));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(doc["schema"], 1);
    assert_eq!(doc["exit"], 0);
    assert_eq!(doc["size"], MIB);
    assert_eq!(doc["count"], 3);
    assert_eq!(doc["relays"], serde_json::json!([]));
    let far = &doc["destination"];
    assert_eq!(far["destination"], "tester@127.0.0.1");
    assert!(far["login_ms"].as_f64().is_some(), "{far}");
    for key in ["min_ms", "p50_ms", "p95_ms", "max_ms"] {
        assert!(far["echo"][key].as_f64().is_some(), "{key}: {far}");
    }
    assert_eq!(far["down"]["command"], format!("head -c {MIB} /dev/zero"));
    assert_eq!(far["up"]["command"], "cat > /dev/null");
    for way in ["down", "up"] {
        assert_eq!(far[way]["bytes"], MIB, "{way}: {far}");
        assert!(far[way]["seconds"].as_f64().is_some_and(|s| s > 0.0), "{way}: {far}");
    }
    assert!(far["error"].is_null(), "{far}");
}

#[test]
fn a_host_without_cat_ends_with_127() {
    let s = Session::start("ping-bare");
    let out = ran(ping(&s, &direct(&s, &["--size", "1M"], "bare-host")));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(127), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    assert!(stdout.contains("echo: cat: the host has no such program (exit 127)"), "{stdout}");
    assert!(!stdout.contains("down ("), "no measure runs after the echo failed: {stdout}");
}

#[test]
fn a_status_that_comes_before_the_servers_reply_is_kept() {
    let s = Session::start("ping-early");
    let out = ran(ping(&s, &direct(&s, &["--size", "1M"], "bare-early-host")));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(127), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    assert!(stdout.contains("echo: cat: the host has no such program (exit 127)"), "{stdout}");
}

#[test]
fn the_first_echo_which_waits_for_cat_to_start_is_not_counted() {
    let s = Session::start("ping-late");
    let out = ran(ping(&s, &direct(&s, &["--size", "64K", "--count", "3", "--json"], "late-host")));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    let max = doc["destination"]["echo"]["max_ms"].as_f64().expect("the echo's maximum");
    assert!(max < 1000.0, "the first echo, 1 s late, was counted: {max} ms");
}

#[test]
fn each_ping_through_the_stand_in_relay_gets_its_pong() {
    let s = Session::start("ping-relay");
    let Some(flags) = relay_flags(&s) else { return };
    let mut args = flags.clone();
    args.extend(["--target".to_string(), format!("127.0.0.1:{}", s.port), "--count".into(), "10".into()]);
    let out = ran(ping(&s, &args));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "one line for the one relay host: {stdout}");
    let line = lines[0];
    assert!(line.starts_with("relay relay-a.test:"), "{line}");
    for step in ["token minted ", "DNS and TCP ", "TLS ", &format!("upgrade to 127.0.0.1:{} ", s.port)] {
        assert!(line.contains(step), "{step:?}: {line}");
    }
    assert!(line.contains("; 10 pings: min "), "{line}");
    assert!(!line.contains("lost"), "{line}");
    // The second run takes the token from the cache.
    let out = ran(ping(&s, &args));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("token cached "), "{}", text(&out.stdout));
}

#[test]
fn json_through_the_stand_in_relay_has_each_step() {
    let s = Session::start("ping-relay-json");
    let Some(mut args) = relay_flags(&s) else { return };
    args.extend([
        "--target".to_string(),
        format!("127.0.0.1:{}", s.port),
        "--count".into(),
        "4".into(),
        "--json".into(),
    ]);
    let out = ran(ping(&s, &args));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    let leg = &doc["relays"][0];
    assert_eq!(leg["target"], format!("127.0.0.1:{}", s.port));
    assert_eq!(leg["token"], "minted");
    assert_eq!(leg["connect"], "DNS and TCP");
    for key in ["token_ms", "connect_ms", "tls_ms", "upgrade_ms"] {
        assert!(leg[key].as_f64().is_some(), "{key}: {leg}");
    }
    assert!(leg["pings"]["p95_ms"].as_f64().is_some(), "{leg}");
    assert_eq!(leg["pings_lost"], 0);
    assert!(leg["error"].is_null(), "{leg}");
    assert!(doc["destination"].is_null());
}

#[test]
fn no_relay_host_that_answers_exits_69() {
    let s = Session::start("ping-unavailable");
    // A port that nothing holds: the connection is refused at once.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let args = ["--relay-host".to_string(), format!("127.0.0.1:{port}"), "--count".into(), "2".into()];
    let mut cmd = ping(&s, &args);
    cmd.env("PODSSH_RELAY_TOKEN", "a-token-that-no-relay-sees");
    let out = ran(cmd);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(69), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    assert!(stdout.starts_with(&format!("relay 127.0.0.1:{port}: token from PODSSH_RELAY_TOKEN ")), "{stdout}");
    assert!(!stdout.contains("pings:"), "{stdout}");
}

#[test]
fn a_destination_through_the_stand_in_relay_is_measured_after_the_leg() {
    let s = Session::start("ping-relay-far");
    let Some(mut args) = relay_flags(&s) else { return };
    args.extend(["--target".to_string(), format!("127.0.0.1:{}", s.port)]);
    args.extend(s.common());
    args.extend(["--size", "1M", "--count", "3", "-p", &s.port.to_string(), "tester@127.0.0.1"].map(String::from));
    let out = ran(ping(&s, &args));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "{stdout}");
    assert!(lines[0].contains("; 3 pings: min "), "{stdout}");
    assert!(lines[1].starts_with("ssh tester@127.0.0.1: login "), "{stdout}");
    assert!(lines[4].starts_with("up (cat > /dev/null): 1.0 MiB in "), "{stdout}");
}
