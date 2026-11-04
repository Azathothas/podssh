//! `podssh relay status` with no NAME, `info` and `trace` (T-058) as
//! processes. A bad target or a misplaced `--json` refuses the run with 64
//! before anything connects, and `PODSSH_OFFLINE` with 69. Through the
//! stand-in relay (`scripts/fake-relay.py`): the `/health` of each host,
//! the pool and the limits of `/relays.json`, and the trace of a target
//! with the token in its header, its first line and the relay's refusal to
//! dial; and a pair's state and expiry from an operator's file, on a host
//! that stores no pair, and the words of `pair` on the way past the expiry
//! (T-591). Those checks say that they did not run when this host has no
//! Python or no openssl for the stand-in.

// The signed list of deployments of podssh's relay role (T-346).
mod relay_signed;
mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(120);

/// `podssh relay ARGS` with HOME and the cache in the session's scratch
/// directory, and no proxy and no token from this host's environment.
fn relay(s: &Session, args: &[String]) -> Command {
    relay_at(&s.home, args)
}

/// [`relay`] with HOME and the cache under `home`: another host's.
fn relay_at(home: &std::path::Path, args: &[String]) -> Command {
    let mut all = vec!["relay".to_string()];
    all.extend(args.iter().cloned());
    let mut cmd = throughput_harness::command_in(home, &all);
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
        cmd.env_remove(name);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

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

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| w.to_string()).collect()
}

/// A relay host that must never be reached: it counts its connections.
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

/// A port of the loopback that nothing holds, for a moment.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A target that greets each connection with one line, then closes.
fn banner_target(line: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            let _ = stream.write_all(line.as_bytes());
        }
    });
    port
}

/// What the relay under test says of itself: the stand-in's words, or those
/// of podssh's own relay role with `PODSSH_RELAY_UNDER_TEST=podssh` (T-169).
struct Who {
    version: String,
    edge: Option<&'static str>,
    pool: &'static str,
    road: &'static str,
}

fn who() -> Who {
    if std::env::var("PODSSH_RELAY_UNDER_TEST").as_deref() == Ok("podssh") {
        Who { version: format!("podssh {}", env!("CARGO_PKG_VERSION")), edge: None, pool: "podssh", road: "direct" }
    } else {
        Who { version: "fake".into(), edge: Some("TEST"), pool: "stand-in", road: "loopback" }
    }
}

/// The stand-in relay's flags, its host, or `None` when it cannot run here.
fn stand_in(s: &Session) -> Option<(Vec<String>, String)> {
    let cell = match Cell::fake_relay_mode(s, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let host = at("--relay-host");
    let flags = vec!["--ca-file".into(), at("--ca-file"), "--relay-addr".into(), "relay-a.test=127.0.0.1".into()];
    Some((flags, host))
}

#[test]
fn bad_targets_and_a_misplaced_json_are_refused_before_anything_connects() {
    let s = Session::start("relay-refuse");
    let (port, reached) = counting_listener();
    let host = format!("127.0.0.1:{port}");
    let cases: [(&[&str], &str); 9] = [
        (&["trace"], "missing HOST"),
        (&["trace", "a&b", "22"], "trace"),
        (&["trace", "github.com", "0"], "is not a port"),
        (&["trace", "github.com", "99999"], "is not a port"),
        (&["info", "github.com"], "missing PORT"),
        (&["trace", "github.com", "22", "extra"], "one word too many"),
        (&["pair", "lab", "--json"], "--json goes with"),
        (&["spec", "--json"], "--json goes with"),
        (&["pair", "lab", "--pair-file", "lab.json"], "--pair-file goes with"),
    ];
    for (args, says) in cases {
        let mut all = words(args);
        all.extend(["--relay-host".to_string(), host.clone()]);
        let out = ran(relay(&s, &all));
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(reached.load(Ordering::SeqCst), 0, "a refused run connected to the relay host");
}

#[test]
fn offline_asks_nothing_and_exits_69() {
    let s = Session::start("relay-offline");
    let (port, reached) = counting_listener();
    for args in [&["status"][..], &["info"], &["trace", "github.com", "22"]] {
        let mut all = words(args);
        all.extend(["--relay-host".to_string(), format!("127.0.0.1:{port}")]);
        let mut cmd = relay(&s, &all);
        cmd.env("PODSSH_OFFLINE", "1");
        let out = ran(cmd);
        assert_eq!(out.status.code(), Some(69), "{args:?}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains("PODSSH_OFFLINE"), "{args:?}: {}", text(&out.stderr));
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

#[test]
fn status_asks_each_host_and_needs_one_answer() {
    let s = Session::start("relay-status");
    let Some((flags, host)) = stand_in(&s) else { return };
    let dead = format!("127.0.0.1:{}", free_port());
    let mut args = words(&["status", "--relay-host"]);
    args.push(format!("{host},{dead}"));
    args.extend(flags.iter().cloned());
    let out = ran(relay(&s, &args));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    let w = who();
    let edge = w.edge.map(|e| format!(" at edge {e}")).unwrap_or_default();
    assert!(lines[0].starts_with(&format!("relay-a.test: tcp-ssh-relay {}{edge}, ", w.version)), "{stdout}");
    assert!(lines[0].contains("certificate verified for relay-a.test; opened TCP 127.0.0.1:"), "{stdout}");
    assert!(lines[1].starts_with("127.0.0.1: "), "{stdout}");
    // Only the host that is down: none answers.
    let mut args = words(&["status", "--relay-host", &dead]);
    args.extend(flags.iter().cloned());
    let out = ran(relay(&s, &args));
    assert_eq!(out.status.code(), Some(69), "{}", text(&out.stdout));
    assert!(text(&out.stderr).contains("no relay host answered"), "{}", text(&out.stderr));
}

#[test]
fn status_json_is_one_document() {
    let s = Session::start("relay-status-json");
    let Some((flags, host)) = stand_in(&s) else { return };
    let mut args = words(&["status", "--json", "--relay-host", &host]);
    args.extend(flags);
    let out = ran(relay(&s, &args));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(doc["schema"], 1);
    assert_eq!(doc["exit"], 0);
    let first = &doc["hosts"][0];
    assert_eq!(first["host"], "relay-a.test");
    assert_eq!(first["ok"], true);
    let w = who();
    assert_eq!(first["version"], serde_json::json!(w.version));
    assert_eq!(first["edge"], serde_json::json!(w.edge));
    assert!(first["ms"].as_u64().is_some(), "{first}");
}

#[test]
fn info_gives_the_pool_the_limits_and_the_url_for_a_target() {
    let s = Session::start("relay-info");
    let Some((flags, host)) = stand_in(&s) else { return };
    let mut args = words(&["info", "127.0.0.1", "2222", "--relay-host", &host]);
    args.extend(flags.iter().cloned());
    let out = ran(relay(&s, &args));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    let lines: Vec<&str> = stdout.lines().collect();
    let w = who();
    let edge = w.edge.map(|e| format!("; this host reaches it at edge {e}")).unwrap_or_default();
    assert_eq!(lines[0], format!("relay relay-a.test: tcp-ssh-relay {}{edge}", w.version), "{stdout}");
    assert_eq!(lines[1], format!("for 127.0.0.1:2222: wss://{host}/connect/127.0.0.1/2222"), "{stdout}");
    let from = w.edge.map(|e| format!("edge {e}")).unwrap_or_else(|| "the edge that answered".into());
    assert_eq!(
        lines[2],
        format!(
            "pool, in the relay's order: 1 hosts; the rank and the score are the relay's estimate from {from}, \
             which changes with the edge, not a measure of this host's path"
        ),
        "{stdout}"
    );
    assert!(lines[3].contains(w.pool) && lines[3].contains("relay-a.test"), "{stdout}");
    assert!(lines[4].starts_with("measured from this host: podssh relay status"), "{stdout}");
    assert_eq!(
        lines[5],
        "limits: connect 10 s, idle 3 min, a session 12 h, a session 64 MiB, a frame 256 KiB, UDP unsupported",
        "{stdout}"
    );
    let mut args = words(&["info", "--json", "--relay-host", &host]);
    args.extend(flags);
    let out = ran(relay(&s, &args));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(doc["relay"], "relay-a.test");
    assert_eq!(doc["info"]["limits"]["max_frame_bytes"], 262144);
    assert!(doc["info"]["target"].is_null(), "no target was given: {doc}");
    assert_eq!(doc["pool_order"]["by"], "relay", "{doc}");
    assert_eq!(doc["pool_order"]["measured_here"], false, "{doc}");
}

#[test]
fn trace_sends_the_token_and_gives_the_targets_first_line() {
    let s = Session::start("relay-trace");
    let Some((flags, host)) = stand_in(&s) else { return };
    let target = banner_target("SSH-2.0-stand-in-target\r\n");
    let mut args = words(&["trace", "127.0.0.1", &target.to_string(), "--relay-host", &host]);
    args.extend(flags.iter().cloned());
    let out = ran(relay(&s, &args));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    let lines: Vec<&str> = stdout.lines().collect();
    let w = who();
    let edge = w.edge.map(|e| format!(", edge {e}")).unwrap_or_default();
    let head =
        format!("trace 127.0.0.1:{target} through relay-a.test ({}{edge}): live; road {}, dialed", w.version, w.road);
    assert!(lines[0].starts_with(&head), "{stdout}");
    assert!(lines[0].ends_with("25 bytes seen"), "{stdout}");
    assert_eq!(lines[1], "banner: SSH-2.0-stand-in-target", "{stdout}");
    // One word, HOST:PORT, and the JSON, which holds no field of the caller.
    let mut args = words(&["trace", &format!("127.0.0.1:{target}"), "--json", "--relay-host", &host]);
    args.extend(flags);
    let out = ran(relay(&s, &args));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(doc["target"]["banner"], "SSH-2.0-stand-in-target");
    assert_eq!(doc["edge"], serde_json::json!(w.edge));
    assert!(doc.get("request").is_none(), "{doc}");
}

#[test]
fn a_target_that_the_relay_cannot_dial_is_69() {
    let s = Session::start("relay-trace-closed");
    let Some((mut args, host)) = stand_in(&s) else { return };
    let closed = free_port();
    args.extend(words(&["trace", "127.0.0.1", &closed.to_string(), "--relay-host", &host]));
    let out = ran(relay(&s, &args));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(69), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    assert!(stdout.contains(&format!("trace 127.0.0.1:{closed} through relay-a.test")), "{stdout}");
    assert!(stdout.contains("the relay did not dial it: refused: cannot reach"), "{stdout}");
}

/// A relay host behind a proxy that speaks only TLS 1.2 (T-067): its
/// `/health`, a token, a trace, and an SSH session through a WebSocket,
/// each over TLS 1.2.
#[test]
fn a_relay_that_speaks_only_tls12_is_reached_with_tls12() {
    let s = Session::start("relay-tls12");
    let cell = match Cell::fake_relay_mode(&s, "tls12", "the stand-in relay, TLS 1.2 alone") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let flags = vec!["--ca-file".to_string(), at("--ca-file"), "--relay-addr".into(), "relay-a.test=127.0.0.1".into()];
    let mut args = words(&["status", "--relay-host", &at("--relay-host")]);
    args.extend(flags.iter().cloned());
    let out = ran(relay(&s, &args));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    assert!(stdout.contains("; TLS 1.2, certificate verified for relay-a.test;"), "{stdout}");
    let target = banner_target("SSH-2.0-behind-tls12\r\n");
    let mut args = words(&["trace", "127.0.0.1", &target.to_string(), "--relay-host", &at("--relay-host")]);
    args.extend(flags);
    let out = ran(relay(&s, &args));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("banner: SSH-2.0-behind-tls12"), "{}", text(&out.stdout));
    let mut ssh = cell.args.clone();
    ssh.push("greet".into());
    let mut cmd = s.command(&ssh);
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        cmd.env_remove(name);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = ran(cmd);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), ssh_harness::GREETING);
}

/// T-591: the operator's host holds the operator's part of a pair alone, in
/// a file, and stores none; `status --pair-file FILE` names online or
/// offline and the expiry, NAME is only the label shown, and `--json` gives
/// one object with `seconds_left`. With no file, that host has no pair (78).
#[test]
fn relay_status_of_an_operator_s_file_names_the_expiry() {
    let s = Session::start("relay-status-file");
    let Some((flags, host)) = stand_in(&s) else { return };
    let file = s.home.join("lab-operator.json");
    let mut args = words(&["pair", "lab", "--relay-host", &host, "--operator-file"]);
    args.push(file.display().to_string());
    args.extend(flags.iter().cloned());
    let out = ran(relay(&s, &args));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // The operator's host: another HOME, with nothing in its store.
    let elsewhere = throughput_harness::scratch("relay-status-operator");
    let status = |extra: &[&str]| {
        let mut args = words(&["status", "--pair-file"]);
        args.push(file.display().to_string());
        args.extend(words(extra));
        args.extend(flags.iter().cloned());
        ran(relay_at(&elsewhere, &args))
    };
    let out = status(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    assert!(stdout.starts_with(&format!("{}: offline; expires 20", file.display())), "{stdout}");
    let out = status(&["lab"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(stdout.starts_with("lab: offline; expires 20") && stdout.trim_end().ends_with('Z'), "{stdout}");
    let out = status(&["lab", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(
        (doc["label"].as_str(), doc["online"].as_bool(), doc["sessions"].as_u64()),
        (Some("lab"), Some(false), Some(0))
    );
    let left = doc["seconds_left"].as_i64().expect("seconds_left");
    assert!((71 * 3600..=72 * 3600).contains(&left), "a new pair lives 72 h: {doc}");
    assert!(doc["expires"].as_str().is_some_and(|at| at.starts_with("20") && at.ends_with('Z')), "{doc}");
    let mut args = words(&["status", "lab"]);
    args.extend(flags.iter().cloned());
    let out = ran(relay_at(&elsewhere, &args));
    assert_eq!(out.status.code(), Some(78), "no pair is stored there: {}", text(&out.stderr));
    let _ = std::fs::remove_dir_all(&elsewhere);
}

/// T-591: `relay pair` keeps its one line on stdout, which scripts read, and
/// says on stderr how a pair goes on past its expiry.
#[test]
fn relay_pair_says_the_way_past_the_expiry() {
    let s = Session::start("relay-pair-words");
    let Some((flags, host)) = stand_in(&s) else { return };
    let mut args = words(&["pair", "lab", "--relay-host", &host]);
    args.extend(flags);
    let out = ran(relay(&s, &args));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(stdout.lines().count(), 1, "one line on stdout: {stdout}");
    assert!(stdout.starts_with("lab: expires 20"), "{stdout}");
    let way =
        "podssh relay: in its last 24 h, podssh relay pair lab --operator-file NEW makes the next pair, which the \
               node takes at the expiry; NEW goes to each operator";
    assert!(stderr.contains(way), "{stderr}");
}

#[test]
fn a_token_that_the_relay_refuses_is_77() {
    let s = Session::start("relay-trace-token");
    let Some((mut args, host)) = stand_in(&s) else { return };
    args.extend(words(&["trace", "127.0.0.1", "22", "--relay-host", &host]));
    let mut cmd = relay(&s, &args);
    cmd.env("PODSSH_RELAY_TOKEN", "a-token-that-the-stand-in-refuses");
    let out = ran(cmd);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(77), "{err}");
    assert!(err.contains("refused the token for /trace"), "{err}");
    assert!(!err.contains("a-token-that-the-stand-in-refuses"), "the token was shown: {err}");
}
