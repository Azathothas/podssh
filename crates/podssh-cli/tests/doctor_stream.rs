//! `podssh doctor --stream URL` (T-325, GitHub #54) as a process, against
//! servers of the probes on the loopback: the stand-in relay
//! (`scripts/fake-relay.py`, `scripts/fake_stream.py`) with no fault and in
//! a mode for each fault of a path that the probes must name (a response
//! held until its end, a body held until its end, a cap of 1 MiB as nginx's
//! default, a quiet stream ended at 3 s), and podssh's own relay role; then
//! go-httpbin, software that podssh did not write, where this host has it:
//! its response and its cap get the role's verdicts. Each line names its
//! property with its size or its time. The quiet probe holds 6 s. The
//! checks say that they did not run when this host has no Python or no
//! openssl for the stand-in, and no go-httpbin.

mod ssh_harness;
mod throughput_harness;

use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use throughput_harness::{found, Cell, Session};

/// The bound on each run of doctor: the probes take about 15 s here.
const LIMIT: Duration = Duration::from_secs(180);
/// The quiet probe's hold in these runs.
const HOLD: &str = "6";

/// One line of the section `stream`: its label, its check and its detail.
struct Line {
    label: String,
    check: String,
    detail: String,
}

/// `podssh doctor ARGS` with the stand-in's CA, no proxy and no relay of the
/// machine: its exit code and the lines of its section `stream`.
fn doctor(s: &Session, flags: &[&str], ca: Option<&str>) -> (i32, Vec<Line>, String) {
    let mut args = vec!["doctor".to_string()];
    args.extend(flags.iter().map(|f| f.to_string()));
    let mut cmd = match ca {
        Some(ca) => s.stand_in(&args, ca),
        None => throughput_harness::without_proxy(s.command(&args)),
    };
    cmd.env_remove("PODSSH_RELAY_TOKEN").env_remove("PODSSH_RELAY").env_remove("PODSSH_OFFLINE");
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh doctor {flags:?} still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let section = text.split("\nstream\n").nth(1).unwrap_or_else(|| panic!("no section stream: {text}"));
    // `  LABEL  CHECK          DETAIL`: the label in 4, the check in 14.
    let lines = section
        .lines()
        .take_while(|l| l.starts_with("  "))
        .map(|l| Line { label: l[2..6].trim().into(), check: l[8..22].trim().into(), detail: l[23..].into() })
        .collect();
    (out.status.code().unwrap_or(-1), lines, text)
}

/// The detail of the check `name`, whose label must be `label`.
fn detail<'a>(lines: &'a [Line], name: &str, label: &str, text: &str) -> &'a str {
    let line = lines.iter().find(|l| l.check == name).unwrap_or_else(|| panic!("no line {name}: {text}"));
    assert_eq!(line.label, label, "{name}: {}", line.detail);
    &line.detail
}

/// The flags of a run at `cell`'s relay host: its name pinned to the
/// loopback, its CA, and the short hold.
fn at_cell(cell: &Cell) -> (Vec<String>, String) {
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (host, ca) = (at("--relay-host"), at("--ca-file"));
    let mut flags: Vec<String> = ["--stream", "--stream-idle", HOLD, "--relay-addr", "relay-a.test=127.0.0.1"]
        .iter()
        .map(|f| f.to_string())
        .collect();
    flags.insert(1, format!("https://{host}"));
    flags.extend(["--ca-file".to_string(), ca.clone()]);
    (flags, ca)
}

/// The section at the stand-in of `mode`, or `None` when it cannot run here.
fn at_stand_in(s: &Session, mode: &str) -> Option<(Vec<Line>, String)> {
    let cell = match Cell::fake_relay_mode(s, mode, mode) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let (flags, ca) = at_cell(&cell);
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let (_, lines, text) = doctor(s, &flags, Some(&ca));
    assert!(lines.iter().all(|l| l.label != "FAIL"), "{mode}: {text}");
    Some((lines, text))
}

/// The seconds in `detail` after `words`, as a line writes them (`3.0 s`).
fn seconds_after(detail: &str, words: &str) -> f64 {
    let rest = detail.split_once(words).unwrap_or_else(|| panic!("no {words:?} in {detail}")).1;
    rest.split(' ').next().unwrap().parse().unwrap_or_else(|_| panic!("no seconds after {words:?}: {detail}"))
}

/// What a path with no fault gives: each probe names it, with its size or
/// its time.
fn a_clean_path(lines: &[Line], text: &str) {
    let server = detail(lines, "stream server", "ok", text);
    assert!(server.contains("podssh's relay role, which reads a body as it comes, 8 MiB at most"), "{server}");
    let response = detail(lines, "response", "ok", text);
    assert!(response.contains("a response of 5 bytes sent over 2.0 s came over"), "{response}");
    assert!(response.ends_with("the path passes a response as it comes"), "{response}");
    let spread = seconds_after(response, "came over ");
    assert!((1.5..=2.5).contains(&spread), "{response}");
    let body = detail(lines, "request body", "ok", text);
    assert!(body.contains("a body of 4 pieces sent over 1.5 s came to the server over"), "{body}");
    assert!(body.ends_with("the path passes a request's body as it comes"), "{body}");
    let cap = detail(lines, "body cap", "ok", text);
    assert!(cap.contains("each body from 64 KiB to 8 MiB passed"), "{cap}");
    let quiet = detail(lines, "quiet stream", "ok", text);
    assert!(quiet.contains("a response quiet for 6.0 s after its first byte came whole after 6."), "{quiet}");
    assert!(quiet.ends_with("nothing on the path ends a stream quiet for that long"), "{quiet}");
}

#[test]
fn a_clean_path_streams_takes_8_mib_and_keeps_a_quiet_stream() {
    let s = Session::start("stream-clean");
    let Some((lines, text)) = at_stand_in(&s, "normal") else { return };
    a_clean_path(&lines, &text);
}

/// The stand-in that holds each response until its end: the response's
/// bytes came at once, after its 2 s.
#[test]
fn a_path_that_holds_the_response_is_named() {
    let s = Session::start("stream-buffer");
    let Some((lines, text)) = at_stand_in(&s, "buffer") else { return };
    let response = detail(&lines, "response", "ok", &text);
    assert!(response.contains("came at once, after 2."), "{response}");
    assert!(response.ends_with("something on the path holds a response until its end"), "{response}");
    assert!(!response.contains("as it comes"), "{response}");
}

#[test]
fn a_path_that_holds_the_body_is_named() {
    let s = Session::start("stream-bodybuffer");
    let Some((lines, text)) = at_stand_in(&s, "bodybuffer") else { return };
    let body = detail(&lines, "request body", "ok", &text);
    assert!(body.contains("came to the server at once, 1."), "{body}");
    assert!(body.ends_with("something on the path holds a request's body until its end"), "{body}");
    let response = detail(&lines, "response", "ok", &text);
    assert!(response.ends_with("the path passes a response as it comes"), "a body's fault alone: {response}");
}

/// nginx's default refuses a body of more than 1 MiB: the line names the
/// two sizes, the status and the product that it looks like.
#[test]
fn a_cap_of_1_mib_is_named_with_nginx_s_default() {
    let s = Session::start("stream-bodycap");
    let Some((lines, text)) = at_stand_in(&s, "bodycap:1048576") else { return };
    let cap = detail(&lines, "body cap", "ok", &text);
    assert!(cap.contains("a body of 1 MiB passed, and one of 2 MiB got 413 Content Too Large"), "{cap}");
    assert!(cap.contains("something on the path refuses a body of 2 MiB"), "{cap}");
    assert!(cap.ends_with("; looks like nginx's client_max_body_size (1 MiB by default)"), "{cap}");
}

/// A path that ends a stream quiet for 3 s: the line names the time.
#[test]
fn a_quiet_stream_ended_at_3_s_is_named() {
    let s = Session::start("stream-idle");
    let Some((lines, text)) = at_stand_in(&s, "idle:3") else { return };
    let quiet = detail(&lines, "quiet stream", "ok", &text);
    let ended = seconds_after(quiet, "first byte ended ");
    assert!((2.5..=4.0).contains(&ended), "{quiet}");
    assert!(quiet.contains("something on the path ends a stream quiet for about"), "{quiet}");
    let response = detail(&lines, "response", "ok", &text);
    assert!(response.ends_with("the path passes a response as it comes"), "gaps of 0.5 s pass: {response}");
}

/// podssh's own relay role serves the probes, and a path with no fault
/// gives each verdict of the stand-in's.
#[test]
fn podssh_s_relay_role_serves_the_probes() {
    let s = Session::start("stream-role");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &[]) {
        Ok(cell) => cell,
        Err((_, why)) => return eprintln!("did not run: {why}"),
    };
    let (flags, ca) = at_cell(&cell);
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let (_, lines, text) = doctor(&s, &flags, Some(&ca));
    a_clean_path(&lines, &text);
    // No other section ran: --stream checks this host and the stream alone.
    assert!(!text.contains("\nrelay\n") && !text.contains("\negress\n"), "{text}");
}

/// A value that does not read is 64, before anything connects.
#[test]
fn a_stream_url_that_does_not_read_is_refused() {
    let s = Session::start("stream-refused");
    for flags in [["--stream", "ftp://n.example"], ["--stream-idle", "30"]] {
        let args: Vec<String> = std::iter::once("doctor").chain(flags).map(String::from).collect();
        let out = s.command(&args).stdin(Stdio::null()).output().unwrap();
        assert_eq!(out.status.code(), Some(64), "{flags:?}");
        assert!(out.stdout.is_empty() && String::from_utf8_lossy(&out.stderr).starts_with("podssh doctor: "));
    }
}

/// go-httpbin with the role's paths (`-prefix /v1/probe`) and its cap (8
/// MiB): a server that podssh did not write gives the response and the cap
/// the verdicts of the role's; it says not when each part of a body came.
#[test]
fn go_httpbin_gives_the_response_and_the_cap_the_role_s_verdicts() {
    if !found("go-httpbin", &["-version"]) {
        return eprintln!("did not run: no go-httpbin here");
    }
    let s = Session::start("stream-httpbin");
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let child = Command::new("go-httpbin")
        .args(["-host", "127.0.0.1", "-port", &port.to_string(), "-prefix", "/v1/probe"])
        .args(["-max-body-size", "8388608", "-max-duration", "600s", "-log-level", "OFF"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("go-httpbin starts");
    s.keep(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "go-httpbin did not listen on {port} within 20 s");
        std::thread::sleep(Duration::from_millis(100));
    }
    let url = format!("http://127.0.0.1:{port}");
    let (_, lines, text) = doctor(&s, &["--stream", &url, "--stream-idle", HOLD], None);
    let server = detail(&lines, "stream server", "ok", &text);
    assert!(server.contains("names no limits of the probes"), "{server}");
    let response = detail(&lines, "response", "ok", &text);
    assert!(response.ends_with("the path passes a response as it comes"), "{response}");
    let cap = detail(&lines, "body cap", "ok", &text);
    assert!(cap.contains("each body from 64 KiB to 8 MiB passed"), "{cap}");
    let body = detail(&lines, "request body", "????", &text);
    assert!(body.contains("says not when each part came"), "{body}");
    let quiet = detail(&lines, "quiet stream", "ok", &text);
    assert!(quiet.contains("came whole after 6."), "{quiet}");
}
