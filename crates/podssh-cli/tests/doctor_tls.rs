//! `podssh doctor`'s diagnosis of the TLS handshakes (T-487, GitHub #99),
//! as a process, through a stand-in proxy on the loopback that plays the
//! egress behind it: one that lists names (github.com's handshake reaches a
//! TLS server of the test's own, for that name, and each other name is
//! reset after its ClientHello, as the reporter's sandbox did), one that
//! resets each handshake, and one that drops each (it takes the ClientHello
//! and never answers). The relay hosts and the DERP server are names that
//! the stand-in reaches; no byte leaves the loopback.

mod cleanup;

// A TLS server of the test's own CA, for github.com.
#[path = "update_support/mod.rs"]
mod update_support;

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The bound on each run of doctor.
const LIMIT: Duration = Duration::from_secs(120);

/// The names of the roads, which the stand-in reaches.
const RELAYS: &str = "relay-a.test,relay-b.test";
const DERP: &str = "derp.test";

/// Every variable that could steer the doctor somewhere this test did not
/// choose; the test sets the ones that it uses.
const STEERING: &[&str] = &[
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "no_proxy",
    "NO_PROXY",
    "PODSSH_OFFLINE",
    "PODSSH_RELAY",
    "PODSSH_RELAY_ADDR",
    "PODSSH_RELAY_TOKEN",
    "PODSSH_FORWARDER",
    "PODSSH_VIA",
    "PODSSH_IROH_RELAY",
    "SSL_CERT_FILE",
    "SSH_AUTH_SOCK",
];

/// What the egress behind the stand-in does with a handshake on port 443.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Egress {
    /// TLS for github.com, a listed name; each other name reset.
    Names,
    /// Each handshake reset, github.com's too.
    ResetsEach,
    /// Each handshake taken and never answered.
    DropsEach,
}

/// The stand-in proxy: its port. A CONNECT to an address is refused, as a
/// proxy of names refuses one; one to port 22 is taken and closed.
fn proxy(egress: Egress, tls_port: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || answer(conn, egress, tls_port));
        }
    });
    port
}

/// The target of a CONNECT, read from its head.
fn target(conn: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
        if conn.read(&mut byte).unwrap_or(0) == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string();
    line.split_whitespace().nth(1).map(String::from)
}

fn answer(mut conn: TcpStream, egress: Egress, tls_port: u16) {
    let Some(target) = target(&mut conn) else { return };
    let (host, port) = target.rsplit_once(':').unwrap_or((target.as_str(), "443"));
    if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        let _ = conn.write_all(b"HTTP/1.1 403 names only\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    let _ = conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    if port != "443" {
        std::thread::sleep(Duration::from_millis(100));
        return;
    }
    match (egress, host == "github.com") {
        (Egress::Names, true) => splice(conn, tls_port),
        (Egress::DropsEach, _) => hold(conn),
        _ => reset_after_hello(conn),
    }
}

/// The ClientHello is let in and never read, and the connection closed: a
/// close with bytes unread is a reset (RST), as an egress that lists names
/// sends for a name that is not on its list.
fn reset_after_hello(conn: TcpStream) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
    let mut first = [0u8; 1];
    if matches!(conn.peek(&mut first), Ok(n) if n > 0) {
        // The rest of the ClientHello comes in the same flight.
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(conn);
}

/// Each byte taken and nothing sent back, until the client goes.
fn hold(mut conn: TcpStream) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(60)));
    let mut sink = [0u8; 4096];
    while matches!(conn.read(&mut sink), Ok(n) if n > 0) {}
}

/// The connection carried to the TLS server, both ways.
fn splice(conn: TcpStream, tls_port: u16) {
    let Ok(up) = TcpStream::connect(("127.0.0.1", tls_port)) else { return };
    let (mut down_r, mut up_w) = (conn.try_clone().unwrap(), up.try_clone().unwrap());
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut down_r, &mut up_w);
    });
    let (mut up_r, mut down_w) = (up, conn);
    let _ = std::io::copy(&mut up_r, &mut down_w);
}

/// A fresh directory, removed when the test ends.
fn scratch(tag: &str) -> PathBuf {
    static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-doctor-tls-{tag}-{}-{call}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// One doctor at a time, as the others of the tests of doctor run.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// `podssh doctor ARGS` through the stand-in at `port`, with HOME and the
/// cache in a scratch directory and no settings file: its stdout.
fn doctor(args: &[&str], port: u16) -> String {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let home = scratch("home");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("doctor").args(args).env("HOME", &home).env("USERPROFILE", &home);
    for name in STEERING {
        cmd.env_remove(name);
    }
    // No STUN server is asked (T-641): its datagrams would leave the loopback.
    cmd.env("https_proxy", format!("http://127.0.0.1:{port}"))
        .env("PODSSH_DERP_SERVER", DERP)
        .env("PODSSH_CACHE_DIR", home.join("cache"))
        .env("PODSSH_SETTINGS", "none")
        .env("PODSSH_STUN", "no");
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("podssh runs");
    let mut stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || std::io::read_to_string(&mut stdout).unwrap_or_default());
    let began = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if began.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh doctor {args:?} still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    out.join().unwrap()
}

/// The TLS server for github.com, on a runtime that the test keeps, and
/// its CA file for `--ca-file`.
fn github() -> (tokio::runtime::Runtime, update_support::Server, String) {
    let home = scratch("tls");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let server = runtime.block_on(update_support::Server::start_for(&home, &["github.com"]));
    let ca = server.ca_file.display().to_string();
    (runtime, server, ca)
}

/// `doctor --json` through `egress`: the report, its diagnosis, and the
/// detail of its line `TLS reference`; the counts are the checks' alone.
fn json_run(egress: Egress, relays: &str) -> (serde_json::Value, String) {
    let (_runtime, server, ca) = github();
    let port = proxy(egress, server.addr.port());
    let out = doctor(&["--json", "--relay-host", relays, "--ca-file", &ca], port);
    let doc: serde_json::Value = serde_json::from_str(&out).expect("stdout is one JSON object");
    let checks = doc["checks"].as_array().unwrap();
    let counts = &doc["counts"];
    let counted = ["ok", "fail", "unknown"].iter().map(|k| counts[k].as_u64().unwrap()).sum::<u64>();
    assert_eq!(counted as usize, checks.len(), "a diagnosis adds no count: {out}");
    let reference = checks.iter().find(|c| c["check"] == "TLS reference").expect("the line TLS reference");
    let detail = reference["detail"].as_str().unwrap().to_string();
    assert_eq!(reference["status"], "ok", "{reference}");
    (doc, detail)
}

/// The reporter's case: each relay host FAIL, reset after its ClientHello,
/// github.com's handshake complete, and one line after the counts that says
/// so; in `--json`, the diagnosis `tls-names` with github.com as evidence.
#[test]
fn a_list_of_names_is_said_once_after_the_counts() {
    let (_runtime, server, ca) = github();
    let port = proxy(Egress::Names, server.addr.port());
    let out = doctor(&["--relay-host", RELAYS, "--ca-file", &ca], port);
    let relays: Vec<&str> = out.lines().filter(|l| l.split_whitespace().nth(1) == Some("relay")).collect();
    assert_eq!(relays.len(), 2, "{out}");
    assert!(relays.iter().all(|l| l.starts_with("  FAIL")), "{out}");
    let reference = out.lines().find(|l| l.contains("TLS reference")).unwrap_or_else(|| panic!("{out}"));
    assert!(reference.starts_with("  ok") && reference.contains("TLS completed for github.com"), "{reference}");
    let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    let (counts, last) = (lines[lines.len() - 2], lines[lines.len() - 1]);
    assert!(counts.contains(" ok, ") && counts.contains(" FAIL, "), "{out}");
    let way = format!("diagnosis: the way out through the proxy 127.0.0.1:{port}");
    assert!(last.starts_with(&format!("{way} resets TLS for each name that it does not list")), "{last}");
    assert!(last.contains("github.com is on the list and the relay's name is not"), "{last}");
    let (doc, _) = json_run(Egress::Names, RELAYS);
    let found = &doc["diagnosis"];
    assert_eq!(found.as_array().map(Vec::len), Some(1), "{doc}");
    assert_eq!(found[0]["kind"], "tls-names", "{doc}");
    assert_eq!(found[0]["evidence"], serde_json::json!(["github.com"]), "{doc}");
}

/// Each handshake reset, github.com's too: the second case, with each name
/// as evidence.
#[test]
fn a_reset_of_each_handshake_is_its_own_case() {
    let (doc, reference) = json_run(Egress::ResetsEach, RELAYS);
    assert!(reference.ends_with(": a reset; the reference of the roads' handshakes"), "{reference}");
    let found = &doc["diagnosis"][0];
    assert_eq!(found["kind"], "tls-reset", "{doc}");
    let evidence = found["evidence"].as_array().unwrap();
    for name in ["github.com", "relay-a.test", "relay-b.test", DERP] {
        assert!(evidence.iter().any(|e| e == name), "{name}: {doc}");
    }
}

/// Each handshake taken and never answered: the third case, a timeout and
/// no reset. One relay host, as each waits for its bound.
#[test]
fn a_path_that_drops_each_handshake_is_told_from_a_reset() {
    let (doc, reference) = json_run(Egress::DropsEach, "relay-a.test");
    assert!(reference.ends_with(": a timeout; the reference of the roads' handshakes"), "{reference}");
    let found = &doc["diagnosis"][0];
    assert_eq!(found["kind"], "tls-dropped", "{doc}");
    assert!(found["detail"].as_str().unwrap().contains("resets none"), "{doc}");
}
