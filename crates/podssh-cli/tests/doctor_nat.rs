//! `podssh doctor`'s line `nat` (T-641, GitHub #139) as a process: offline
//! one more `????` and nothing sent; `PODSSH_STUN=no` and a bad value; and,
//! through a stand-in proxy on the loopback that refuses each CONNECT, the
//! line against two stand-in STUN servers on the loopback (one that gives
//! the address that it saw, one that gives a NAT's, one that is silent). No
//! datagram and no connection leaves the loopback; the system resolver is
//! asked for the relay's name, as in the other tests of doctor. The unit
//! tests of `doctor::nat` hold each form.

mod cleanup;

use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The bound on each run of doctor.
const LIMIT: Duration = Duration::from_secs(120);

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
    "PODSSH_STUN",
    "SSL_CERT_FILE",
    "SSH_AUTH_SOCK",
];

/// One doctor at a time, as the other tests of doctor run.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn scratch() -> PathBuf {
    static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-doctor-nat-{}-{call}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

/// `podssh doctor ARGS` with `set`, HOME and the cache in a scratch
/// directory and no settings file; offline unless a proxy is set.
fn doctor(args: &[&str], set: &[(&str, &str)]) -> Run {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let home = scratch();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("doctor").args(args).env("HOME", &home).env("USERPROFILE", &home);
    for name in STEERING {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_CACHE_DIR", home.join("cache")).env("PODSSH_SETTINGS", "none");
    for (name, value) in set {
        cmd.env(name, value);
    }
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs");
    let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || std::io::read_to_string(&mut out).unwrap_or_default());
    let err = std::thread::spawn(move || std::io::read_to_string(&mut err).unwrap_or_default());
    let began = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if began.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh doctor {args:?} still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Run { code: status.code().unwrap_or(-1), out: out.join().unwrap(), err: err.join().unwrap() }
}

/// The item `nat` of a report of `--json`: its section, status and detail.
fn nat_item(out: &str) -> Option<(String, String, String)> {
    let doc: serde_json::Value = serde_json::from_str(out).unwrap_or_else(|e| panic!("{e}: {out}"));
    let item = doc["checks"].as_array().unwrap().iter().find(|c| c["check"] == "nat")?.clone();
    let text = |key: &str| item[key].as_str().unwrap_or_default().to_string();
    Some((text("section"), text("status"), text("detail")))
}

/// Offline: the line is one `????` in the section egress, nothing was sent,
/// and the run's exit is 0; `--quick` has no such line.
#[test]
fn offline_the_line_is_one_unknown_and_quick_leaves_it_out() {
    let run = doctor(&["--json"], &[("PODSSH_OFFLINE", "1")]);
    assert_eq!(run.code, 0, "{}{}", run.out, run.err);
    let (section, status, detail) = nat_item(&run.out).expect("a line nat");
    assert_eq!((section.as_str(), status.as_str()), ("egress", "unknown"), "{detail}");
    assert_eq!(detail, "not attempted: PODSSH_OFFLINE is set");
    let quick = doctor(&["--json", "--quick"], &[("PODSSH_OFFLINE", "1")]);
    assert_eq!(nat_item(&quick.out), None, "{}", quick.out);
    // The text: the same line, with its label.
    let text = doctor(&[], &[("PODSSH_OFFLINE", "1")]);
    assert!(text.out.contains("  ????  nat            not attempted: PODSSH_OFFLINE is set"), "{}", text.out);
}

/// `PODSSH_STUN=no` says that it turned the line off; a value that names
/// one server is 78 before any probe, with nothing on stdout.
#[test]
fn the_variable_turns_the_line_off_and_a_bad_value_is_78() {
    let off = doctor(&["--json"], &[("PODSSH_OFFLINE", "1"), ("PODSSH_STUN", "no")]);
    let (_, status, detail) = nat_item(&off.out).expect("a line nat");
    let words = "PODSSH_STUN=no turns it off, so no STUN server was asked";
    assert_eq!((status.as_str(), detail.as_str()), ("unknown", words));
    let bad = doctor(&[], &[("PODSSH_OFFLINE", "1"), ("PODSSH_STUN", "stun.example:3478")]);
    assert_eq!(bad.code, 78, "{}{}", bad.out, bad.err);
    assert!(bad.out.is_empty(), "{}", bad.out);
    assert!(bad.err.contains("podssh doctor: PODSSH_STUN: 1 named; give 2 to 4 STUN servers"), "{}", bad.err);
}

/// A stand-in proxy that refuses each CONNECT at once, so that the other
/// sections end quickly and nothing leaves the loopback.
fn refusing_proxy() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
                while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                    if conn.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = conn.write_all(b"HTTP/1.1 403 refused by the stand-in\r\nContent-Length: 0\r\n\r\n");
            });
        }
    });
    port
}

/// A stand-in STUN server on the loopback: it answers each Binding Request
/// with `says`, or with the address that the request came from when `says`
/// is `None`; `silent`, it reads and answers nothing. Written here from RFC
/// 8489's layout, apart from podssh's codec.
fn stun_server(says: Option<SocketAddr>, silent: bool) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buffer) {
            // A Binding Request: type 0x0001 and the magic cookie.
            if silent || n < 20 || buffer[..2] != [0, 1] || buffer[4..8] != [0x21, 0x12, 0xa4, 0x42] {
                continue;
            }
            let SocketAddr::V4(seen) = says.unwrap_or(from) else { continue };
            // XOR-MAPPED-ADDRESS: the port XOR 0x2112, the address XOR the cookie.
            let port = (seen.port() ^ 0x2112).to_be_bytes();
            let ip: Vec<u8> = seen.ip().octets().iter().zip([0x21, 0x12, 0xa4, 0x42]).map(|(a, k)| a ^ k).collect();
            let mut answer = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42];
            answer.extend_from_slice(&buffer[8..20]);
            answer.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, port[0], port[1]]);
            answer.extend_from_slice(&ip);
            let _ = socket.send_to(&answer, from);
        }
    });
    addr
}

/// The line through the stand-in proxy, against `servers`.
fn online(servers: [SocketAddr; 2]) -> (String, String, String) {
    let proxy = format!("http://127.0.0.1:{}", refusing_proxy());
    let stun = format!("{},{}", servers[0], servers[1]);
    let set = [("https_proxy", proxy.as_str()), ("PODSSH_STUN", stun.as_str()), ("PODSSH_DERP_SERVER", "derp.test")];
    let run = doctor(&["--json", "--relay-host", "relay.test"], &set);
    nat_item(&run.out).unwrap_or_else(|| panic!("no line nat: {}{}", run.out, run.err))
}

/// Two servers that give the address that they saw: no NAT, as both saw the
/// one socket's; a NAT's one address for both: one mapping; one silent
/// server: `????`, naming it, never FAIL.
#[test]
fn against_stand_ins_the_line_reads_the_nat_and_silence_is_unknown() {
    let (a, b) = (stun_server(None, false), stun_server(None, false));
    let (section, status, detail) = online([a, b]);
    assert_eq!((section.as_str(), status.as_str()), ("egress", "ok"), "{detail}");
    let says = format!("no NAT: {a} and {b} each saw this host's own address, 127.0.0.1:");
    assert!(detail.starts_with(&says), "{detail}");

    let mapped: SocketAddr = "198.51.100.7:40000".parse().unwrap();
    let (c, d) = (stun_server(Some(mapped), false), stun_server(Some(mapped), false));
    let (_, status, detail) = online([c, d]);
    assert_eq!(status, "ok", "{detail}");
    let says = format!("one mapping for all destinations: {c} and {d} each saw {mapped}");
    assert!(detail.starts_with(&says), "{detail}");

    let (e, silent) = (stun_server(None, false), stun_server(None, true));
    let (_, status, detail) = online([e, silent]);
    assert_eq!(status, "unknown", "{detail}");
    assert!(detail.contains(&format!("{silent} said nothing in 3 tries of 1000 ms")), "{detail}");
}
