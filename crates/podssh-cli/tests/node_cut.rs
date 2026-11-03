//! A client's lost link during a node's bulk (T-421), on the loopback: two
//! sessions of the resumable layer through one node, each a download from
//! the tests' SSH server. The first goes through a stand-in proxy
//! (`scripts/fake-proxy.py`) that resets its link with RST in the middle of
//! its bytes; the second goes straight to the relay, and is in its middle
//! then. The node's frames that were on their way for the first session meet
//! a relay that has closed it. podssh's relay role drops them as frames in
//! flight, so the node's socket stays and no `1003` comes (the race comes or
//! not, by the timing here; the role's contract test makes it each time).
//! The stand-in relay, as strict as the default relay (T-412), closes the
//! node's socket with `1003 unknown session id`; it tells the node of the
//! lost link a second late (`lateclose:1`), as a relay far from its node, so
//! that the race comes each time. The node connects again at once (T-255),
//! so the second session's layer resumes with no backoff. Each
//! session ends with exit 0 and each of its bytes. The checks say that they
//! did not run when this host has no Python or no openssl for the stand-ins.
#![cfg(unix)]

mod ssh_harness;
mod throughput_harness;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use throughput_harness::{found, lines_of, scripts, wait_for, without_proxy, Cell, Session};

const MIB: u64 = 1 << 20;
/// The session whose link is cut, at [`CUT_AT`].
const CUT: u64 = 24 * MIB;
const CUT_AT: u64 = 6 * MIB;
/// The session that goes on: long enough to be in its middle at the cut.
const ON: u64 = 48 * MIB;
/// The other session starts once this much of this one came.
const FLOWING: u64 = 4 * MIB;
const LIMIT: Duration = Duration::from_secs(300);
/// The longest wait between two reads of the session that goes on.
const STALL: Duration = Duration::from_secs(3);
/// The stand-in relay's name, on the loopback, for a run with no proxy.
const PINS: [&str; 2] = ["--relay-addr", "relay-a.test=127.0.0.1"];
/// The byte of each block that the tests' server's `source` sends.
const FILL: u8 = 0x5a;

/// One download's end.
struct Run {
    code: Option<i32>,
    bytes: u64,
    whole: bool,
    /// The longest wait between two reads, from the first byte on.
    stall: Duration,
    err: String,
}

/// `podssh ssh ... source N` from `cmd`: its run. `cut` is written when that
/// many bytes came; `flowing` is told once [`FLOWING`] came.
fn download(mut cmd: Command, cut: Option<(PathBuf, u64)>, flowing: Option<mpsc::Sender<()>>) -> Run {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reading = std::thread::spawn(move || {
        let (mut buf, mut bytes, mut whole) = (vec![0u8; 1 << 16], 0u64, true);
        let (mut last, mut stall) = (None::<Instant>, Duration::ZERO);
        let (mut cut, mut flowing) = (cut, flowing);
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            let now = Instant::now();
            stall = stall.max(last.map_or(Duration::ZERO, |at| now - at));
            last = Some(now);
            whole &= buf[..n].iter().all(|b| *b == FILL);
            bytes += n as u64;
            if cut.as_ref().is_some_and(|(_, at)| bytes >= *at) {
                std::fs::write(cut.take().unwrap().0, b"now").unwrap();
            }
            if bytes >= FLOWING {
                if let Some(tx) = flowing.take() {
                    let _ = tx.send(());
                }
            }
        }
        (bytes, whole, stall)
    });
    let mut stderr = child.stderr.take().unwrap();
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + LIMIT;
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let ((bytes, whole, stall), err) = (reading.join().unwrap(), said.join().unwrap());
    Run { code, bytes, whole, stall, err }
}

/// A stand-in proxy that maps relay-a.test to `port` and resets each open
/// tunnel once `start` appears: its URL.
fn proxy(session: &Session, port: &str, start: &Path) -> String {
    let python = ["python3", "python"].into_iter().find(|p| found(p, &["--version"])).expect("Python");
    let port_file = session.home.join("proxy-client.port");
    let mut cmd = Command::new(python);
    cmd.arg(scripts().join("fake-proxy.py")).arg("--port-file").arg(&port_file);
    cmd.arg("--log").arg(session.home.join("proxy-client.log")).arg("--start-file").arg(start);
    cmd.arg("--map").arg(format!("relay-a.test=127.0.0.1:{port}")).args(["--stop-after", "0"]);
    session.keep(cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
            return format!("http://127.0.0.1:{port}");
        }
        assert!(Instant::now() < deadline, "the stand-in proxy did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// What the two sessions and the node gave.
struct Cut {
    cut: Run,
    on: Run,
    node: Vec<String>,
}

/// The two sessions through one node at the relay of `cell`.
fn two_sessions(session: &Session, cell: &Cell) -> Cut {
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let mut pair = session.stand_in(&words(&["relay"]), &ca);
    let out = pair.args(["pair", "lab", "--relay-host", &relay]).args(PINS).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let target = format!("127.0.0.1:{}", session.port);
    let mut node = session.stand_in(&words(&["node"]), &ca);
    node.args(["lab", target.as_str()]).args(PINS);
    let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");

    let operator = |bytes: u64| {
        let mut args = words(&["ssh"]);
        args.extend(session.common());
        args.extend([format!("node://tester@{}", "lab"), format!("source {bytes}")]);
        args
    };
    // The session that goes on: straight to the relay.
    let mut on = session.stand_in(&operator(ON)[..1], &ca);
    on.args(PINS).args(&operator(ON)[1..]);
    // The session that is cut: through the proxy, with no pin, which would
    // go around it (T-318).
    let start = session.home.join("start");
    let port = relay.rsplit_once(':').unwrap().1.to_string();
    let mut cut = without_proxy(session.command(&operator(CUT)));
    cut.env("HTTPS_PROXY", proxy(session, &port, &start)).env("SSL_CERT_FILE", &ca);

    let (tx, rx) = mpsc::channel();
    let on = std::thread::spawn(move || download(on, None, Some(tx)));
    rx.recv_timeout(LIMIT).expect("the session that goes on flows");
    let cut = download(cut, Some((start, CUT_AT)), None);
    let on = on.join().unwrap();
    let node = lines.try_iter().collect();
    eprintln!("the longest waits: {:?} of the session that went on, {:?} of the one cut", on.stall, cut.stall);
    Cut { cut, on, node }
}

/// Each session ended with exit 0 and each of its bytes, the cut came, and
/// the session that went on never waited [`STALL`] or more.
fn both_whole(c: &Cut) {
    for (run, bytes) in [(&c.cut, CUT), (&c.on, ON)] {
        assert_eq!(run.code, Some(0), "{}\nthe node: {:?}", run.err, c.node);
        assert_eq!((run.bytes, run.whole), (bytes, true), "{}", run.err);
    }
    assert!(c.cut.err.contains("resuming the session"), "the cut came: {}", c.cut.err);
    assert!(
        c.on.stall < STALL,
        "the session that went on waited {:?}: {}\nthe node: {:?}",
        c.on.stall,
        c.on.err,
        c.node
    );
}

/// podssh's relay role drops the frames in flight: the node's socket stays,
/// and no 1003 comes (the session's end fails for one).
#[test]
fn the_role_drops_the_frames_in_flight_of_a_lost_link() {
    let session = Session::start("node-cut-role");
    // The role's own proxy would carry nothing here: an empty value is unset.
    let unset: Vec<(&str, String)> =
        ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"].iter().map(|v| (*v, String::new())).collect();
    let cell = match Cell::podssh_relay_env(&session, "podssh's relay role", &[], &unset) {
        Ok(cell) => cell,
        Err((_, why)) => return eprintln!("did not run: {why}"),
    };
    let c = two_sessions(&session, &cell);
    both_whole(&c);
    assert!(!c.node.iter().any(|l| l.contains("1003")), "no 1003 reached the node: {:?}", c.node);
}

/// The strict stand-in closes the node's socket with 1003 for such a frame,
/// as the default relay does, here each time, as it tells the node of the
/// lost link a second late; the node connects again at once, and the session
/// that goes on resumes within [`STALL`].
#[test]
fn a_strict_relay_s_1003_costs_the_other_session_no_backoff() {
    // With the role in the stand-in's place (T-169), no 1003 comes.
    if std::env::var("PODSSH_RELAY_UNDER_TEST").as_deref() == Ok("podssh") {
        return eprintln!("did not run: PODSSH_RELAY_UNDER_TEST=podssh puts the role in the stand-in's place");
    }
    let session = Session::start("node-cut-stand-in");
    let cell = match Cell::fake_relay_mode(&session, "lateclose:1", "the stand-in relay, its close late") {
        Ok(cell) => cell,
        Err((_, why)) => return eprintln!("did not run: {why}"),
    };
    let c = two_sessions(&session, &cell);
    // The stand-in's own line comes to its log at its end: the node's says it.
    let _ = session.claim_unknown_ids();
    both_whole(&c);
    let closed: Vec<&String> = c.node.iter().filter(|l| l.contains("1003")).collect();
    assert!(!closed.is_empty(), "the 1003 came: {:?}", c.node);
    for line in closed {
        assert!(line.ends_with("connecting again at once"), "the node went again at once: {line}");
    }
}
