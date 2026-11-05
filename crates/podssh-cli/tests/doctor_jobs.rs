//! `podssh doctor`'s sections at once, `--jobs` and `--quick` (T-511, the
//! operator's ruling Q73), as a process, through a stand-in proxy on the
//! loopback that refuses each CONNECT: at once for a name that does not
//! start with `slow`, after [`WAIT`] for one that does. Four sections each
//! reach one slow name (the relay's second host, a forwarder, the second
//! proxy of `--via` and the DERP server), so the proxy's log of when each
//! came tells sections at once from sections one after another, whatever
//! the egress's own probes and the system resolver take.

mod cleanup;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long the stand-in holds the CONNECT of a slow name.
const WAIT: Duration = Duration::from_secs(3);

/// The bound on each run of doctor.
const LIMIT: Duration = Duration::from_secs(120);

/// The slow names, each in a section of its own.
const SLOW_RELAY: &str = "slow-relay.example";
const SLOW_FORWARDER: &str = "slow-forwarder.example";
const SLOW_VIA: &str = "slow-via.example";
const SLOW_DERP: &str = "slow-derp.example";

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
    "PODSSH_DERP_SERVER",
    "PODSSH_IROH_RELAY",
    "SSL_CERT_FILE",
    "SSH_AUTH_SOCK",
];

/// When the proxy first got a CONNECT for each name.
type Log = Arc<Mutex<BTreeMap<String, Instant>>>;

/// The stand-in proxy: its port, and its log.
fn proxy() -> (u16, Log) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let kept = log.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let log = kept.clone();
            std::thread::spawn(move || answer(conn, &log));
        }
    });
    (port, log)
}

/// One CONNECT: its name logged, then a 403, at once or after [`WAIT`].
fn answer(mut conn: std::net::TcpStream, log: &Log) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
        if conn.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string();
    let target = line.split_whitespace().nth(1).unwrap_or_default();
    let host = target.rsplit_once(':').map_or(target, |(host, _)| host).to_string();
    let slow = host.starts_with("slow");
    log.lock().unwrap().entry(host).or_insert_with(Instant::now);
    if slow {
        std::thread::sleep(WAIT);
    }
    let _ = conn.write_all(b"HTTP/1.1 403 refused by the stand-in\r\nContent-Length: 0\r\n\r\n");
}

/// A fresh directory for HOME and the cache, removed when the test ends.
fn scratch_home() -> PathBuf {
    static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-doctor-jobs-{}-{call}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

struct Run {
    code: i32,
    out: String,
    took: Duration,
}

/// One doctor at a time: two at once would share the machine's time, which
/// these tests measure.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// `podssh doctor ARGS` through the stand-in at `port`, with HOME and the
/// cache in a scratch directory and no settings file.
fn doctor(args: &[&str], port: u16) -> Run {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let home = scratch_home();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("doctor").args(args).env("HOME", &home).env("USERPROFILE", &home);
    for name in STEERING {
        cmd.env_remove(name);
    }
    // No STUN server is asked (T-641): its datagrams would leave the loopback.
    cmd.env("https_proxy", format!("http://127.0.0.1:{port}"))
        .env("PODSSH_DERP_SERVER", SLOW_DERP)
        .env("PODSSH_CACHE_DIR", home.join("cache"))
        .env("PODSSH_SETTINGS", "none")
        .env("PODSSH_STUN", "no");
    let began = Instant::now();
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("podssh runs");
    let mut stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || std::io::read_to_string(&mut stdout).unwrap_or_default());
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if began.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh doctor {args:?} still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let took = began.elapsed();
    Run { code: status.code().unwrap_or(-1), out: out.join().unwrap(), took }
}

/// The flags that reach each slow name, and the relay's first host, which
/// the egress probes.
const ROADS: [&str; 6] = [
    "--relay-host",
    "fast-relay.example,slow-relay.example",
    "--forwarder",
    "wss://slow-forwarder.example/p",
    "--via",
    "https://slow-via.example",
];

/// The form of a report: each section, and each check with its label, in
/// order; the details hold times, which differ from run to run.
fn form(out: &str) -> Vec<String> {
    let lines = out.lines().skip_while(|l| *l != "this host");
    lines.filter(|l| !l.is_empty()).map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" ")).collect()
}

/// When each slow name came, after the first of them.
fn came(log: &Log) -> Vec<(String, Duration)> {
    let log = log.lock().unwrap();
    let slow: Vec<(&String, &Instant)> = log.iter().filter(|(host, _)| host.starts_with("slow")).collect();
    let first = slow.iter().map(|(_, at)| **at).min().expect("a slow name came");
    let mut came: Vec<(String, Duration)> = slow.iter().map(|(host, at)| ((*host).clone(), **at - first)).collect();
    came.sort_by_key(|(_, after)| *after);
    came
}

/// At once, the four slow sections reach their names together, and the run
/// is shorter by most of their waits than one at a time, where each section
/// starts once the one before it has ended; the report has the same form,
/// in the order of the sections, either way.
#[test]
fn the_sections_run_at_once_and_jobs_1_runs_them_one_after_another() {
    let (port, log) = proxy();
    let at_once = doctor(&ROADS, port);
    let together = came(&log);
    let (port_one, log_one) = proxy();
    let mut one_args = ROADS.to_vec();
    one_args.extend(["--jobs", "1"]);
    let one = doctor(&one_args, port_one);
    let apart = came(&log_one);
    let names: Vec<&str> = apart.iter().map(|(host, _)| host.as_str()).collect();
    assert_eq!(names, [SLOW_RELAY, SLOW_FORWARDER, SLOW_VIA, SLOW_DERP], "in the order of the report: {apart:?}");
    assert_eq!(together.len(), 4, "{together:?}\n{}", at_once.out);
    let spread = together.last().unwrap().1;
    // The spans, for the record of a run (`--nocapture`).
    eprintln!("at once: the slow names within {spread:?}, the run {:?}; one at a time: {:?}", at_once.took, one.took);
    assert!(spread < WAIT, "at once, the slow names came within {spread:?}: {together:?}");
    for pair in apart.windows(2) {
        assert!(pair[1].1 - pair[0].1 >= WAIT, "one at a time, a section waits for the one before: {apart:?}");
    }
    assert!(one.took >= WAIT * 4, "{:?}", one.took);
    assert!(one.took >= at_once.took + WAIT * 2, "at once {:?}, one at a time {:?}", at_once.took, one.took);
    // The same report, in the same order: the slow sections each FAIL.
    assert_eq!(form(&at_once.out), form(&one.out), "{}\n----\n{}", at_once.out, one.out);
    assert_eq!((at_once.code, one.code), (1, 1), "{}", at_once.out);
    let sections: Vec<&str> =
        at_once.out.lines().filter(|l| ["egress", "relay", "forwarders", "via", "derp", "pairs"].contains(l)).collect();
    assert_eq!(sections, ["egress", "relay", "forwarders", "via", "derp", "pairs"], "{}", at_once.out);
    for host in [SLOW_RELAY, SLOW_FORWARDER, SLOW_VIA, SLOW_DERP] {
        // The host's own check, not the line of the list's order (T-607),
        // what a request with no TLS meets on the way to it (T-326), nor
        // whether it offers HTTP/2 (T-321).
        let own = |l: &&str| {
            let line = l.trim_start();
            let section = line.split_whitespace().nth(1);
            l.contains(host) && !matches!(section, Some("rank" | "cleartext" | "http2"))
        };
        let line = at_once.out.lines().find(own).unwrap_or_else(|| panic!("{host}: {}", at_once.out));
        assert!(line.starts_with("  FAIL") && line.contains("403"), "{line}");
    }
}

/// `--quick`: this host, the egress and the relay, the roads that the run
/// names (here `--via`), and no line of the quick tunnel's edge, DERP or
/// the pairs; the DERP server is never asked, and the last line names what
/// was left out.
#[test]
fn quick_checks_the_host_the_egress_and_the_relay_and_names_what_it_left_out() {
    let (port, log) = proxy();
    let asked = |log: &Log| log.lock().unwrap().keys().cloned().collect::<Vec<String>>();
    let run = doctor(&["--quick", "--relay-host", "fast-relay.example", "--via", "https://slow-via.example"], port);
    assert!(!asked(&log).iter().any(|host| host == SLOW_DERP), "--quick asked the DERP server: {:?}", asked(&log));
    assert!(asked(&log).iter().any(|host| host == SLOW_VIA), "the road that the run names: {:?}", asked(&log));
    // The sections, after the title and the version, and before the counts.
    let heads = run.out.lines().filter(|l| !l.is_empty() && !l.starts_with(' ') && !l.contains(" ok, "));
    let sections: Vec<&str> = heads.skip(2).collect();
    assert_eq!(sections, ["this host", "egress", "relay", "forwarders", "via", "left out"], "{}", run.out);
    let last = run.out.lines().rev().find(|l| l.starts_with("  ")).unwrap_or_default();
    assert!(last.starts_with("  ????  sections       not checked with --quick: the quick tunnel's edge"), "{last}");
    let tail = "DERP, the public carriers, the pairs and the net held; a run without --quick checks them";
    assert!(last.contains(tail), "{last}");
    // --json: no check of the roads left out, and the same line, unknown,
    // in its section.
    let json = doctor(&["--quick", "--json", "--relay-host", "fast-relay.example"], port);
    assert!(!asked(&log).iter().any(|host| host == SLOW_DERP), "--quick asked the DERP server: {:?}", asked(&log));
    let doc: serde_json::Value = serde_json::from_str(&json.out).expect("stdout is one JSON object");
    let checks = doc["checks"].as_array().unwrap();
    for item in checks {
        let (section, check) = (item["section"].as_str().unwrap(), item["check"].as_str().unwrap());
        assert!(!["derp", "carriers", "pairs", "net", "iroh", "tor"].contains(&section), "{item}");
        let gone = ["UDP out", "edge road", "quick tunnel roots", "bind UDP", "nat"].contains(&check)
            || ["DERP", "iroh", "pair "].iter().any(|word| check.starts_with(word));
        assert!(!gone, "{item}");
    }
    let line = checks.iter().find(|c| c["check"] == "sections").expect("the line of --quick");
    assert_eq!((line["section"].as_str(), line["status"].as_str()), (Some("left out"), Some("unknown")), "{line}");
}

/// A bad `--jobs` is a usage error before any probe.
#[test]
fn a_bad_number_of_jobs_is_refused_before_any_probe() {
    let (port, log) = proxy();
    for bad in ["0", "65", "many"] {
        let run = doctor(&["--jobs", bad], port);
        assert_eq!(run.code, 64, "--jobs {bad}: {}", run.out);
        assert!(run.out.is_empty(), "{}", run.out);
    }
    assert!(log.lock().unwrap().is_empty(), "a probe ran");
}
