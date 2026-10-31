//! The faults of the stand-in relay (T-203), on this machine's loopback:
//! `podssh ssh` through `scripts/fake-relay.py` in a mode that shapes the
//! traffic, to the tests' SSH server. Each check shows that its fault was
//! there: the delay makes a `ConnectTimeout` of 5 s fail (the planted
//! control), the rate gives a time near the one computed, and the cut ends
//! the session. Ignored by default, as they take about two minutes:
//!
//! ```sh
//! cargo test -p podssh-cli --test faults -- --ignored --test-threads 1
//! ```
//!
//! The same checks run in the gate's container, in `scripts/interop-faults.sh`.

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::process::Stdio;
use std::time::{Duration, Instant};

use ssh_harness::GREETING;
use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(240);

/// What a run gave: its code, stdout, stderr, and how long it took.
struct Ran {
    code: i32,
    out: Vec<u8>,
    err: String,
    took: Duration,
}

/// `podssh ssh` in `cell`, with `extra` options, running `command`, with
/// `input` on its stdin; within the limit.
fn ssh(session: &Session, cell: &Cell, extra: &[&str], command: &str, input: Option<Vec<u8>>) -> Ran {
    let mut args = cell.args.clone();
    let at = args.len() - 1;
    for (i, word) in extra.iter().enumerate() {
        args.insert(at + i, word.to_string());
    }
    args.push(command.to_string());
    let started = Instant::now();
    let mut child = session
        .command(&args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    let writer = input.map(|bytes| {
        let mut stdin = child.stdin.take().unwrap();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        })
    });
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        out
    });
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let code = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status.code().unwrap_or(-1);
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh {args:?} did not end within {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = started.elapsed();
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    Ran { code, out: reader.join().unwrap(), err: said.join().unwrap(), took }
}

fn cell(session: &Session, mode: &str) -> Option<Cell> {
    match Cell::fake_relay_mode(session, mode, mode) {
        Ok(cell) => Some(cell),
        Err((_, why)) => {
            eprintln!("skipped: {why}");
            None
        }
    }
}

/// The cell's arguments with no pin of the relay's name: through the
/// stand-in proxy, its map names the host, and a pin to the loopback would
/// go around the proxy and its fault (T-318).
fn unpinned(cell: &Cell) -> Vec<String> {
    let mut args = Vec::new();
    let mut words = cell.args.iter();
    while let Some(word) = words.next() {
        if word == "--relay-addr" {
            words.next();
        } else {
            args.push(word.clone());
        }
    }
    args
}

/// The cell with a second relay host, the same stand-in under the name that
/// its certificate also holds, so that a try on the next host can happen.
fn two_hosts(cell: Cell) -> Cell {
    let mut args = Vec::new();
    let mut words = cell.args.iter();
    while let Some(word) = words.next() {
        args.push(word.clone());
        match (word.as_str(), words.clone().next()) {
            ("--relay-host", Some(host)) => {
                let port = host.rsplit(':').next().unwrap_or_default();
                args.push(format!("{host},relay-b.test:{port}"));
                words.next();
            }
            ("--relay-addr", Some(pin)) => {
                args.push(format!("{pin},relay-b.test=127.0.0.1"));
                words.next();
            }
            _ => {}
        }
    }
    Cell { args, ..cell }
}

/// The cell's arguments with no `--ca-file`: the stand-in's certificate then
/// chains to no root that podssh trusts, as a proxy's that re-signs TLS does
/// (T-340).
fn untrusted(cell: Cell) -> Cell {
    let mut args = Vec::new();
    let mut words = cell.args.iter();
    while let Some(word) = words.next() {
        if word == "--ca-file" {
            words.next();
        } else {
            args.push(word.clone());
        }
    }
    Cell { args, ..cell }
}

/// Bytes that are not all alike, so that a reordered chunk shows.
fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x2545_f491;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[test]
#[ignore = "the fault harness, on the loopback: about 30 s"]
fn with_2_s_each_way_a_command_and_its_status_come_back() {
    let session = Session::start("delay");
    let Some(cell) = cell(&session, "delay:2000") else { return };
    let ran = ssh(&session, &cell, &[], "greet", None);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(ran.out, GREETING.as_bytes());
    // The control: the delay was there, as a limit of 5 s on the handshake
    // ends the same command.
    let planted = ssh(&session, &cell, &["-o", "ConnectTimeout=5"], "greet", None);
    assert_eq!(planted.code, 255, "{}", planted.err);
    assert!(planted.err.contains("did not finish within 5 s"), "{}", planted.err);
}

#[test]
#[ignore = "the fault harness, on the loopback: about 30 s"]
fn with_a_jitter_of_0_to_1_5_s_5_000_000_bytes_go_up_and_back_whole() {
    let session = Session::start("jitter");
    let Some(cell) = cell(&session, "jitter:0:1500:7") else { return };
    let sent = pattern(5_000_000);
    let ran = ssh(&session, &cell, &[], "echo", Some(sent.clone()));
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(ran.out.len(), sent.len(), "{}", ran.err);
    assert!(ran.out == sent, "the bytes came back changed or out of order");
}

#[test]
#[ignore = "the fault harness, on the loopback: about 40 s"]
fn at_64_kib_a_second_2_mb_take_the_time_computed() {
    let session = Session::start("rate");
    let Some(cell) = cell(&session, "rate:65536") else { return };
    let ran = ssh(&session, &cell, &[], "source 2000000", None);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(ran.out.len(), 2_000_000);
    let computed = Duration::from_secs_f64(2_000_000.0 / 65_536.0);
    assert!(ran.took >= computed.mul_f64(0.9), "faster than the rate: {:?}", ran.took);
    assert!(ran.took <= computed.mul_f64(1.5), "{:?}, where {computed:?} was computed", ran.took);
}

#[test]
#[ignore = "the fault harness, on the loopback: a few seconds"]
fn a_cut_ends_the_session_with_255_and_names_the_relay() {
    let session = Session::start("cut");
    let Some(cell) = cell(&session, "cut:1000000") else { return };
    let ran = ssh(&session, &cell, &[], "source 5000000", None);
    assert_eq!(ran.code, 255, "{}", ran.err);
    assert!(ran.out.len() < 5_000_000);
    assert!(ran.err.contains("the connection between podssh and the relay broke"), "{}", ran.err);
}

#[test]
#[ignore = "the fault harness, on the loopback: a few seconds"]
fn a_pause_holds_each_byte_then_lets_it_through() {
    let session = Session::start("pause");
    let Some(cell) = cell(&session, "pause:0:3") else { return };
    let ran = ssh(&session, &cell, &[], "greet", None);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(ran.out, GREETING.as_bytes());
    assert!(ran.took >= Duration::from_secs(3), "the pause did not hold: {:?}", ran.took);
}

/// The stand-in proxy's `--move` (T-203, for T-156): after the move, the
/// forward road's open session, which has no resumable layer, ends with 255
/// when its link goes silent; a new session leaves from 127.0.0.2, and
/// works.
#[test]
#[ignore = "the fault harness, on the loopback: about 50 s"]
fn after_a_move_the_old_link_goes_silent_and_a_new_one_leaves_from_the_new_address() {
    let session = Session::start("move");
    let Some(cell) = cell(&session, "normal") else { return };
    let relay = cell.args.iter().position(|a| a == "--relay-host").map(|i| cell.args[i + 1].clone()).unwrap();
    let port = relay.rsplit_once(':').unwrap().1.to_string();
    let python = ["python3", "python"].into_iter().find(|p| throughput_harness::found(p, &["--version"])).unwrap();
    let port_file = session.home.join("proxy.port");
    let log = session.home.join("proxy.log");
    let proxy = std::process::Command::new(python)
        .arg(throughput_harness::scripts().join("fake-proxy.py"))
        .arg("--port-file")
        .arg(&port_file)
        .arg("--log")
        .arg(&log)
        .arg("--map")
        .arg(format!("relay-a.test=127.0.0.1:{port}"))
        .arg("--move")
        .arg("3:127.0.0.2")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the stand-in proxy");
    session.keep(proxy);
    let deadline = Instant::now() + Duration::from_secs(30);
    let proxy_port = loop {
        if let Some(p) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
            break p;
        }
        assert!(Instant::now() < deadline, "the stand-in proxy did not start");
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut args = unpinned(&cell);
    args.push("sink".into());
    let started = Instant::now();
    // The machine's proxy variables go: podssh reads https_proxy first.
    let mut held = throughput_harness::without_proxy(session.command(&args))
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy_port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    // stdin stays open: the session waits, and its link goes silent at the
    // move.
    let _stdin = held.stdin.take();
    let code = loop {
        if let Some(status) = held.try_wait().unwrap() {
            break status.code().unwrap_or(-1);
        }
        assert!(started.elapsed() < LIMIT, "the session outlived its silent link");
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut err = String::new();
    let _ = held.stderr.take().unwrap().read_to_string(&mut err);
    assert_eq!(code, 255, "{err}");
    assert!(err.contains("relay"), "{err}");
    let mut args = unpinned(&cell);
    args.push("greet".into());
    let out = throughput_harness::without_proxy(session.command(&args))
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy_port}"))
        .stdin(Stdio::null())
        .output()
        .expect("podssh runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, GREETING.as_bytes());
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(logged.contains("from 127.0.0.2"), "the new tunnel's address: {logged}");
}

/// The lines that the test server's `append` left in `file`.
fn runs_in(file: &std::path::Path) -> usize {
    std::fs::read_to_string(file).map_or(0, |text| text.lines().count())
}

/// A drop of the relay during the SSH handshake, before any request (T-025):
/// the relay lost the target, so podssh tries once more and says so; the
/// command's status comes back, and the command ran once.
#[test]
#[ignore = "the fault harness, on the loopback: about 10 s"]
fn a_drop_before_the_request_is_tried_again_and_the_command_runs_once() {
    let session = Session::start("dropfirst");
    let Some(cell) = cell(&session, "dropfirst:20:1011") else { return };
    // In the home, which the session removes when it ends.
    let file = session.home.join("ran");
    let ran = ssh(&session, &cell, &[], &format!("append {} 5 0", file.display()), None);
    assert_eq!(ran.code, 5, "{}", ran.err);
    assert_eq!(ran.err.matches("so podssh tries once more").count(), 1, "{}", ran.err);
    assert_eq!(runs_in(&file), 1, "{}", ran.err);
}

/// A drop after the command was asked for is no failure to try again: the
/// server may have run it. 255, no try, and the command ran once; a plant
/// that tries in each phase runs it twice.
#[test]
#[ignore = "the fault harness, on the loopback: about 10 s"]
fn a_drop_after_the_request_is_not_tried_again() {
    let session = Session::start("dropafter");
    let Some(cell) = cell(&session, "dropfirstat:3:1011") else { return };
    // In the home, which the session removes when it ends.
    let file = session.home.join("ran");
    let ran = ssh(&session, &cell, &[], &format!("append {} 0 30", file.display()), None);
    assert_eq!(ran.code, 255, "{}", ran.err);
    assert!(!ran.err.contains("so podssh tries"), "{}", ran.err);
    assert_eq!(runs_in(&file), 1, "{}", ran.err);
}

/// The relay's check of a slow client (T-062): once more than 256 bytes
/// wait for podssh, in the handshake, the stand-in closes `1013 client
/// receive backlog`, as the relay's source does at 2 MiB. podssh ends with
/// 255, names the close and what makes it, and tries on no other host: a
/// backlog is no drop, and a new session would meet the same reader.
#[test]
#[ignore = "the fault harness, on the loopback: a few seconds"]
fn a_backlog_at_the_relay_ends_the_run_and_is_never_tried_again() {
    let session = Session::start("backlog");
    let Some(cell) = cell(&session, "backlog:256:1024") else { return };
    let ran = ssh(&session, &two_hosts(cell), &[], "greet", None);
    assert_eq!(ran.code, 255, "{}", ran.err);
    assert!(ran.err.contains("relay close 1013: client receive backlog"), "{}", ran.err);
    assert!(ran.err.contains("2 MiB wait for podssh"), "{}", ran.err);
    assert!(!ran.err.contains("so podssh tries"), "{}", ran.err);
}

/// The window of 512 KiB keeps what waits for podssh under the relay's
/// 2 MiB (T-062): at 256 KiB/s from a queue with no bound, 4 MB come whole
/// and no Close comes. A window of 4 MiB would let the server put 4 MiB in
/// the queue.
#[test]
#[ignore = "the fault harness, on the loopback: about 20 s"]
fn the_window_keeps_what_waits_under_the_relay_s_check() {
    let session = Session::start("window");
    let Some(cell) = cell(&session, "backlog:2097152:262144") else { return };
    let ran = ssh(&session, &cell, &[], "source 4000000", None);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(ran.out.len(), 4_000_000, "{}", ran.err);
}

#[test]
#[ignore = "the fault harness, on the loopback: a few seconds"]
fn a_relay_whose_issuer_podssh_does_not_trust_ends_with_what_to_do() {
    let session = Session::start("issuer");
    let Some(cell) = cell(&session, "normal") else { return };
    let cell = untrusted(cell);
    let ran = ssh(&session, &cell, &[], "true", None);
    let says = |err: &str| err.contains("UnknownIssuer") && err.contains("--ca-file FILE or SSL_CERT_FILE");
    assert!(ran.code != 0 && says(&ran.err), "ssh: {}: {}", ran.code, ran.err);
    // podssh proxy, through the same relay arguments.
    let relay: Vec<String> = cell.args.windows(2).filter(|w| w[0].starts_with("--relay-")).flatten().cloned().collect();
    let mut args = vec!["proxy".to_string()];
    args.extend(relay);
    args.extend(["127.0.0.1".to_string(), "22".to_string()]);
    let done = session.command(&args).stdin(Stdio::null()).output().expect("podssh runs");
    let err = String::from_utf8_lossy(&done.stderr);
    assert!(!done.status.success() && says(&err), "proxy: {:?}: {err}", done.status);
    // podssh doctor, with the same relay: its line of the relay says it too.
    let mut args = vec!["doctor".to_string()];
    args.extend(cell.args.windows(2).filter(|w| w[0].starts_with("--relay-")).flatten().cloned());
    let done = session.command(&args).stdin(Stdio::null()).output().expect("podssh runs");
    let out = String::from_utf8_lossy(&done.stdout);
    assert!(!done.status.success() && says(&out), "doctor: {:?}: {out}", done.status);
}

#[test]
#[ignore = "the fault harness, on the loopback: a few seconds"]
fn a_relay_whose_certificate_has_expired_names_this_hosts_clock() {
    let session = Session::start("clock");
    let cell = match Cell::fake_relay_expired(&session) {
        Ok(cell) => cell,
        Err((_, why)) => return eprintln!("skipped: {why}"),
    };
    let says = |err: &str| err.contains("this host's clock, which reads") && err.contains(" GMT");
    let ran = ssh(&session, &cell, &[], "true", None);
    assert!(ran.code != 0 && says(&ran.err), "ssh: {}: {}", ran.code, ran.err);
    let relay: Vec<String> = cell
        .args
        .windows(2)
        .filter(|w| w[0].starts_with("--relay-") || w[0] == "--ca-file")
        .flatten()
        .cloned()
        .collect();
    let mut args = vec!["proxy".to_string()];
    args.extend(relay.clone());
    args.extend(["127.0.0.1".to_string(), "22".to_string()]);
    let done = session.command(&args).stdin(Stdio::null()).output().expect("podssh runs");
    let err = String::from_utf8_lossy(&done.stderr);
    assert!(!done.status.success() && says(&err), "proxy: {:?}: {err}", done.status);
    // podssh cp, to the same far end through the same relay.
    let here = session.home.join("clock-copy.bin");
    std::fs::write(&here, b"a byte or two").expect("a file to copy");
    let mut args =
        vec!["cp".to_string(), "--timeout".to_string(), "60s".to_string(), "-P".to_string(), session.port.to_string()];
    args.extend(session.common());
    args.extend(relay);
    args.extend([here.display().to_string(), "tester@127.0.0.1:clock-copy.bin".to_string()]);
    let done = session.command(&args).stdin(Stdio::null()).output().expect("podssh runs");
    let err = String::from_utf8_lossy(&done.stderr);
    assert!(!done.status.success() && says(&err), "cp: {:?}: {err}", done.status);
}
