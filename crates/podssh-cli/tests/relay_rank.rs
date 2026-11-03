//! `podssh relay rank` (T-606) as a process, against two stand-in relays of
//! `scripts/fake-relay.py`: one that behaves and one that answers each
//! upgrade 600 ms late (`slowopen:600`), named slow first. The rank puts the
//! fast one first, names a host that answers nothing, keeps its file in the
//! cache, private and with no token, and `--cached` reads it back with no
//! connection; `--forget` removes it. With `PODSSH_OFFLINE`, 69 before any
//! connection; a bad flag, 64. The checks say that they did not run when
//! this host has no Python or no openssl for the stand-in.

// The rank in a session's background, with RelayRank auto alone (T-608).
mod rank_background;
mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(180);

fn relay(home: &Path, args: &[String]) -> Command {
    let mut all = vec!["relay".to_string()];
    all.extend(args.iter().cloned());
    podssh(home, &all)
}

/// podssh with HOME and the cache under `home`, and no proxy and no token
/// from this host's environment: the rank's egress is `direct`.
fn podssh(home: &Path, all: &[String]) -> Command {
    let mut cmd = throughput_harness::command_in(home, all);
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

/// A target of the stand-in's sessions that greets each with SSH's line and
/// holds it open until its client goes, as GitHub's SSH port does.
fn banner_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let _ = stream.write_all(b"SSH-2.0-stand-in-target\r\n");
                let _ = std::io::copy(&mut stream, &mut std::io::sink());
            });
        }
    });
    port
}

/// The `--relay-host` of a stand-in cell, and its `--ca-file`.
fn host_of(cell: &Cell) -> (String, String) {
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    (at("--relay-host"), at("--ca-file"))
}

/// The files named `name` under `dir`.
fn found(dir: &Path, name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(found(&path, name));
        } else if path.file_name().is_some_and(|n| n == name) {
            out.push(path);
        }
    }
    out
}

#[test]
fn the_rank_puts_the_fast_host_first_and_keeps_it() {
    let s = Session::start("relay-rank");
    let (fast, slow) = match (
        Cell::fake_relay_mode(&s, "normal", "the stand-in relay"),
        Cell::fake_relay_mode(&s, "slowopen:600", "the stand-in relay, slow to open"),
    ) {
        (Ok(fast), Ok(slow)) => (fast, slow),
        (Err((_, why)), _) | (_, Err((_, why))) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let ((fast, ca), (slow, _)) = (host_of(&fast), host_of(&slow));
    // A host that answers nothing: a port that nothing holds, for a moment.
    let gone = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let gone = format!("relay-a.test:{gone}");
    let target = format!("127.0.0.1:{}", banner_target());
    let flags = [
        "--ca-file".to_string(),
        ca,
        "--relay-addr".into(),
        "relay-a.test=127.0.0.1".into(),
        "--relay-host".into(),
        format!("{slow},{gone},{fast}"),
        "--target".into(),
        target,
    ];
    let mut args = words(&["rank", "--rounds", "3", "--count", "2"]);
    args.extend(flags.iter().cloned());
    let out = ran(relay(&s.home, &args));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "{stdout}");
    assert!(lines[0].starts_with(&format!(" 1 {fast}: opened 3 of 3")), "{stdout}");
    assert!(lines[1].starts_with(&format!(" 2 {slow}: opened 3 of 3")), "{stdout}");
    assert!(lines[2].starts_with(&format!(" 3 {gone}: opened 0 of 3")), "{stdout}");
    assert_eq!(stderr.matches("rank 3/3 ").count(), 3, "a line for each probe: {stderr}");
    assert!(stderr.contains("kept in the cache; it holds 24 h for this egress"), "{stderr}");
    // The file: private, with no token.
    let files = found(&s.home, "relay-rank.json");
    assert_eq!(files.len(), 1, "{files:?}");
    let kept = std::fs::read_to_string(&files[0]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let doc: serde_json::Value = serde_json::from_str(&kept).unwrap();
    assert_eq!((doc["named"].as_bool(), doc["egress"].as_str()), (Some(true), Some("direct")), "{kept}");
    for file in std::fs::read_dir(files[0].parent().unwrap()).unwrap().flatten() {
        let name = file.file_name().into_string().unwrap();
        if name.starts_with("relay-token-") {
            let token: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
            let secret = token["token"].as_str().unwrap_or_default();
            assert!(!secret.is_empty() && !kept.contains(secret), "the rank keeps no token");
        }
    }
    // --cached: no connection, even offline; --json, one object.
    let mut offline = relay(&s.home, &words(&["rank", "--cached"]));
    offline.env("PODSSH_OFFLINE", "1");
    let out = ran(offline);
    let cached = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(cached.starts_with("rank of 3 hosts to 127.0.0.1:"), "{cached}");
    assert!(cached.contains("for this egress: it holds"), "{cached}");
    assert!(cached.lines().nth(1).is_some_and(|l| l.contains(&fast)), "{cached}");
    let out = ran(relay(&s.home, &words(&["rank", "--cached", "--json"])));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!((doc["holds"].as_bool(), doc["hosts"][0]["host"].as_str()), (Some(true), Some(fast.as_str())));
    // podssh status names it, with no connection.
    let mut status = podssh(&s.home, &words(&["status"]));
    status.env("PODSSH_OFFLINE", "1");
    let out = ran(status);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("status is one JSON object");
    let rank = &doc["relay_rank"];
    assert_eq!((rank["first"].as_str(), rank["hosts"].as_u64()), (Some(fast.as_str()), Some(3)), "{rank}");
    assert_eq!((rank["holds"].as_bool(), rank["named"].as_bool()), (Some(true), Some(true)), "{rank}");
    // --forget: gone.
    let out = ran(relay(&s.home, &words(&["rank", "--forget"])));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(found(&s.home, "relay-rank.json").is_empty());
    let out = ran(relay(&s.home, &words(&["rank", "--cached"])));
    assert_eq!(out.status.code(), Some(69), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no rank is kept"), "{}", text(&out.stderr));
    let mut status = podssh(&s.home, &words(&["status"]));
    status.env("PODSSH_OFFLINE", "1");
    let doc: serde_json::Value = serde_json::from_slice(&ran(status).stdout).unwrap();
    assert!(doc["relay_rank"].is_null(), "{}", doc["relay_rank"]);
}

#[test]
fn offline_and_bad_flags_refuse_before_anything_connects() {
    let s = Session::start("relay-rank-refuse");
    let (port, reached) = counting_listener();
    let host = format!("127.0.0.1:{port}");
    let mut offline = relay(&s.home, &words(&["rank", "--relay-host", &host]));
    offline.env("PODSSH_OFFLINE", "1");
    let out = ran(offline);
    assert_eq!(out.status.code(), Some(69), "{}", text(&out.stderr));
    let cases: [(&[&str], &str); 7] = [
        (&["rank", "--rounds", "0"], "a number from 1 to 20"),
        (&["rank", "--rounds", "21"], "a number from 1 to 20"),
        (&["rank", "--count", "x"], "a number from 1 to 20"),
        (&["rank", "--target", "a&b:22"], "--target"),
        (&["rank", "extra"], "rank takes no NAME"),
        (&["rank", "--cached", "--forget"], "give one"),
        (&["status", "--rounds", "2"], "go with `podssh relay rank` only"),
    ];
    for (args, says) in cases {
        let mut all = words(args);
        all.extend(["--relay-host".to_string(), host.clone()]);
        let out = ran(relay(&s.home, &all));
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0, "nothing connects before the flags are checked");
}

/// A target that sends one line and closes: a `proxy` run then ends.
fn line_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            let _ = stream.write_all(b"SSH-2.0-stand-in-target\r\n");
        }
    });
    port
}

/// T-607: each attempt of a race that opened leaves a sample of its time in
/// the rank's file, with no connection of its own: a run of `proxy
/// --relay-failover parallel` over the slow stand-in and the fast one, named
/// in that order, keeps one of each, the slow one's 600 ms longer.
#[test]
fn a_race_keeps_a_sample_of_each_host_that_opened() {
    let s = Session::start("relay-rank-samples");
    let (fast, slow) = match (
        Cell::fake_relay_mode(&s, "normal", "the stand-in relay"),
        Cell::fake_relay_mode(&s, "slowopen:600", "the stand-in relay, slow to open"),
    ) {
        (Ok(fast), Ok(slow)) => (fast, slow),
        (Err((_, why)), _) | (_, Err((_, why))) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let ((fast, ca), (slow, _)) = (host_of(&fast), host_of(&slow));
    let target = line_target().to_string();
    let args = words(&[
        "proxy",
        "--relay-failover",
        "parallel",
        "--relay-host",
        &format!("{slow},{fast}"),
        "--ca-file",
        &ca,
        "--relay-addr",
        "relay-a.test=127.0.0.1",
        "127.0.0.1",
        &target,
    ]);
    let out = ran(podssh(&s.home, &args));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).starts_with("SSH-2.0-stand-in-target"), "{}", text(&out.stdout));
    let files = found(&s.home, "relay-rank.json");
    assert_eq!(files.len(), 1, "{files:?}");
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&files[0]).unwrap()).unwrap();
    let time = |host: &str| doc["samples"][host][0]["open_ms"].as_f64();
    let (fast_ms, slow_ms) = (time(&fast), time(&slow));
    assert!(fast_ms.is_some() && slow_ms.is_some(), "a sample of each: {doc}");
    assert!(slow_ms.unwrap() - fast_ms.unwrap() >= 500.0, "the slow one's 600 ms: {doc}");
    assert_eq!(doc["samples"][&fast][0]["egress"], "direct", "{doc}");
    // No rank was made: the file holds the samples alone, and nothing holds.
    assert!(doc["hosts"].as_array().is_none_or(|h| h.is_empty()), "{doc}");
    // status says which order a run of the default list takes: the samples,
    // or none with PODSSH_RELAY_RANK=no.
    let order = |off: bool| {
        let mut status = podssh(&s.home, &words(&["status"]));
        status.env("PODSSH_OFFLINE", "1");
        if off {
            status.env("PODSSH_RELAY_RANK", "no");
        }
        let doc: serde_json::Value = serde_json::from_slice(&ran(status).stdout).expect("status is one JSON object");
        doc["relay_order"].as_str().map(str::to_string)
    };
    assert_eq!(order(false).as_deref(), Some("samples"));
    assert_eq!(order(true).as_deref(), Some("off"));
}
