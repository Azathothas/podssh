//! What a user feels (T-660), as `podssh ping` measures it. Through the
//! stand-in relay shaped as osewa's cellular link (`profile:cellular` of
//! `scripts/fake_shape.py`: 60 ms, 10 Mbit/s and a deep queue),
//! `--under-load` reads an echo beside the download above the idle one, with
//! the raw time of each key and no key of the warm-up. `--connect-runs` times
//! each cold connect, each a connection of its own. Each flag is refused
//! before anything connects where it does not apply. The shaped check says
//! that it did not run when this host has no Python or no openssl for the
//! stand-in.

use std::sync::atomic::Ordering;

use super::{counting_listener, direct, ping, ran, relay_flags_in, text};
use crate::throughput_harness::Session;

/// A figure of the JSON, or NaN, which no comparison passes.
fn figure(value: &serde_json::Value) -> f64 {
    value.as_f64().unwrap_or(f64::NAN)
}

#[test]
fn under_load_through_a_shaped_stand_in_reads_an_echo_above_the_idle_one() {
    let s = Session::start("ping-under-load");
    let Some(mut args) = relay_flags_in(&s, "profile:cellular") else { return };
    args.extend(["--target".to_string(), format!("127.0.0.1:{}", s.port)]);
    args.extend(s.common());
    args.extend(["--under-load", "--json", "-p", &s.port.to_string(), "tester@127.0.0.1"].map(String::from));
    let out = ran(ping(&s, &args));
    assert_eq!(out.status.code(), Some(0), "stdout: {}\nstderr: {}", text(&out.stdout), text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    let under = &doc["destination"]["under_load"];
    let beat = (under["keys"].as_u64(), under["gap_ms"].as_u64(), under["warmup_ms"].as_u64());
    assert_eq!(beat, (Some(40), Some(150), Some(3000)), "{under}");
    let samples = |part: &str| under[part]["samples"].as_array().cloned().unwrap_or_default();
    let (idle, loaded) = (samples("idle"), samples("loaded"));
    // Each key has its raw sample, idle and under load: none was dropped.
    assert_eq!((idle.len(), loaded.len()), (40, 40), "{under}");
    // 60 MiB at 10 Mbit/s lasts far longer than the keys: each went beside it.
    assert!(loaded.iter().all(|k| k["beside"] == true), "{under}");
    // No key of the warm-up is counted: the first went 3 s after the download started.
    let first = loaded.iter().map(|k| figure(&k["sent_ms"])).fold(f64::INFINITY, f64::min);
    assert!(first >= 3000.0, "a key went {first} ms after the download started, inside its warm-up: {under}");
    // The echo beside the download waits behind it in the link's queue.
    let (loaded_p50, idle_p95) = (figure(&under["loaded"]["p50_ms"]), figure(&under["idle"]["p95_ms"]));
    assert!(loaded_p50 > idle_p95, "under load p50 {loaded_p50} ms, idle p95 {idle_p95} ms: {under}");
    // The summary is of the raw samples: the 20th of 40 by rank is the p50.
    let mut echoes: Vec<f64> = loaded.iter().map(|k| figure(&k["echo_ms"])).collect();
    echoes.sort_by(f64::total_cmp);
    assert!((loaded_p50 - echoes[19]).abs() < 0.01, "p50 {loaded_p50}, the 20th sample {}: {under}", echoes[19]);
    assert!(under["load"]["typing_bytes"].as_u64().is_some_and(|b| b > 0), "{under}");
    assert!(under["load"]["ended_ms"].is_null(), "the download was stopped, not spent: {under}");
    // The plain measures do not run beside it.
    let far = &doc["destination"];
    assert!(far["echo"].is_null() && far["down"].is_null() && far["up"].is_null(), "{far}");
}

#[test]
fn under_load_gives_the_echo_idle_and_beside_the_download_in_lines() {
    let s = Session::start("ping-under-load-lines");
    let out = ran(ping(&s, &direct(&s, &["--under-load"], "tester")));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines[0].starts_with("ssh tester@127.0.0.1: login "), "{stdout}");
    assert!(lines[1].starts_with("echo idle (cat), 40 keys 150 ms apart: min "), "{stdout}");
    // On the bare loopback the download may end before or while the keys
    // run: the line of either says so.
    assert!(lines.get(2).is_some_and(|l| l.starts_with("echo under load")), "{stdout}");
    assert!(!lines.iter().any(|l| l.starts_with("down (") || l.starts_with("up (")), "{stdout}");
}

#[test]
fn connect_runs_time_each_cold_connect_to_the_exit_of_true() {
    let s = Session::start("ping-connect-runs");
    let flags = ["--connect-runs", "3", "--size", "64K", "--count", "2", "--json"];
    let out = ran(ping(&s, &direct(&s, &flags, "tester")));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    let connect = &doc["destination"]["connect"];
    assert_eq!((connect["runs"].as_u64(), connect["command"].as_str()), (Some(3), Some("true")), "{connect}");
    let samples = connect["samples_ms"].as_array().cloned().unwrap_or_default();
    assert_eq!(samples.len(), 3, "{connect}");
    assert!(samples.iter().all(|v| figure(v) > 0.0), "{connect}");
    assert!(figure(&connect["p50_ms"]) > 0.0, "{connect}");
    // Each run is a connection of its own, then the plain measures' login.
    assert_eq!(s.connections.load(Ordering::SeqCst), 4);
    // The plain echo keeps its raw samples too.
    assert_eq!(doc["destination"]["echo"]["samples_ms"].as_array().map(Vec::len), Some(2), "{doc}");
    // And in lines: after the login, the runs.
    let out = ran(ping(&s, &direct(&s, &["--connect-runs", "2", "--size", "64K"], "tester")));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}\n{}", text(&out.stderr));
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines[0].starts_with("ssh tester@127.0.0.1: login "), "{stdout}");
    assert!(lines[1].starts_with("connect and true, 2 runs: min "), "{stdout}");
    assert!(lines[2].starts_with("echo (cat), 10 bytes: min "), "{stdout}");
}

#[test]
fn the_measures_of_feel_are_refused_before_anything_connects() {
    let s = Session::start("ping-feel-refuse");
    let (port, reached) = counting_listener();
    let relay = ["--relay-host".to_string(), format!("127.0.0.1:{port}")];
    let with_host = |flags: &[&str]| direct(&s, flags, "tester");
    let none = |flags: &[&str]| flags.iter().map(|f| f.to_string()).chain(relay.clone()).collect::<Vec<_>>();
    let cases: [(Vec<String>, &str); 7] = [
        (with_host(&["--connect-runs", "0"]), "--connect-runs 0: from 1 to 20"),
        (with_host(&["--connect-runs", "21"]), "--connect-runs 21: from 1 to 20"),
        (with_host(&["--connect-runs", "many"]), "from 1 to 20"),
        (none(&["--under-load"]), "--under-load measures through a host"),
        (none(&["--connect-runs", "2"]), "--connect-runs measures through a host"),
        (with_host(&["--under-load", "--count", "5"]), "--count is for the plain echo and throughput"),
        (with_host(&["--under-load", "--size", "1M"]), "--size is for the plain echo and throughput"),
    ];
    for (args, says) in cases {
        let out = ran(ping(&s, &args));
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.stdout.is_empty(), "{args:?}: {}", text(&out.stdout));
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(reached.load(Ordering::SeqCst), 0, "a refused run connected to the relay host");
    assert_eq!(s.connections.load(Ordering::SeqCst), 0, "a refused run connected to the SSH server");
}
