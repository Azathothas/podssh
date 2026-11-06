//! `podssh relay status`, `info` and `trace` against the live relay
//! (T-058), and the warning before its idle cut (T-463), on request, as they
//! reach the network:
//!
//! ```sh
//! cargo test -p podssh-cli --test relay_live -- --ignored
//! ```
//!
//! Each run has a scratch cache, so a token minted for it goes with it.

mod cleanup;

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(180);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-relay-live-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh relay ARGS` with a scratch HOME and cache, within [`LIMIT`].
fn relay(name: &str, args: &[&str]) -> Output {
    let home = scratch(name);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("relay").args(args);
    cmd.env("HOME", &home).env("USERPROFILE", &home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    for name in ["PODSSH_OFFLINE", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
        cmd.env_remove(name);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh relay {args:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
#[ignore = "reaches the live relay"]
fn status_reads_the_health_of_the_default_relay() {
    let out = relay("status", &["status"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    let first = stdout.lines().next().unwrap_or_default();
    assert!(first.starts_with(&format!("{}: tcp-ssh-relay ", podssh_relay::default_relay_host())), "{stdout}");
    assert!(first.contains("certificate verified"), "{stdout}");
}

#[test]
#[ignore = "reaches the live relay"]
fn info_ranks_the_pool_for_github() {
    let out = relay("info", &["info", "github.com", "22", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert_eq!(doc["info"]["service"], "tcp-ssh-relay");
    assert_eq!(doc["info"]["target"]["host"], "github.com");
    assert!(doc["info"]["pool"].as_array().is_some_and(|p| !p.is_empty()), "{doc}");
    assert!(doc["info"]["limits"]["max_session_bytes"].as_u64().is_some(), "{doc}");
}

#[test]
#[ignore = "reaches the live relay"]
fn trace_reads_githubs_banner_through_the_relay() {
    let out = relay("trace", &["trace", "github.com", "22"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    assert!(stdout.contains(": live;"), "{stdout}");
    assert!(stdout.lines().any(|l| l.starts_with("banner: SSH-2.0-")), "{stdout}");
    // A target in a blocked range: the relay refuses to dial it.
    let out = relay("trace-blocked", &["trace", "10.0.0.1", "22"]);
    assert_eq!(out.status.code(), Some(69), "{}", text(&out.stdout));
    assert!(text(&out.stdout).contains("the relay did not dial it"), "{}", text(&out.stdout));
}

/// GitHub #98 (T-463), through the live relay to the operator's server of
/// `PODSSH_THROUGHPUT_SSH` (`USER@HOST[:PORT]`, with the key of
/// `PODSSH_THROUGHPUT_KEY`), 3 minutes with nothing sent: with
/// `ServerAliveInterval=0`, the warning at about 150 s, then the relay's
/// idle cut at about 180 s, each once. A run with no server named fails: a
/// skip would read as a pass.
#[test]
#[ignore = "the live relay, 3 minutes, and the server of PODSSH_THROUGHPUT_SSH"]
fn idle_warn_comes_before_the_relays_idle_cut() {
    use std::io::{BufRead, BufReader};
    let target = std::env::var("PODSSH_THROUGHPUT_SSH").ok().filter(|t| !t.trim().is_empty());
    let target = target.expect("PODSSH_THROUGHPUT_SSH names no server (Q38): this run needs one");
    let home = scratch("idle-warn");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "-o", "ServerAliveInterval=0", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]);
    cmd.arg("-o").arg(format!("UserKnownHostsFile={}", home.join("known_hosts").display()));
    if let Ok(key) = std::env::var("PODSSH_THROUGHPUT_KEY") {
        cmd.args(["-i", &key, "-o", "IdentitiesOnly=yes"]);
    }
    match target.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => cmd.args(["-p", port, host]),
        _ => cmd.arg(&target),
    };
    cmd.arg("sleep 200; echo alive");
    cmd.env("HOME", &home).env("USERPROFILE", &home).env("PODSSH_SSH_CONFIG", "none");
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    for name in ["PODSSH_OFFLINE", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let started = Instant::now();
    let stderr = child.stderr.take().unwrap();
    // Each line of stderr with the time that it came.
    let lines = std::thread::spawn(move || {
        BufReader::new(stderr).lines().map_while(Result::ok).map(|l| (started.elapsed(), l)).collect::<Vec<_>>()
    });
    let deadline = started + Duration::from_secs(260);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh ssh did not end within 260 s");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let code = child.wait().unwrap().code();
    let lines = lines.join().unwrap();
    let said = |words: &str| lines.iter().filter(|(_, l)| l.contains(words)).collect::<Vec<_>>();
    let warned = said("the relay ends this session in");
    assert_eq!(warned.len(), 1, "one warning: {lines:?}");
    let at = warned[0].0;
    assert!(at >= Duration::from_secs(140) && at <= Duration::from_secs(165), "the warning at {at:?}: {lines:?}");
    let cut = said("idle");
    assert!(cut.iter().any(|(t, _)| *t > at), "the relay's idle cut after the warning: {lines:?}");
    assert_eq!(code, Some(255), "{lines:?}");
}
