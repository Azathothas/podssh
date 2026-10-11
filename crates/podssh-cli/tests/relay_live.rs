//! `podssh relay status`, `info` and `trace` against the live relay
//! (T-058), on request, as they reach the network:
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
    assert!(first.starts_with(&format!("{}: tcp-ssh-relay ", podssh_relay::DEFAULT_RELAY_HOST)), "{stdout}");
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
