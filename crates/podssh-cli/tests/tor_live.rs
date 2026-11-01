//! The Tor road on Tor's public network (T-353; the operator's ruling of Q60:
//! short runs, from GitHub Actions and a session's own host). One bootstrap
//! of Arti, then one stream to `github.com:22`, twice: `podssh proxy
//! tor://github.com:22` must give GitHub's SSH banner. Each run's time to
//! the banner is printed, the first with the bootstrap and the fetch of the
//! directory, the second from the cached directory (step 4's measurement
//! within the ruling; no throughput, which would take more than one short
//! stream). On request only:
//!
//! ```sh
//! cargo test -p podssh-cli --features tor --test tor_live -- --ignored --nocapture
//! ```
#![cfg(feature = "tor")]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A bootstrap from nothing fetches the directory: minutes, at worst.
const LIMIT: Duration = Duration::from_secs(300);

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-tor-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One `podssh proxy tor://github.com:22`: the first line that came back,
/// the time to it, and what podssh said, within the limit.
fn banner(home: &Path) -> (String, Duration, String) {
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["proxy", "tor://github.com:22"])
        .env("HOME", home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", "none")
        .env("PODSSH_CACHE_DIR", home.join("cache"))
        .env_remove("PODSSH_TOR_NETWORK")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while let Ok(1) = out.read(&mut byte) {
            line.push(byte[0]);
            if byte[0] == b'\n' || line.len() > 255 {
                break;
            }
        }
        let _ = tx.send((String::from_utf8_lossy(&line).trim().to_string(), started.elapsed()));
    });
    let (line, took) = rx.recv_timeout(LIMIT).unwrap_or_default();
    let _ = child.kill();
    let mut said = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut said);
    let _ = child.wait();
    (line, took, said)
}

#[test]
#[ignore = "network: Tor's public network, one bootstrap and one stream to github.com:22 (Q60)"]
fn github_s_banner_through_tor_s_public_network() {
    let home = scratch();
    let (first, took, said) = banner(&home);
    println!("tor live: first run (a bootstrap from nothing): {first:?} in {:.1} s", took.as_secs_f64());
    assert!(first.starts_with("SSH-2.0-"), "no SSH banner through Tor: {first:?}; podssh said: {said}");
    let (second, took, said) = banner(&home);
    println!("tor live: second run (the cached directory): {second:?} in {:.1} s", took.as_secs_f64());
    assert!(second.starts_with("SSH-2.0-"), "no SSH banner the second time: {second:?}; podssh said: {said}");
    let _ = std::fs::remove_dir_all(&home);
}
