//! `podssh proxy` against the live relay. Ignored by default: it needs the
//! network and mints a relay token (self-service, cached per machine).
//!
//! ```sh
//! cargo test -p podssh-cli --test proxy_live -- --ignored
//! ```
//!
//! Honours `HTTPS_PROXY`, `PODSSH_RELAY` and `PODSSH_RELAY_TOKEN` like the
//! binary does, so it also proves the proxied path when run behind one.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore = "network: reaches github.com:22 through the live relay"]
fn the_ssh_banner_of_github_arrives_through_the_relay() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["proxy", "github.com", "22"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh starts");
    let mut stdout = child.stdout.take().unwrap();
    let started = Instant::now();
    let mut banner = Vec::new();
    let mut byte = [0u8; 1];
    // An SSH server speaks first: its version line, ending in LF.
    while !banner.ends_with(b"\n") && started.elapsed() < Duration::from_secs(30) {
        match stdout.read(&mut byte) {
            Ok(1) => banner.push(byte[0]),
            _ => break,
        }
    }
    let _ = child.kill();
    let mut stderr = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut stderr);
    let _ = child.wait();
    let line = String::from_utf8_lossy(&banner);
    assert!(line.starts_with("SSH-2.0-"), "no SSH banner; got {line:?}; stderr: {stderr}");
}
