//! `podssh doctor` against a stand-in relay (`scripts/fake-relay.py`) whose
//! upgrade fails in one of three ways (T-324, GitHub #54): a refusal, a 101
//! whose `Sec-WebSocket-Accept` is not the key's, and a valid 101 after
//! which the connection ends with no Close. Each has its own way out, so
//! the forward line names each as its own. The checks say that they did not
//! run when this host has no Python or no openssl for the stand-in.

mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

/// The forward line of `podssh doctor` through a stand-in relay of `mode`,
/// or `None` when the stand-in cannot run here.
fn forward_line(s: &Session, mode: &str) -> Option<String> {
    let cell = match Cell::fake_relay_mode(s, mode, mode) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let ca = at("--ca-file");
    let args: Vec<String> =
        ["doctor", "--relay-host", &at("--relay-host"), "--relay-addr", "relay-a.test=127.0.0.1", "--ca-file", &ca]
            .map(String::from)
            .to_vec();
    let mut cmd = s.stand_in(&args, &ca);
    cmd.env_remove("PODSSH_RELAY_TOKEN").env_remove("PODSSH_RELAY");
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh doctor still ran after 120 s ({mode})");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(1), "{mode}: {text}{}", String::from_utf8_lossy(&out.stderr));
    let line = text.lines().find(|l| l.contains(" forward ")).unwrap_or_else(|| panic!("{mode}: {text}"));
    assert!(line.starts_with("  FAIL  forward"), "{mode}: {line}");
    Some(line.to_string())
}

#[test]
fn the_three_failures_of_the_upgrade_are_named_apart() {
    let s = Session::start("doctor-upgrade");
    let Some(refused) = forward_line(&s, "refuse:403") else { return };
    // The status and the body's line, and nothing of the other two.
    assert!(refused.contains("HTTP 403") && refused.contains("refused by fault injection"), "{refused}");
    assert!(!refused.contains("Sec-WebSocket-Accept") && !refused.contains("upgrade passed"), "{refused}");

    let Some(stranger) = forward_line(&s, "badaccept") else { return };
    assert!(stranger.contains("Sec-WebSocket-Accept was"), "{stranger}");
    assert!(stranger.contains("answered in the relay's place"), "{stranger}");
    assert!(!stranger.contains("HTTP 403") && !stranger.contains("upgrade passed"), "{stranger}");

    let Some(cut) = forward_line(&s, "hangup:200") else { return };
    assert!(cut.contains("the upgrade passed (101, with this request's accept)"), "{cut}");
    assert!(cut.contains("s later with no Close") && cut.contains("drops the stream after the upgrade"), "{cut}");
    assert!(!cut.contains("HTTP 403") && !cut.contains("in the relay's place"), "{cut}");
}
