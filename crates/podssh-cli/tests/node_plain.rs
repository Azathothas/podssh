//! `podssh node --plain` (T-263) from end to end, through the stand-in
//! relay's reverse road on the loopback: a plain node carries TARGET's bytes
//! as they come, with no `GREETING`, and the default node greets with the
//! resumable layer. `podssh ssh -v node://` says which it found, and logs in
//! to the tests' SSH server through each. Each check says that it did not
//! run when this host has no Python or no openssl for the stand-in.

mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;

use throughput_harness::{lines_of, wait_for, Cell, Session};

/// A node of the stand-in relay in front of the tests' SSH server, with
/// `extra` flags, and `podssh ssh -v node://tester@lab greet` through it:
/// the client's exit code, stdout and stderr, and the node's first line.
fn through_a_node(tag: &str, extra: &[&str]) -> Option<(i32, String, String, String)> {
    let session = Session::start(tag);
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[String]| {
        let mut cmd = session.command(args);
        cmd.env("SSL_CERT_FILE", &ca);
        cmd
    };
    let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay];
    args.extend(pins.iter().cloned());
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port)];
    args.extend(pins.iter().cloned());
    args.extend(extra.iter().map(|a| a.to_string()));
    let mut node = command(&args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let first = wait_for(&lines, "serving").expect("the node starts");
    // The relay has the node's socket only from this line on.
    wait_for(&lines, "online").expect("the node is online");
    let mut args = vec!["ssh".to_string(), "-v".into()];
    args.extend(session.common());
    args.extend(pins);
    args.extend(["node://tester@lab".to_string(), "greet".into()]);
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    Some((out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr), first))
}

#[test]
fn a_plain_node_carries_target_s_bytes_with_no_layer() {
    let Some((code, out, err, first)) = through_a_node("plain", &["--plain"]) else { return };
    assert!(first.contains("in plain mode, with no resumable layer"), "the node names its mode: {first}");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, ssh_harness::GREETING, "{err}");
    assert!(err.contains("the far end offers no resumable layer"), "TARGET's bytes came first: {err}");
}

#[test]
fn the_default_node_greets_with_the_layer_and_is_not_plain() {
    let Some((code, out, err, first)) = through_a_node("layered", &[]) else { return };
    assert!(first.contains("with the resumable layer"), "the node names its mode: {first}");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, ssh_harness::GREETING, "{err}");
    assert!(err.contains("the layer's features"), "the node greeted: {err}");
    assert!(!err.contains("offers no resumable layer"), "{err}");
}
