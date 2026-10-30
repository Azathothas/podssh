//! `podssh ssh --upgrade` (T-167). Offline: what it refuses, and what
//! `podssh node --temporary` refuses. Against the tests' SSH server, where
//! `podssh --version` answers no podssh: the session stays on the first
//! connection, with one note, and no node is started. Against a server whose
//! `podssh ...` commands run the binary under test, through the stand-in
//! relay's reverse road (Python and openssl, else the check says that it did
//! not run): the session moves to the temporary node, with the same host
//! key; the offer, with the pair's connect token, came in the SSH channel
//! alone, and no argv and no output holds a token.

mod pair_harness;
mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;
use std::sync::atomic::Ordering;

use ssh_harness::podssh::Podssh;
use throughput_harness::{Cell, Session};

/// A fingerprint of the form that a client key has.
const KEY: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

/// A word with the shape of the relay's tokens: 64 of `[0-9a-z]`.
fn token_shaped(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| w.len() == 64 && w.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()))
}

#[test]
fn upgrade_refuses_what_two_connections_cannot_carry() {
    let home = pair_harness::scratch("upgrade-args");
    let mut cases = vec![
        (vec!["ssh", "--upgrade", "node://lab", "true"], "are podssh ends"),
        (vec!["ssh", "--upgrade", "--persist", "example.org"], "give one"),
        (vec!["ssh", "--upgrade", "-R", "8080:localhost:80", "example.org"], "no -R or RemoteForward"),
        (vec!["ssh", "--node-key", KEY, "--upgrade", "example.org"], "--node-key"),
        (vec!["node", "--temporary", "not-a-key"], "not a key"),
        (vec!["node", "--temporary", KEY, "--plain"], "--plain"),
        (vec!["node", "--temporary", KEY, "up", "web=127.0.0.1:22"], "one sshd"),
    ];
    // Windows refuses -O itself, before --upgrade is read: no connection is
    // shared there.
    if cfg!(unix) {
        cases
            .push((vec!["ssh", "--upgrade", "-O", "check", "-S", "/tmp/x", "example.org"], "-O asks a control master"));
    }
    for (args, says) in cases {
        let (rc, out, err) = pair_harness::podssh(&home, &args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

/// `--client-key` goes with `--upgrade`, and still not alone with a
/// standard sshd.
#[test]
fn a_client_key_goes_with_upgrade_alone() {
    let home = pair_harness::scratch("upgrade-key");
    let words = ["ssh", "--client-key", "k", "example.org", "true"];
    let (rc, _, err) = pair_harness::podssh(&home, &words, &[]);
    assert_eq!(rc, 64, "{err}");
    let words = ["ssh", "--upgrade", "--client-key", "k", "example.org", "true"];
    let (rc, _, err) = pair_harness::podssh(&home, &words, &[]);
    assert_ne!(rc, 64, "{err}");
}

#[test]
fn with_no_podssh_on_the_server_the_session_stays_with_one_note() {
    let s = Session::start("upgrade-none");
    let mut args = vec!["ssh".to_string(), "--direct".into(), "-p".into(), s.port.to_string(), "--upgrade".into()];
    args.extend(s.common());
    args.extend(["tester@127.0.0.1".to_string(), "greet".into()]);
    let out = s.command(&args).stdin(Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), ssh_harness::GREETING, "{err}");
    // One note, and no node: a client that started one with no probe says
    // another thing, and fails here.
    assert_eq!(err.matches("no podssh answers there").count(), 1, "{err}");
    assert_eq!(err.matches("stays on this connection").count(), 1, "{err}");
    assert_eq!(s.connections.load(Ordering::SeqCst), 1, "one login: {err}");
}

#[test]
fn the_session_moves_to_the_temporary_node_and_no_argv_holds_a_token() {
    let s = Session::start("upgrade-node");
    let cell = match Cell::fake_relay_mode(&s, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    // The server's podssh has a home of its own, and reaches the stand-in.
    let server = s.home.join("server");
    podssh_relay::cache::private_dir(&server.join("cache")).unwrap();
    let path = |p: &std::path::Path| p.display().to_string();
    let podssh = Podssh {
        env: vec![
            ("HOME".into(), path(&server)),
            ("USERPROFILE".into(), path(&server)),
            ("XDG_CACHE_HOME".into(), path(&server.join("cache"))),
            ("LOCALAPPDATA".into(), path(&server.join("cache"))),
            ("SSL_CERT_FILE".into(), ca.clone()),
            ("PODSSH_RELAY".into(), relay),
            ("PODSSH_RELAY_ADDR".into(), "relay-a.test=127.0.0.1".into()),
            ("PODSSH_SSH_CONFIG".into(), "none".into()),
        ],
        argv: Default::default(),
    };
    let argv = podssh.argv.clone();
    let (port, seen) = s.runtime.block_on(ssh_harness::start_podssh(&s.home.join("host_key"), podssh));
    let mut args = vec!["ssh".to_string(), "--relay-addr".into(), "relay-a.test=127.0.0.1".into()];
    args.extend(["--direct".to_string(), "-p".into(), port.to_string(), "--upgrade".into(), "-v".into()]);
    args.extend(s.common());
    args.extend(["tester@127.0.0.1".to_string(), "greet".into()]);
    let out = s.stand_in(&args, &ca).stdin(Stdio::null()).output().unwrap();
    let (stdout, err) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(stdout, ssh_harness::GREETING, "{err}");
    assert!(err.contains("the temporary node took the session"), "{err}");
    assert!(!err.contains("stays on this connection"), "{err}");
    // The first login, the node's look at sshd, and the session's own dial.
    assert_eq!(seen.load(Ordering::SeqCst), 3, "{err}");
    let argv = argv.lock().unwrap().clone();
    assert_eq!(argv.len(), 2, "the probe and the node: {argv:?}");
    assert_eq!(argv[0], ["--version"]);
    assert_eq!(&argv[1][..2], ["node", "--temporary"]);
    assert!(argv.iter().flatten().chain(&args).all(|w| !token_shaped(w)), "a token on an argv: {argv:?}");
    assert!(!token_shaped(&stdout) && !token_shaped(&err), "a token in the output: {err}");
}
