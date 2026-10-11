//! The routes of a node (T-089) from end to end, through the stand-in
//! relay's reverse road on the loopback: one pair and one node offer two TCP
//! services and the tests' SSH server, each under its route; an operator
//! names one as `NAME/ROUTE`, and `podssh ssh` as `node://NAME/ROUTE`. The
//! allowlist grants routes by key, read again for each session. Each check
//! says that it did not run when this host has no Python or no openssl for
//! the stand-in.

mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use throughput_harness::{lines_of, wait_for, Cell, Session};

/// A TCP service that writes `word` to each connection, and counts them.
fn service(word: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = stream.write_all(word.as_bytes());
        }
    });
    (port, count)
}

/// What an operator got: its exit code, stdout and stderr.
fn ran(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

#[test]
fn routes_reach_their_own_target_as_the_allowlist_grants() {
    let session = Session::start("routes");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    // The pins go before a command's words, as `ssh` takes each word after
    // its destination for the remote command.
    let command = |args: &[String]| {
        let mut cmd = session.command(&args[..1]);
        cmd.env("SSL_CERT_FILE", &ca).args(&pins).args(&args[1..]);
        cmd
    };
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let (rc, _, err) = ran(&mut command(&words(&["relay", "pair", "lab", "--relay-host", &relay])));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    let ((web, web_seen), (db, db_seen)) = (service("web\n"), service("db\n"));
    // In a directory of its own: the node refuses an allowlist that others
    // can change, as this host's temporary directory lets them.
    let private = session.home.join("private");
    podssh_relay::cache::private_dir(&private).unwrap();
    let allow = private.join("allow");
    std::fs::write(&allow, "# no key yet\n").unwrap();
    let node_args = words(&[
        "node",
        "lab",
        &format!("web=127.0.0.1:{web}"),
        &format!("db=127.0.0.1:{db}"),
        &format!("ssh=127.0.0.1:{}", session.port),
        "--allow",
        &allow.display().to_string(),
    ]);
    let mut node = command(&node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let first = wait_for(&lines, "serving").expect("the node starts");
    assert!(first.contains(&format!("web=127.0.0.1:{web}")), "the first line names each route: {first}");
    wait_for(&lines, "online").expect("the node is online");
    let operator = |name: &str| ran(&mut command(&words(&["operator", name])));
    // No key in the allowlist: this client's key is refused, and named.
    let (rc, _, err) = operator("lab/web");
    assert_ne!(rc, 0, "{err}");
    // The key of the refusal's line: an earlier line names it too, with a
    // `;` after it.
    let refused = err.lines().find(|l| l.contains("refused this client's key")).expect("the refusal names the key");
    let fingerprint = refused.split_whitespace().find(|w| w.starts_with("SHA256:")).expect("the client's key");
    let fingerprint = fingerprint.trim_end_matches([':', ';']).to_string();
    std::fs::write(&allow, format!("{fingerprint} routes=web,ssh the test's client\n")).unwrap();
    let (web_dials, db_dials) = (web_seen.load(Ordering::SeqCst), db_seen.load(Ordering::SeqCst));
    // Its route: that target alone.
    let (rc, out, err) = operator("lab/web");
    let said = || lines.try_iter().collect::<Vec<_>>().join("\n");
    assert_eq!((rc, out.as_str()), (0, "web\n"), "{err}\nthe node:\n{}", said());
    // A route that the key may not use, one that the node does not have, and
    // none with no target of that kind: refused alike, and nothing dialled.
    for (name, says) in [
        ("lab/db", "may not use the route db"),
        ("lab/nope", "may not use the route nope"),
        ("lab", "name one, as NAME/ROUTE"),
    ] {
        let (rc, out, err) = operator(name);
        assert_ne!(rc, 0, "{name}: {err}");
        assert!(err.contains(says) && out.is_empty(), "{name}: {err}");
    }
    assert_eq!(db_seen.load(Ordering::SeqCst), db_dials, "a refused route was dialled");
    assert_eq!(web_seen.load(Ordering::SeqCst), web_dials + 1);
    // A change of the allowlist holds for the next session.
    std::fs::write(&allow, format!("{fingerprint} routes=* the test's client\n")).unwrap();
    let (rc, out, err) = operator("lab/db");
    assert_eq!((rc, out.as_str()), (0, "db\n"), "{err}");
    // podssh ssh names a route too, and its host key under its own name.
    let mut args = vec!["ssh".to_string()];
    args.extend(session.common());
    args.extend(words(&["node://tester@lab/ssh", "greet"]));
    let (rc, out, err) = ran(&mut command(&args));
    assert_eq!((rc, out.as_str()), (0, ssh_harness::GREETING), "{err}");
    let known = std::fs::read_to_string(session.home.join("known_hosts")).unwrap_or_default();
    assert!(known.contains("node://lab/ssh") || err.contains("node://lab/ssh"), "{known} {err}");
}
