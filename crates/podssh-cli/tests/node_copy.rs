//! `podssh cp`, `scp` and `sftp` to a node of a pair (T-296). Offline, with
//! a scratch HOME: a node operand names its pair before anything connects
//! (78 with no pair under the label, 69 at the network with one), and a
//! port, `-J` or `--direct` with a node is refused (64), as for `ssh`. From
//! end to end through the stand-in relay's reverse road on the loopback, as
//! `tests/node_routes.rs` runs it: one pair, and one node in front of the
//! test's SSH server, with a route to a second one; `cp` up and down, `scp`
//! up, and `sftp`'s put and get agree with the disk, and
//! `node://NAME/ROUTE` takes its route. That test says that it did not run
//! when this host has no Python, no openssl or no `sftp-server`.

mod pair_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use throughput_harness::{lines_of, wait_for, Cell, Session};

/// The stand-in relay's name, on the loopback.
const PINS: [&str; 2] = ["--relay-addr", "relay-a.test=127.0.0.1"];
/// The bound on each run of podssh.
const RUN_LIMIT: Duration = Duration::from_secs(180);

fn data(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect()
}

/// A node operand is the node of the pair under its label, before anything
/// connects: the store is read first, then the network, which
/// `PODSSH_OFFLINE` stops. Read as a host, `node://tester@lab:x` would be
/// the host `node`, and neither answer would come.
#[test]
fn a_node_operand_names_its_pair_and_a_port_with_a_node_is_refused() {
    let home = pair_harness::scratch("copy");
    let a = home.join("a");
    std::fs::write(&a, b"a").unwrap();
    let a = a.display().to_string();
    let script = home.join("batch");
    std::fs::write(&script, "pwd\n").unwrap();
    let script = script.display().to_string();
    let each = [
        vec!["cp", "--timeout", "30s", a.as_str(), "node://tester@lab:x"],
        vec!["scp", a.as_str(), "node://tester@lab/ssh:x"],
        vec!["sftp", "-b", script.as_str(), "node://tester@lab"],
    ];
    // No pair under the label: the remedy, and the node's name.
    for args in &each {
        let (rc, _, err) = pair_harness::podssh(&home, args, &[]);
        assert_eq!(rc, 78, "{args:?}: {err}");
        assert!(err.contains("node://lab") && err.contains("podssh relay pair lab"), "{args:?}: {err}");
    }
    // A pair under the label: as far as the network, and no token shown.
    pair_harness::store(&home, "lab", 0);
    for args in &each {
        let (rc, out, err) = pair_harness::podssh(&home, args, &[]);
        assert_eq!(rc, 69, "{args:?}: {err}");
        assert!(err.contains("node://lab") && err.contains("PODSSH_OFFLINE"), "{args:?}: {err}");
        pair_harness::no_token(&out);
        pair_harness::no_token(&err);
    }
    // The pair and the network come before the channel: no run made a key.
    let key = pair_harness::cache_dir(&home).join("client.key");
    assert!(!key.exists(), "a copy that could not go made a key of this client");
    // A port, a jump or --direct cannot reach a node, as for ssh (64).
    for (args, says) in [
        (vec!["cp", "--timeout", "30s", "-P", "2222", a.as_str(), "node://tester@lab:x"], "a node has no port"),
        (vec!["cp", "--timeout", "30s", "-J", "jump", a.as_str(), "node://tester@lab:x"], "-J hop"),
        (vec!["cp", "--timeout", "30s", "--direct", "node://tester@lab:x", "."], "--direct cannot reach a node"),
        (vec!["mv", "--timeout", "30s", "-o", "Port=2222", a.as_str(), "node://tester@lab:x"], "a node has no port"),
        (vec!["scp", "-P", "2222", a.as_str(), "node://tester@lab:x"], "a node has no port"),
        (vec!["sftp", "-P", "2222", "-b", script.as_str(), "node://tester@lab"], "a node has no port"),
        (vec!["sftp", "--direct", "-b", script.as_str(), "node://tester@lab"], "--direct cannot reach a node"),
        (vec!["cp", "--timeout", "30s", a.as_str(), "node://tester@lab/a b:x"], "is not a route"),
    ] {
        let (rc, _, err) = pair_harness::podssh(&home, &args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
}

/// `podssh ARGS` in the session's home, with the stand-in's CA and its
/// address: the code, stdout and stderr, within [`RUN_LIMIT`].
fn ran(session: &Session, ca: &str, args: &[String]) -> (i32, String, String) {
    let mut cmd = session.command(&args[..1]);
    cmd.env("SSL_CERT_FILE", ca).args(PINS).args(&args[1..]).current_dir(&session.home);
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let read = |mut from: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = from.read_to_string(&mut text);
            text
        })
    };
    let out = read(Box::new(child.stdout.take().expect("stdout")));
    let err = read(Box::new(child.stderr.take().expect("stderr")));
    let end = Instant::now() + RUN_LIMIT;
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code().unwrap_or(-1);
        }
        if Instant::now() > end {
            let _ = child.kill();
            let _ = child.wait();
            break -1;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (code, out.join().unwrap_or_default(), err.join().unwrap_or_default())
}

/// A second test server, with its host key in `dir`, where its
/// `sftp-server` runs: its port.
fn second_server(session: &Session, dir: &Path) -> u16 {
    std::fs::create_dir_all(dir).unwrap();
    let key = dir.join("host_key");
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(&key)
        .stdin(Stdio::null())
        .output()
        .expect("podssh keygen runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    session.runtime.block_on(ssh_harness::start(&key))
}

#[test]
fn copies_reach_a_node_and_its_route_through_the_stand_in_relay() {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let session = Session::start("node-copy");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let (rc, _, err) = ran(&session, &ca, &words(&["relay", "pair", "lab", "--relay-host", &relay]));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    // The node: the test's server as its TARGET, and a second server, whose
    // `sftp-server` runs in a directory of its own, as the route `other`.
    let second = session.home.join("second");
    let second_port = second_server(&session, &second);
    let target = format!("127.0.0.1:{}", session.port);
    let route = format!("other=127.0.0.1:{second_port}");
    let mut node = session.command(&words(&["node"]));
    node.env("SSL_CERT_FILE", &ca).args(PINS).args(["lab", target.as_str(), route.as_str()]);
    let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");
    let home = &session.home;
    let want = data(300_000);
    std::fs::write(home.join("here.bin"), &want).unwrap();
    let copy = |verb: &str, rest: &[&str]| {
        let mut args = words(&[verb]);
        if verb == "cp" {
            args.extend(words(&["--timeout", "120s"]));
        }
        args.extend(session.common());
        args.extend(words(rest));
        ran(&session, &ca, &args)
    };
    // cp up and down, to the node's TARGET.
    let (rc, _, err) = copy("cp", &["here.bin", "node://tester@lab:there.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("there.bin")).unwrap(), want, "the copy up");
    let (rc, _, err) = copy("cp", &["node://tester@lab:there.bin", "back.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("back.bin")).unwrap(), want, "the copy down");
    // scp up, and sftp's put and get in one batch.
    let (rc, _, err) = copy("scp", &["here.bin", "node://tester@lab:scp.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("scp.bin")).unwrap(), want, "scp up");
    std::fs::write(home.join("batch"), "put here.bin put.bin\nget put.bin got.bin\n").unwrap();
    let (rc, out, err) = copy("sftp", &["-b", "batch", "node://tester@lab"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.contains("sftp> put here.bin put.bin"), "{out}");
    assert_eq!(std::fs::read(home.join("put.bin")).unwrap(), want, "sftp's put");
    assert_eq!(std::fs::read(home.join("got.bin")).unwrap(), want, "sftp's get");
    // The route: the second server's directory, and not the first's.
    let (rc, _, err) = copy("cp", &["here.bin", "node://tester@lab/other:routed.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(second.join("routed.bin")).unwrap(), want, "the copy up through the route");
    assert!(!home.join("routed.bin").exists(), "the copy went to the node's TARGET, not its route");
    std::fs::write(home.join("batch"), "get routed.bin routed-back.bin\n").unwrap();
    let (rc, _, err) = copy("sftp", &["-b", "batch", "node://tester@lab/other"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("routed-back.bin")).unwrap(), want, "sftp's get through the route");
}
