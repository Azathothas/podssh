//! The copies reach a member of the net by its name alone (T-453), a module
//! of `tests/net.rs`: `podssh cp`, `scp` and `sftp` read `NAME:PATH` and
//! `NAME` as `podssh ssh NAME` reads its destination, the net first, and
//! reach the member's node through the stand-in relay; `podssh mv` takes the
//! member by its name and as `node://NAME` for one server, which renames
//! within itself, and refuses one file named both ways. It says that it did
//! not run when this host has no Python, no openssl or no `sftp-server`.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::throughput_harness::{lines_of, wait_for, Cell, Session};
use crate::{copy_of, key_hex, net, owner_key, ran};

/// The bound on each run of a copy.
const LIMIT: Duration = Duration::from_secs(180);

fn data(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect()
}

/// An end's key in a private file of `dir`, from one byte.
fn key_file(dir: &Path, name: &str, seed: u8) -> String {
    let path = dir.join(name);
    let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    podssh_relay::cache::create_private(&path, format!("{hex}\n").as_bytes()).unwrap();
    path.display().to_string()
}

/// `cmd` run to its end within [`LIMIT`]: its code (-1 when it was stopped
/// at the limit), stdout and stderr.
fn bounded(cmd: &mut Command) -> (i32, String, String) {
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
    let end = Instant::now() + LIMIT;
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

#[test]
fn copies_reach_a_member_by_its_name_alone() {
    if crate::ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let session = Session::start("net-copy");
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
    let dir = session.home.join("private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let (node_key, a_key) = (key_file(&dir, "node.key", 0x21), key_file(&dir, "a.key", 0x31));
    let (owner_doc, node_doc, a_doc) = (dir.join("owner.doc"), dir.join("node.doc"), dir.join("a.doc"));
    let (owner, _) = owner_key(&dir, "owner");
    let o = owner.display().to_string();
    let owner_says = |args: &[&str]| {
        let (rc, _, err) = net(&session.home, &owner_doc, args);
        assert_eq!(rc, 0, "{args:?}: {err}");
    };
    owner_says(&["net", "init", "home", "--owner-key", &o]);
    for (name, seed) in [("lab", 0x21), ("a", 0x31)] {
        owner_says(&["net", "add", name, &key_hex(seed), "--owner-key", &o]);
    }
    let given = copy_of(&owner_doc, &dir, "serial-3");
    for doc in [&node_doc, &a_doc] {
        let (rc, _, err) = net(&session.home, doc, &["net", "take", &given]);
        assert_eq!(rc, 0, "{err}");
    }
    // The commands of the relay's ends, in the session's home: the pins
    // after the verb, and the end's net.
    let end = |doc: &Path, args: &[String]| {
        let mut cmd = session.stand_in(&args[..1], &ca);
        cmd.args(&pins).args(&args[1..]).env("PODSSH_NET", doc).current_dir(&session.home);
        cmd
    };
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let (rc, _, err) = ran(&mut end(&node_doc, &words(&["relay", "pair", "lab", "--relay-host", &relay])));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    // The node: the test's server, whose `sftp-server` runs in the home;
    // no --allow, so the net is its door.
    let target = format!("127.0.0.1:{}", session.port);
    let node_args = words(&["node", "lab", &target, "--key", &node_key]);
    let mut node = end(&node_doc, &node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");
    let home = &session.home;
    let want = data(200_000);
    std::fs::write(home.join("here.bin"), &want).unwrap();
    // Each copy as the member a, by the member's name alone. The relay host
    // is the stand-in's, so that a name read as a host stays on the loopback.
    let copy = |verb: &str, rest: &[&str]| {
        let mut args = words(&[verb]);
        if verb == "cp" || verb == "mv" {
            args.extend(words(&["--timeout", "120s"]));
        }
        args.extend(session.common());
        args.extend(words(&["--client-key", &a_key, "--relay-host", &relay]));
        args.extend(words(rest));
        bounded(&mut end(&a_doc, &args))
    };
    let (rc, _, err) = copy("cp", &["here.bin", "tester@lab:there.bin"]);
    assert_eq!(rc, 0, "the copy up by the member's name alone: {err}");
    assert_eq!(std::fs::read(home.join("there.bin")).unwrap(), want, "the copy up");
    let (rc, _, err) = copy("cp", &["tester@lab:there.bin", "back.bin"]);
    assert_eq!(rc, 0, "the copy down by the member's name alone: {err}");
    assert_eq!(std::fs::read(home.join("back.bin")).unwrap(), want, "the copy down");
    let (rc, _, err) = copy("scp", &["here.bin", "tester@lab:scp.bin"]);
    assert_eq!(rc, 0, "scp by the member's name alone: {err}");
    assert_eq!(std::fs::read(home.join("scp.bin")).unwrap(), want, "scp up");
    std::fs::write(home.join("batch"), "put here.bin put.bin\nget put.bin got.bin\n").unwrap();
    let (rc, out, err) = copy("sftp", &["-b", "batch", "tester@lab"]);
    assert_eq!(rc, 0, "sftp by the member's name alone: {err}");
    assert!(out.contains("sftp> put here.bin put.bin"), "{out}");
    assert_eq!(std::fs::read(home.join("put.bin")).unwrap(), want, "sftp's put");
    assert_eq!(std::fs::read(home.join("got.bin")).unwrap(), want, "sftp's get");
    // One node, named both ways: mv is the server's rename, said as no move
    // between hosts, and one file named both ways is refused before
    // anything connects.
    let (rc, _, err) = copy("mv", &["tester@lab:scp.bin", "node://tester@lab:moved.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!err.contains("on different hosts"), "the member and node://lab were two hosts: {err}");
    assert_eq!(std::fs::read(home.join("moved.bin")).unwrap(), want, "the rename");
    assert!(!home.join("scp.bin").exists(), "the source of the rename stayed");
    let (rc, _, err) = copy("mv", &["tester@lab:moved.bin", "node://tester@lab:moved.bin"]);
    assert!(rc == 64 && err.contains("name one file"), "one file named both ways: {rc} {err}");
    assert!(home.join("moved.bin").exists(), "a move onto itself removed its file");
}
