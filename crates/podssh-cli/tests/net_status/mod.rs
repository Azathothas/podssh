//! `podssh ping NAME`, `podssh status --net` and doctor's section `net`
//! (T-435), a module of `tests/net.rs`, against three ends on the stand-in
//! relay: the owner's net names the node lab, the node gone, the member a and
//! a member relay hub. lab runs, in front of a listener that counts its
//! connections; gone has its pair and never runs, as a node that stopped.
//! `ping lab` gives each road with its time and the pair's road as the one
//! that answered first, and lab dials nothing at its TARGET for it; `ping
//! gone` is not reached (69). `status --net` then lists each member, with the
//! road that last reached lab and gone as missed; doctor, offline, says the
//! net held and asks no member relay. It says that it did not run when this
//! host has no Python or no openssl for the stand-in.

use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::throughput_harness::{lines_of, wait_for, Cell, Session};
use crate::{copy_of, key_hex, net, owner_key, ran};

/// The bound on each run here.
const LIMIT: Duration = Duration::from_secs(120);

/// An end's key in a private file of `dir`, from one byte.
fn key_file(dir: &Path, name: &str, seed: u8) -> String {
    let path = dir.join(name);
    let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    podssh_relay::cache::create_private(&path, format!("{hex}\n").as_bytes()).unwrap();
    path.display().to_string()
}

/// A TARGET on the loopback that takes each connection and counts it.
fn counting_target() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(conn);
        }
    });
    (port, count)
}

/// `cmd` run to its end within [`LIMIT`]: its code (-1 when it was stopped
/// at the limit), stdout and stderr, each read directly.
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
fn ping_names_each_road_and_status_lists_each_member_with_its_road() {
    let session = Session::start("net-status");
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
    let lab_key = key_file(&dir, "lab.key", 0x21);
    let (owner_doc, lab_doc, a_doc) = (dir.join("owner.doc"), dir.join("lab.doc"), dir.join("a.doc"));
    let (owner, _) = owner_key(&dir, "owner");
    let o = owner.display().to_string();
    let owner_says = |args: &[&str]| {
        let (rc, _, err) = net(&session.home, &owner_doc, args);
        assert_eq!(rc, 0, "{args:?}: {err}");
    };
    owner_says(&["net", "init", "home", "--owner-key", &o]);
    for (name, seed) in [("lab", 0x21), ("gone", 0x23), ("a", 0x31)] {
        owner_says(&["net", "add", name, &key_hex(seed), "--owner-key", &o]);
    }
    owner_says(&["net", "add", "hub", &key_hex(0x41), "--roles", "relay", "--owner-key", &o]);
    let given = copy_of(&owner_doc, &dir, "serial-5");
    for doc in [&lab_doc, &a_doc] {
        let (rc, _, err) = net(&session.home, doc, &["net", "take", &given]);
        assert_eq!(rc, 0, "{err}");
    }
    // The commands of the relay's ends: the pins after the verb.
    let end = |doc: &Path, args: &[String]| {
        let mut cmd = session.stand_in(&args[..1], &ca);
        cmd.args(&pins).args(&args[1..]).env("PODSSH_NET", doc);
        cmd
    };
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    for name in ["lab", "gone"] {
        let (rc, _, err) = ran(&mut end(&lab_doc, &words(&["relay", "pair", name, "--relay-host", &relay])));
        assert_eq!(rc, 0, "podssh relay pair {name}: {err}");
    }
    // lab runs in front of the counting TARGET; gone never runs.
    let (port, dialled) = counting_target();
    let target = format!("127.0.0.1:{port}");
    let node_args = words(&["node", "lab", &target, "--key", &lab_key]);
    let mut node = end(&lab_doc, &node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");
    // The node dials its TARGET once as it starts; the roads add none.
    let before = dialled.load(Ordering::SeqCst);
    let (rc, out, err) = bounded(&mut end(&a_doc, &words(&["ping", "lab"])));
    assert_eq!(rc, 0, "ping lab: {out}{err}");
    let first = out.lines().find(|l| l.starts_with("node://lab: the pair's road: answered in ")).unwrap_or_default();
    assert!(first.ends_with(" ms"), "the pair's road has its time: {out}");
    assert!(out.lines().last().unwrap_or_default().starts_with("node://lab: the pair's road answered first, in "));
    let (rc, out, err) = bounded(&mut end(&a_doc, &words(&["ping", "--json", "lab"])));
    assert_eq!(rc, 0, "ping --json lab: {out}{err}");
    let doc: Value = serde_json::from_str(out.trim()).expect("one JSON object");
    let pair = &doc["node"]["roads"][0];
    assert_eq!((&pair["road"], &pair["answered"]), (&json!("the pair's road"), &json!(true)), "{doc}");
    assert!(pair["ms"].as_f64().is_some_and(|ms| ms > 0.0), "the road's time was measured: {doc}");
    assert_eq!(doc["node"]["won"], "the pair's road", "{doc}");
    assert_eq!(doc["exit"], 0);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(dialled.load(Ordering::SeqCst), before, "a road's link opened a session at the TARGET");
    // A node that does not run is not reached, and each road says why.
    let (rc, out, err) = bounded(&mut end(&a_doc, &words(&["ping", "gone"])));
    assert_eq!(rc, 69, "ping gone: {out}{err}");
    assert!(out.contains("node://gone: the pair's road: failed after "), "{out}");
    assert_eq!(out.lines().last(), Some("node://gone: not reached: no road answered"), "{out}");
    // status --net: each member, and what the races from here last found.
    let (rc, out, err) = bounded(&mut end(&a_doc, &words(&["status", "--net"])));
    assert_eq!(rc, 0, "{err}");
    let line: Value = serde_json::from_str(out.trim()).expect("one line of JSON");
    let net = &line["net"];
    assert_eq!((&net["name"], &net["serial"], &net["count"]), (&json!("home"), &json!(5), &json!(4)), "{net}");
    let member = |name: &str| {
        let members = net["members"].as_array().unwrap_or_else(|| panic!("no members: {net}"));
        members.iter().find(|m| m["name"] == name).cloned().unwrap_or_else(|| panic!("no {name}: {net}"))
    };
    let lab = member("lab");
    assert_eq!((&lab["last"], &lab["reached"]["road"]), (&json!("reached"), &json!("the pair's road")), "{lab}");
    assert!(lab["reached"]["ms"].as_f64().is_some_and(|ms| ms > 0.0), "{lab}");
    let gone = member("gone");
    assert_eq!(gone["last"], "missed", "{gone}");
    assert!(gone["missed"]["why"].as_str().is_some_and(|why| why.starts_with("no road reached the node")), "{gone}");
    assert_eq!((&member("a")["last"], &member("hub")["roles"]), (&Value::Null, &json!(["relay"])), "{net}");
    let (_, plain, _) = bounded(&mut end(&a_doc, &words(&["status"])));
    let plain: Value = serde_json::from_str(plain.trim()).expect("one line of JSON");
    assert!(plain["net"]["members"].is_null() && plain["net"]["count"] == 4, "no members without --net: {plain}");
    // doctor, offline: the net held, and its member relay not asked.
    let (_, out, _) = bounded(end(&a_doc, &words(&["doctor"])).env("PODSSH_OFFLINE", "1"));
    let held = out.lines().find(|l| l.starts_with("  ok    net ")).unwrap_or_else(|| panic!("no line net: {out}"));
    assert!(held.contains("the net home, serial 5") && held.contains("4 members"), "{held}");
    let hub = out.lines().find(|l| l.contains("member relay hub")).unwrap_or_else(|| panic!("{out}"));
    assert!(hub.starts_with("  ????") && hub.contains("not asked: PODSSH_OFFLINE is set"), "{hub}");
}
