//! The net's policy (T-430) from end to end, a module of `tests/net.rs`.
//! With no connection: `podssh net policy set` signs a policy that `show`
//! gives back and `check` reads, refuses one with a fault and signs nothing,
//! and `clear` removes it. Three ends on the stand-in relay, a node with two
//! routes and two members: each reaches what a rule lets it; a route and a
//! target that no rule names are refused, with the policy's words at the
//! node, and nothing is dialled; a newer document that removes a rule is in
//! force at the next session.

use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::throughput_harness::{lines_of, wait_for, Cell, Session};
use crate::{copy_of, key_hex, net, owner_key, private, ran};

#[test]
fn the_policy_is_set_shown_checked_and_cleared_with_no_connection() {
    let home = private("net-policy");
    let doc = home.join("net.doc");
    let (owner, _) = owner_key(&home, "owner");
    let o = owner.display().to_string();
    let says = |args: &[&str]| net(&home, &doc, args);
    assert_eq!(says(&["net", "init", "home", "--owner-key", &o]).0, 0);
    let members = [("lab", 0x21, "node"), ("gw", 0x22, "node,exit"), ("laptop", 0x31, "node"), ("phone", 0x41, "node")];
    for (name, seed, roles) in members {
        let (rc, _, err) = says(&["net", "add", name, &key_hex(seed), "--roles", roles, "--owner-key", &o]);
        assert_eq!(rc, 0, "{err}");
    }
    // No policy: each member reaches each, as Tailscale's default policy.
    let (rc, out, err) = says(&["net", "policy", "check", "phone", "lab/db"]);
    assert!(rc == 0 && out.starts_with("allowed\t") && out.contains("has no policy"), "{rc} {out} {err}");
    let (rc, out, err) = says(&["net", "policy", "show"]);
    assert!(rc == 0 && out.is_empty() && err.contains("has no policy"), "{err}");
    // laptop reaches lab whole, gw's exit and a range; phone, by its tag,
    // lab's web alone.
    let file = home.join("policy.json");
    let f = file.display().to_string();
    let policy = r#"{"tags": {"dev": ["phone"]}, "rules": [
        {"from": ["laptop"], "to": ["lab", "exit:gw", "10.1.0.0/16"], "note": "the owner's laptop"},
        {"from": ["tag:dev"], "to": ["lab/web"]}
    ]}"#;
    std::fs::write(&file, policy).unwrap();
    let (rc, _, err) = says(&["net", "policy", "set", &f, "--owner-key", &o]);
    assert!(rc == 0 && err.contains("set the policy: 2 rules, 1 tags") && err.contains("serial 6"), "{err}");
    let phone = key_hex(0x41);
    for (from, to, code, words) in [
        ("laptop", "lab", 0, "rule 1 of the net home's policy (serial 6): from laptop to lab"),
        ("laptop", "lab/db", 0, "(the owner's laptop)"),
        ("laptop", "exit:gw", 0, "rule 1 "),
        ("laptop", "10.1.2.3", 0, "rule 1 "),
        ("laptop", "10.2.0.1", 77, "lets laptop reach 10.2.0.1"),
        ("laptop", "exit:lab", 77, "lets laptop reach exit:lab"),
        ("phone", "lab/web", 0, "rule 2 "),
        (phone.as_str(), "lab/web", 0, "rule 2 "),
        ("phone", "lab/db", 77, "no rule of the net home's policy (serial 6) lets phone reach lab/db"),
        ("phone", "lab", 77, "lets phone reach lab"),
        ("lab", "laptop", 77, "lets lab reach laptop"),
    ] {
        let (rc, out, err) = says(&["net", "policy", "check", from, to]);
        let verdict = if code == 0 { "allowed\t" } else { "refused\t" };
        assert!(rc == code && out.starts_with(verdict) && out.contains(words), "{from} {to}: {rc} {out} {err}");
    }
    // show gives the policy back as a file that set takes; the document
    // requires it, so that a podssh of before refuses it whole.
    let (rc, out, _) = says(&["net", "policy", "show"]);
    let shown: serde_json::Value = serde_json::from_str(&out).expect("show gives JSON");
    assert!(rc == 0 && shown["rules"][1]["to"][0] == "lab/web" && shown["tags"]["dev"][0] == "phone", "{out}");
    let (_, bytes, _) = says(&["net", "show"]);
    assert!(bytes.contains("\"requires\":[\"policy\"]"), "{bytes}");
    // A policy with a fault is refused, with its reason, and signs nothing.
    for (text, why) in [
        (r#"{"rules": [{"from": ["tag:ops"], "to": ["lab"]}]}"#, "the tag ops is not in the policy's \"tags\""),
        (r#"{"rules": [{"from": ["laptop"], "to": ["lab"], "ports": [22]}]}"#, "the field \"ports\" is not one"),
        (r#"{"rules": [{"from": ["laptop"], "to": ["10.0.0.0/33"]}]}"#, "is not what a rule reaches"),
        (r#"{"rules": [], "deny": []}"#, "\"deny\" is not one that podssh reads"),
        (r#"{"tags": {}}"#, "has no \"rules\""),
        ("not json", "is not JSON"),
    ] {
        std::fs::write(&file, text).unwrap();
        let (rc, _, err) = says(&["net", "policy", "set", &f, "--owner-key", &o]);
        assert!(rc == 65 && err.contains(why), "{text}: {rc} {err}");
    }
    let gone = home.join("gone.json").display().to_string();
    assert_eq!(says(&["net", "policy", "set", &gone, "--owner-key", &o]).0, 66);
    let (_, _, err) = says(&["net", "ls"]);
    assert!(err.contains("serial 6"), "a policy refused signed nothing: {err}");
    // The command line, checked before anything is read.
    let (o, phone) = (o.as_str(), phone.as_str());
    for (args, why) in [
        (vec!["net", "policy"], "podssh net policy: check FROM TO, show, set FILE or clear"),
        (vec!["net", "policy", "allow"], "check FROM TO, show, set FILE or clear"),
        (vec!["net", "policy", "check", "laptop"], "podssh net policy check FROM TO: 2 words given"),
        (vec!["net", "policy", "check", "laptop", "lab", "--owner-key", o], "--owner-key is for podssh net init"),
        (vec!["net", "policy", "check", "nobody", "lab"], "has no member of that name or key"),
        (vec!["net", "policy", "check", phone, "nobody"], "has no member nobody"),
        (vec!["net", "policy", "check", "laptop", "lab/-x"], "is not a route"),
    ] {
        let (rc, _, err) = says(&args);
        assert!(rc == 64 && err.contains(why), "{args:?}: {rc} {err}");
    }
    // clear: each member reaches each again, and the document requires no
    // policy.
    let (rc, _, err) = says(&["net", "policy", "clear", "--owner-key", o]);
    assert!(rc == 0 && err.contains("cleared the policy") && err.contains("serial 7"), "{err}");
    let (_, bytes, _) = says(&["net", "show"]);
    assert!(!bytes.contains("\"policy\""), "{bytes}");
    let (rc, out, _) = says(&["net", "policy", "check", "phone", "lab/db"]);
    assert!(rc == 0 && out.contains("has no policy"), "{out}");
    let (rc, _, err) = says(&["net", "policy", "clear", "--owner-key", o]);
    assert!(rc == 64 && err.contains("has no policy to clear"), "{err}");
}

/// A TCP service that writes `word` to each connection, and counts them.
fn service(word: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(word.as_bytes());
        }
    });
    (port, count)
}

/// Whether the node's channel refused a run: no byte, and its words.
fn refusal(rc: i32, out: &str, err: &str) -> bool {
    rc != 0 && out.is_empty() && err.contains("refused this client's key")
}

/// An end's key in a private file of `dir`, from one byte.
fn key_file(dir: &Path, name: &str, seed: u8) -> String {
    let path = dir.join(name);
    let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    podssh_relay::cache::create_private(&path, format!("{hex}\n").as_bytes()).unwrap();
    path.display().to_string()
}

#[test]
fn a_member_reaches_only_what_the_policy_lets_it() {
    let session = Session::start("net-policy-ends");
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
    let (node_key, a_key, b_key) =
        (key_file(&dir, "node.key", 0x21), key_file(&dir, "a.key", 0x31), key_file(&dir, "b.key", 0x41));
    let (owner_doc, node_doc, a_doc, b_doc) =
        (dir.join("owner.doc"), dir.join("node.doc"), dir.join("a.doc"), dir.join("b.doc"));
    let (owner, _) = owner_key(&dir, "owner");
    let o = owner.display().to_string();
    let owner_says = |args: &[&str]| {
        let (rc, _, err) = net(&session.home, &owner_doc, args);
        assert_eq!(rc, 0, "{args:?}: {err}");
    };
    owner_says(&["net", "init", "home", "--owner-key", &o]);
    for (name, seed) in [("lab", 0x21), ("a", 0x31), ("b", 0x41)] {
        owner_says(&["net", "add", name, &key_hex(seed), "--owner-key", &o]);
    }
    // a reaches lab whole; b, by the tag dev, lab's web alone.
    let policy = dir.join("policy.json");
    let p = policy.display().to_string();
    let write_policy = |with_b: bool| {
        let b = if with_b { r#", {"from": ["tag:dev"], "to": ["lab/web"]}"# } else { "" };
        let text = format!(r#"{{"tags": {{"dev": ["b"]}}, "rules": [{{"from": ["a"], "to": ["lab"]}}{b}]}}"#);
        std::fs::write(&policy, text).unwrap();
    };
    write_policy(true);
    owner_says(&["net", "policy", "set", &p, "--owner-key", &o]);
    let given = copy_of(&owner_doc, &dir, "serial-5");
    for doc in [&node_doc, &a_doc, &b_doc] {
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
    let (rc, _, err) = ran(&mut end(&node_doc, &words(&["relay", "pair", "lab", "--relay-host", &relay])));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    // The node: the tests' SSH server with no route, and two routes; no
    // --allow, so the net and its policy are its door.
    let ((web, _), (db, db_seen)) = (service("web\n"), service("db\n"));
    let (target, web, db) =
        (format!("127.0.0.1:{}", session.port), format!("web=127.0.0.1:{web}"), format!("db=127.0.0.1:{db}"));
    let node_args = words(&["node", "lab", &target, &web, &db, "--key", &node_key]);
    let mut node = end(&node_doc, &node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let member = wait_for(&lines, "a member of the net home as lab").expect("the node says its net");
    assert!(member.contains("serial 5") && member.contains("as the 2 rules of its policy let"), "{member}");
    wait_for(&lines, "online").expect("the node is online");
    let said = || lines.try_iter().collect::<Vec<_>>().join("\n");
    let ssh = |doc: &Path, key: &str| {
        let mut args = vec!["ssh".to_string()];
        args.extend(session.common());
        args.extend(words(&["--client-key", key, "tester@lab", "greet"]));
        ran(&mut end(doc, &args))
    };
    let operator = |doc: &Path, key: &str, name: &str| {
        let args = words(&["operator", name, "--client-key", key]);
        ran(&mut end(doc, &args))
    };
    // a: lab whole, its target with no route and each route.
    let (rc, out, err) = ssh(&a_doc, &a_key);
    assert_eq!((rc, out.as_str()), (0, crate::ssh_harness::GREETING), "{err}\nthe node:\n{}", said());
    let (rc, out, err) = operator(&a_doc, &a_key, "lab/db");
    assert_eq!((rc, out.as_str()), (0, "db\n"), "{err}\nthe node:\n{}", said());
    // b: lab's web alone. Its target with no route, then its db, are refused
    // with the policy's words at the node, and the db is never dialled.
    let (rc, out, err) = operator(&b_doc, &b_key, "lab/web");
    assert_eq!((rc, out.as_str()), (0, "web\n"), "{err}\nthe node:\n{}", said());
    let (rc, out, err) = ssh(&b_doc, &b_key);
    assert!(refusal(rc, &out, &err), "a target that no rule names was reached: {rc} {out} {err}");
    let refused = wait_for(&lines, "refused the operator key").expect("the node names the refusal");
    assert!(refused.ends_with("no rule of the net home's policy (serial 5) lets b reach lab"), "{refused}");
    let dials = db_seen.load(Ordering::SeqCst);
    let (rc, out, err) = operator(&b_doc, &b_key, "lab/db");
    assert!(refusal(rc, &out, &err), "a route that no rule names was reached: {rc} {out} {err}");
    let refused = wait_for(&lines, "lets b reach lab/db").expect("the node names the refusal");
    assert!(refused.contains("refused the operator key"), "{refused}");
    assert_eq!(db_seen.load(Ordering::SeqCst), dials, "a route that the policy refused was dialled");
    // The owner removes b's rule; the node takes the new document, and b's
    // web is refused at its next session, while a's rule stays.
    write_policy(false);
    owner_says(&["net", "policy", "set", &p, "--owner-key", &o]);
    let newer = copy_of(&owner_doc, &dir, "serial-6");
    assert_eq!(net(&session.home, &node_doc, &["net", "take", &newer]).0, 0);
    let (rc, out, err) = operator(&b_doc, &b_key, "lab/web");
    assert!(refusal(rc, &out, &err), "a rule removed still held: {rc} {out} {err}");
    let refused = wait_for(&lines, "lets b reach lab/web").expect("the node names the refusal");
    assert!(refused.contains("(serial 6)"), "{refused}");
    let (rc, out, err) = operator(&a_doc, &a_key, "lab/web");
    assert_eq!((rc, out.as_str()), (0, "web\n"), "{err}\nthe node:\n{}", said());
}
