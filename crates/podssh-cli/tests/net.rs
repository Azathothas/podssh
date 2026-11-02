//! `podssh net` (T-429) from end to end. A document that `podssh net` signs
//! verifies with OpenSSH's `ssh-keygen -Y verify`, and one that `ssh-keygen
//! -Y sign` signs is taken, as signed in a run here and as captured in
//! `src/net/testdata/`; an older serial, another key's signature, another
//! owner and an expired document are refused. Three ends on the stand-in
//! relay: two members reach a node by its name alone; the owner removes
//! one, a member brings the new document to the node in the end-to-end
//! channel, and the removed member is refused at its next session. A check
//! that needs ssh-keygen, or Python and openssl for the stand-in, says that
//! it did not run when this host has none.

mod ssh_harness;
mod throughput_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use podssh_relay::identity::Identity;
use throughput_harness::{command_in, lines_of, scratch, wait_for, Cell, Session};

/// What a run gave: its exit code, stdout and stderr.
fn ran(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// `podssh ARGS` with HOME under `home` and the net's document in `net`.
fn net(home: &Path, doc: &Path, args: &[&str]) -> (i32, String, String) {
    let words: Vec<String> = args.iter().map(|w| w.to_string()).collect();
    let mut cmd = command_in(home, &words);
    ran(cmd.env("PODSSH_NET", doc))
}

/// A private directory of the test, as the files of keys and nets need;
/// its scratch directory goes when the test ends, pass or fail, as the gate
/// fails on a test that leaves one in the temporary directory.
struct Private {
    dir: PathBuf,
    root: PathBuf,
}

impl std::ops::Deref for Private {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.dir
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn private(tag: &str) -> Private {
    let root = scratch(tag);
    let dir = root.join("private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    Private { dir, root }
}

/// An owner's key, made by podssh keygen: its file, and its public line.
fn owner_key(home: &Path, name: &str) -> (PathBuf, String) {
    let path = home.join(name);
    let words = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f"].iter().map(|w| w.to_string());
    let words: Vec<String> = words.chain([path.display().to_string()]).collect();
    let (rc, _, err) = ran(&mut command_in(home, &words));
    assert_eq!(rc, 0, "podssh keygen: {err}");
    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    (path, public.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
}

/// An Ed25519 key of an end, from one byte: its hex, as `net add` takes it.
fn key_hex(seed: u8) -> String {
    Identity::from_seed(&[seed; 32]).public().hex()
}

/// `ssh-keygen ARGS`, its stdin from `stdin`: `None` when this host has none.
fn ssh_keygen(args: &[&str], stdin: Option<&Path>) -> Option<(i32, String)> {
    let mut cmd = Command::new("ssh-keygen");
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(match stdin {
        Some(path) => Stdio::from(std::fs::File::open(path).unwrap()),
        None => Stdio::null(),
    });
    let out = cmd.output().ok()?;
    // Both streams: OpenSSH 9.6 says its verdict of -Y verify on stdout.
    let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Some((out.status.code().unwrap_or(-1), said))
}

/// The captured vectors of `src/net/testdata`.
fn testdata(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/net/testdata").join(name)
}

#[test]
fn a_document_that_podssh_signs_verifies_with_ssh_keygen() {
    let home = private("net-sign");
    let doc = home.join("home.doc");
    let (owner, public) = owner_key(&home, "owner");
    let owner_arg = owner.display().to_string();
    let (rc, _, err) = net(&home, &doc, &["net", "init", "home", "--owner-key", &owner_arg]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("the net home, serial 1"), "{err}");
    let (rc, _, err) = net(&home, &doc, &["net", "add", "lab", &key_hex(0x21), "--owner-key", &owner_arg]);
    assert_eq!(rc, 0, "{err}");
    // A change needs no --owner-key when ~/.ssh holds the owner's key.
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::copy(&owner, ssh.join("id_ed25519")).unwrap();
    std::fs::copy(owner.with_extension("pub"), ssh.join("id_ed25519.pub")).unwrap();
    let (rc, _, err) = net(&home, &doc, &["net", "add", "laptop", &key_hex(0x22), "--roles", "node,exit"]);
    assert_eq!(rc, 0, "{err}");
    let (rc, out, err) = net(&home, &doc, &["net", "ls"]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("serial 3") && err.contains("2 members"), "{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.len() == 2 && lines[0].starts_with("lab\tnode\tSHA256:"), "{out}");
    assert!(lines[1].starts_with("laptop\tnode,exit\t"), "{out}");
    let (rc, bytes, _) = net(&home, &doc, &["net", "show"]);
    assert_eq!(rc, 0);
    let (rc, signature, _) = net(&home, &doc, &["net", "show", "--signature"]);
    assert_eq!(rc, 0);
    assert!(signature.starts_with("-----BEGIN SSH SIGNATURE-----\n"), "{signature}");
    let (plain, sig, allowed) = (home.join("doc.json"), home.join("doc.json.sig"), home.join("allowed"));
    std::fs::write(&plain, &bytes).unwrap();
    std::fs::write(&sig, &signature).unwrap();
    std::fs::write(&allowed, format!("owner {public}\n")).unwrap();
    let verify = |file: &Path| {
        let (a, s) = (allowed.display().to_string(), sig.display().to_string());
        ssh_keygen(&["-Y", "verify", "-f", &a, "-I", "owner", "-n", "podssh-net", "-s", &s], Some(file))
    };
    let Some((rc, said)) = verify(&plain) else {
        eprintln!("did not run: this host has no ssh-keygen");
        return;
    };
    assert_eq!(rc, 0, "ssh-keygen -Y verify: {said}");
    assert!(said.contains("Good \"podssh-net\" signature for owner"), "{said}");
    // The control: a changed byte fails OpenSSH's check too.
    let changed = home.join("changed.json");
    std::fs::write(&changed, bytes.replacen("\"serial\":3", "\"serial\":9", 1)).unwrap();
    assert_ne!(verify(&changed).unwrap().0, 0, "a changed document verified");
}

#[test]
fn a_document_that_ssh_keygen_signs_is_taken() {
    let home = private("net-take-openssh");
    // Captured: OpenSSH_9.6p1's signature of a document written by hand.
    let dir = home.join("given");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(testdata("net.json"), dir.join("net.json")).unwrap();
    std::fs::copy(testdata("net.json.sig"), dir.join("net.json.sig")).unwrap();
    let doc = home.join("held.doc");
    let given = dir.join("net.json").display().to_string();
    let (rc, _, err) = net(&home, &doc, &["net", "take", &given]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("took the net home, serial 3"), "{err}");
    let (rc, out, _) = net(&home, &doc, &["net", "ls"]);
    assert!(rc == 0 && out.starts_with("lab\tnode\t") && out.contains("\nlaptop\tnode,exit\t"), "{out}");
    let (rc, _, err) = net(&home, &doc, &["net", "take", &given]);
    assert!(rc == 0 && err.contains("already"), "{err}");
    // Signed here and now by ssh-keygen, with podssh keygen's key.
    let (owner, public) = owner_key(&home, "owner");
    let fresh = home.join("fresh.json");
    let text = format!(
        "{{\"podssh-net\":1,\"name\":\"lab-net\",\"serial\":1,\"issued\":1793577600,\"expires\":4102444800,\
         \"owner\":\"{public}\",\"members\":[{{\"name\":\"lab\",\"key\":\"{}\",\"roles\":[\"node\"]}}]}}\n",
        key_hex(0x21)
    );
    std::fs::write(&fresh, text).unwrap();
    let (o, f) = (owner.display().to_string(), fresh.display().to_string());
    let Some((rc, said)) = ssh_keygen(&["-q", "-Y", "sign", "-f", &o, "-n", "podssh-net", &f], None) else {
        eprintln!("did not run: this host has no ssh-keygen");
        return;
    };
    assert_eq!(rc, 0, "ssh-keygen -Y sign: {said}");
    let other = home.join("other.doc");
    let (rc, _, err) = net(&home, &other, &["net", "take", &f, "--owner", &public]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("took the net lab-net, serial 1"), "{err}");
}

/// `dir/name`, the signed document of `doc` as it is now.
fn copy_of(doc: &Path, dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    std::fs::copy(doc, &path).unwrap();
    path.display().to_string()
}

#[test]
fn an_older_serial_another_owner_another_key_and_an_end_are_refused() {
    let home = private("net-rules");
    let (owner, _) = owner_key(&home, "owner");
    let (second, second_public) = owner_key(&home, "second");
    let (o, doc) = (owner.display().to_string(), home.join("owner.doc"));
    assert_eq!(net(&home, &doc, &["net", "init", "home", "--owner-key", &o]).0, 0);
    let first = copy_of(&doc, &home, "serial-1");
    assert_eq!(net(&home, &doc, &["net", "add", "lab", &key_hex(0x21), "--owner-key", &o]).0, 0);
    let older = copy_of(&doc, &home, "serial-2");
    assert_eq!(net(&home, &doc, &["net", "add", "a", &key_hex(0x31), "--owner-key", &o]).0, 0);
    let newest = copy_of(&doc, &home, "serial-3");
    let end = home.join("end.doc");
    assert_eq!(net(&home, &end, &["net", "take", &newest]).0, 0);
    let (rc, _, err) = net(&home, &end, &["net", "take", &older]);
    assert_eq!(rc, 65, "an older serial was taken: {err}");
    assert!(err.contains("its serial 2 is not higher than 3"), "{err}");
    let (rc, _, err) = net(&home, &end, &["net", "ls"]);
    assert!(rc == 0 && err.contains("serial 3"), "the newer document stays: {err}");
    // Another owner's net, even of the same name, is never taken.
    let (s, theirs) = (second.display().to_string(), home.join("second.doc"));
    assert_eq!(net(&home, &theirs, &["net", "init", "home", "--owner-key", &s]).0, 0);
    let foreign = copy_of(&theirs, &home, "foreign");
    let (rc, _, err) = net(&home, &end, &["net", "take", &foreign]);
    assert!(rc == 65 && err.contains("not of the owner of the net held here"), "{err}");
    // A first document of an owner that --owner does not name.
    let fresh = home.join("fresh.doc");
    let (rc, _, err) = net(&home, &fresh, &["net", "take", &first, "--owner", &second_public]);
    assert!(rc == 65 && err.contains("and --owner names"), "{err}");
    // Another key's signature, another namespace, and an end gone by: the
    // captured signatures of OpenSSH.
    let given = home.join("given");
    std::fs::create_dir_all(&given).unwrap();
    for (sig, says) in [("by-other.sig", "not by its owner"), ("wrong-namespace.sig", "namespace")] {
        std::fs::copy(testdata("net.json"), given.join("net.json")).unwrap();
        std::fs::copy(testdata(sig), given.join("net.json.sig")).unwrap();
        let (rc, _, err) = net(&home, &fresh, &["net", "take", &given.join("net.json").display().to_string()]);
        assert!(rc == 65 && err.contains(says), "{sig}: {err}");
    }
    std::fs::copy(testdata("expired.json"), given.join("expired.json")).unwrap();
    std::fs::copy(testdata("expired.json.sig"), given.join("expired.json.sig")).unwrap();
    let (rc, _, err) = net(&home, &fresh, &["net", "take", &given.join("expired.json").display().to_string()]);
    assert!(rc == 65 && err.contains("it ended at 2023-11-15T22:13:20Z"), "{err}");
    let (rc, _, err) = net(&home, &fresh, &["net", "ls"]);
    assert!(rc == 78 && err.contains("holds no net"), "nothing refused was kept: {err}");
}

#[test]
fn a_command_of_the_net_that_cannot_be_done_says_why() {
    let home = private("net-refusals");
    let doc = home.join("net.doc");
    let (owner, _) = owner_key(&home, "owner");
    let (o, k) = (owner.display().to_string(), key_hex(1));
    let (o, k) = (o.as_str(), k.as_str());
    for (args, code, says) in [
        (vec!["net"], 64, "missing SUBCOMMAND"),
        (vec!["net", "list"], 64, "not a subcommand"),
        (vec!["net", "ls", "--roles", "node"], 64, "--roles is for podssh net add"),
        (vec!["net", "add", "lab"], 64, "podssh net add NAME KEY"),
        (vec!["net", "ls"], 78, "holds no net"),
        (vec!["net", "add", "lab", k], 78, "holds no net"),
        (vec!["net", "init", "home.example", "--owner-key", o], 64, "is not a name"),
    ] {
        let (rc, out, err) = net(&home, &doc, &args);
        assert!(rc == code && err.contains(says) && out.is_empty(), "{args:?}: {rc} {err}");
    }
    assert_eq!(net(&home, &doc, &["net", "init", "home", "--owner-key", o]).0, 0);
    for (args, code, says) in [
        (vec!["net", "init", "again", "--owner-key", o], 78, "holds the net home already"),
        (vec!["net", "add", "lab", "nope", "--owner-key", o], 64, "is not a key"),
        (vec!["net", "add", "lab", k, "--roles", "funnel", "--owner-key", o], 64, "not a role"),
        (vec!["net", "rm", "nobody", "--owner-key", o], 64, "has no member nobody"),
        (vec!["net", "renew", "--days", "0", "--owner-key", o], 64, "--days 0"),
    ] {
        let (rc, _, err) = net(&home, &doc, &args);
        assert!(rc == code && err.contains(says), "{args:?}: {rc} {err}");
    }
    let (rc, _, err) = net(&home, &doc, &["net", "renew", "--owner-key", o]);
    assert!(rc == 0 && err.contains("serial 2"), "{err}");
    for (value, says) in [("no", "the net is off"), ("relative/net.doc", "the absolute path")] {
        let words = ["net", "ls"].map(String::from);
        let (rc, _, err) = ran(command_in(&home, &words).env("PODSSH_NET", value));
        assert!(rc == 78 && err.contains(says), "{value}: {err}");
    }
}

#[test]
fn members_reach_a_node_by_name_and_a_removed_member_is_refused() {
    let session = Session::start("net-ends");
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
    // Each end's key in a file of its own, and each end's net.
    let key_file = |name: &str, seed: u8| {
        let path = dir.join(name);
        let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
        podssh_relay::cache::create_private(&path, format!("{hex}\n").as_bytes()).unwrap();
        path.display().to_string()
    };
    let (node_key, a_key, b_key) = (key_file("node.key", 0x21), key_file("a.key", 0x31), key_file("b.key", 0x41));
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
    let given = copy_of(&owner_doc, &dir, "serial-4");
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
    // The node has no --allow: the net is its door.
    let target = format!("127.0.0.1:{}", session.port);
    let node_args = words(&["node", "lab", &target, "--key", &node_key]);
    let mut node = end(&node_doc, &node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let member = wait_for(&lines, "a member of the net home as lab").expect("the node says its net");
    assert!(member.contains("serial 4") && member.contains("its 2 other members"), "{member}");
    wait_for(&lines, "online").expect("the node is online");
    // A member reaches the node by its name alone.
    let ssh = |doc: &Path, key: &str| {
        let mut args = vec!["ssh".to_string()];
        args.extend(session.common());
        args.extend(words(&["--client-key", key, "tester@lab", "greet"]));
        ran(&mut end(doc, &args))
    };
    let said = || lines.try_iter().collect::<Vec<_>>().join("\n");
    for (doc, key) in [(&a_doc, &a_key), (&b_doc, &b_key)] {
        let (rc, out, err) = ssh(doc, key);
        assert_eq!((rc, out.as_str()), (0, ssh_harness::GREETING), "{err}\nthe node:\n{}", said());
    }
    // The owner removes b; a takes the new document, and gives it to the
    // node in the channel of its next session.
    owner_says(&["net", "rm", "b", "--owner-key", &o]);
    let newer = copy_of(&owner_doc, &dir, "serial-5");
    assert_eq!(net(&session.home, &a_doc, &["net", "take", &newer]).0, 0);
    let (rc, out, err) = ssh(&a_doc, &a_key);
    assert_eq!((rc, out.as_str()), (0, ssh_harness::GREETING), "{err}\nthe node:\n{}", said());
    let (rc, _, err) = net(&session.home, &node_doc, &["net", "ls"]);
    assert!(rc == 0 && err.contains("serial 5"), "the node took a's document: {err}\nthe node:\n{}", said());
    let (rc, out, err) = ssh(&b_doc, &b_key);
    assert!(rc != 0 && out.is_empty() && err.contains("refused this client's key"), "{rc} {err}");
    let refused = wait_for(&lines, "refused the operator key").expect("the node names the refusal");
    assert!(refused.contains("not a member of the net home (serial 5)"), "{refused}");
    // A refused end gets no document: b still holds serial 4.
    let (_, _, err) = net(&session.home, &b_doc, &["net", "ls"]);
    assert!(err.contains("serial 4"), "{err}");
}
