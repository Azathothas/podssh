//! The DERP road's node with no `--allow`, whose key is a member of the net
//! (T-452), a module of `tests/derp_road.rs`. The net's members are its
//! door: a member reaches it by its name alone, through the DERP ticket that
//! the owner wrote into the net, and a key that the net does not name is
//! refused at the node. A node of no net and no `--allow` is refused before
//! its key is made, as before; a member with no pair serves the road unasked.

use std::path::{Path, PathBuf};

use podssh_relay::identity::file::{self, Place};
use podssh_relay::identity::Identity;
use podssh_relay::session::OsEntropy;

use crate::ssh_harness::GREETING;
use crate::{command, run, ticket_in, wait_for, Lab};

/// The byte of the node's key, so that the owner can name it first.
const NODE_SEED: u8 = 0x21;

/// `podssh ARGS` in `home` with the net's document `doc`.
fn net(home: &Path, doc: &Path, args: &[&str]) -> (i32, String, String) {
    run(command(home, args).env("PODSSH_NET", doc))
}

/// A private key file at `path`, from one byte.
fn key_file(path: &Path, seed: u8) {
    let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    podssh_relay::cache::create_private(path, format!("{hex}\n").as_bytes()).unwrap();
}

/// The hex of the key in the file `path`, made when missing.
fn key_hex(path: &str) -> String {
    file::load(&Place::File(PathBuf::from(path)), &mut OsEntropy).expect("the key").identity.public().hex()
}

/// The node's key, as `net add` takes it.
fn node_hex() -> String {
    Identity::from_seed(&[NODE_SEED; 32]).public().hex()
}

/// The owner of the net: its key, made by podssh keygen, and its document,
/// in a private directory of the test.
struct Owner {
    key: String,
    doc: PathBuf,
    dir: PathBuf,
}

impl Owner {
    fn new(dir: &Path) -> Owner {
        podssh_relay::cache::private_dir(dir).unwrap();
        let key = dir.join("owner").to_string_lossy().into_owned();
        let (rc, _, err) = run(&mut command(dir, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", key.as_str()]));
        assert_eq!(rc, 0, "podssh keygen: {err}");
        Owner { key, doc: dir.join("owner.doc"), dir: dir.to_path_buf() }
    }

    /// `podssh net ARGS --owner-key KEY`, which must pass.
    fn says(&self, args: &[&str]) {
        let mut words = vec!["net"];
        words.extend_from_slice(args);
        words.extend_from_slice(&["--owner-key", self.key.as_str()]);
        let (rc, _, err) = net(&self.dir, &self.doc, &words);
        assert_eq!(rc, 0, "{args:?}: {err}");
    }

    /// The document as it is now, taken by the end of `home` into `doc`.
    fn give(&self, home: &Path, doc: &Path, name: &str) {
        let copy = self.dir.join(name);
        std::fs::copy(&self.doc, &copy).unwrap();
        let copy = copy.to_string_lossy().into_owned();
        let (rc, _, err) = net(home, doc, &["net", "take", copy.as_str()]);
        assert_eq!(rc, 0, "podssh net take: {err}");
    }
}

/// `podssh ssh` from the client's home with the key in `key` and the net of
/// `doc`, through the lab's DERP servers.
fn ssh_as(lab: &Lab, key: &str, doc: &Path, words: &[&str]) -> (i32, String, String) {
    let (known, servers) = (format!("UserKnownHostsFile={}", lab.known), lab.servers());
    let mut args = vec!["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", known.as_str()];
    args.extend_from_slice(&["--ca-file", lab.ca.as_str(), "--client-key", key, "--derp-server", servers.as_str()]);
    args.extend_from_slice(words);
    run(command(&lab.client_home, &args).env("PODSSH_NET", doc))
}

#[test]
fn a_member_reaches_a_derp_node_of_no_allow_by_its_name_and_a_stranger_is_refused() {
    let lab = Lab::new("net");
    let owner = Owner::new(&lab.node_home.parent().unwrap().join("owner"));
    key_file(&lab.node_home.join("node.key"), NODE_SEED);
    let laptop = key_hex(&lab.client_key);
    owner.says(&["init", "home"]);
    owner.says(&["add", "lab", node_hex().as_str()]);
    owner.says(&["add", "laptop", laptop.as_str()]);
    let (node_doc, client_doc) = (lab.node_home.join("net.doc"), lab.client_home.join("net.doc"));
    owner.give(&lab.node_home, &node_doc, "serial-3");
    // No --allow: the net is the door, and the first line says so.
    let servers = lab.servers();
    let (_node, lines, started) = lab.node_with(&[], Some(node_doc.as_path()), &["--derp", "--derp-server", &servers]);
    let door = "with no --allow, the members of the net home are its door";
    let first = started.first().expect("a first line");
    assert!(first.contains("serving") && first.contains(door), "{started:#?}");
    let seen = wait_for(&lines, "a member of the net home as lab");
    assert!(seen.last().unwrap().contains("its 1 other members may come in"), "{seen:#?}");
    assert!(!seen.iter().any(|l| l.contains("connect token")), "a word of the pair's door: {seen:#?}");
    // The owner names the node's ticket in the net; the member reaches the
    // node by its name alone, with no ticket and no pair of its own.
    let ticket = ticket_in(&started, "ticket derp:");
    owner.says(&["add", "lab", node_hex().as_str(), "--derp-ticket", ticket.as_str()]);
    owner.give(&lab.client_home, &client_doc, "serial-4");
    let (rc, out, err) = ssh_as(&lab, &lab.client_key, &client_doc, &["-v", "tester@lab", "greet"]);
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    assert!(err.contains("the DERP road answered first"), "{err}");
    let (rc, _, err) = net(&lab.node_home, &node_doc, &["net", "ls"]);
    assert!(rc == 0 && err.contains("serial 4"), "the node took the member's newer document: {err}");
    // A key that the net does not name finds the node by the same name, and
    // the node refuses it: the net's members are its whole door.
    let stranger = lab.client_home.join("stranger.key");
    key_file(&stranger, 0x51);
    let stranger = stranger.to_string_lossy().into_owned();
    let (rc, out, err) = ssh_as(&lab, &stranger, &client_doc, &["tester@lab", "greet"]);
    let refused = rc == 255 && out.is_empty() && err.contains("refused this client's key");
    assert!(refused, "a key that the net does not name reached the node: {rc} {out:?} {err}");
    let said = wait_for(&lines, "refused the operator key");
    assert!(said.last().unwrap().contains("not a member of the net home"), "{said:#?}");
    drop(lab.runtime);
}

#[test]
fn a_node_of_no_net_and_no_allow_is_refused_and_a_member_with_no_pair_serves_unasked() {
    let lab = Lab::new("net-door");
    let owner = Owner::new(&lab.node_home.parent().unwrap().join("owner"));
    let servers = lab.servers();
    let key = lab.node_home.join("node.key");
    let key_text = key.to_string_lossy().into_owned();
    let node = |doc: &Path, extra: &[&str]| {
        let mut args = vec!["node", "lab", lab.target.as_str(), "--key", key_text.as_str()];
        args.extend_from_slice(&["--ca-file", lab.ca.as_str()]);
        args.extend_from_slice(extra);
        run(command(&lab.node_home, &args).env("PODSSH_NET", doc))
    };
    let derp = ["--derp", "--derp-server", servers.as_str()];
    // No net here and no key yet: refused as before, and no key is made.
    let (rc, _, err) = node(&lab.node_home.join("none.doc"), &derp);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--derp needs --allow FILE") && err.contains("the node has no key yet"), "{err}");
    assert!(!key.exists(), "a node that was refused made its key");
    // A net that does not name the node's key is no door, nor one turned off.
    key_file(&key, NODE_SEED);
    owner.says(&["init", "home"]);
    owner.says(&["add", "laptop", key_hex(&lab.client_key).as_str()]);
    let doc = lab.node_home.join("net.doc");
    owner.give(&lab.node_home, &doc, "serial-2");
    let (rc, _, err) = node(&doc, &derp);
    assert!(rc == 64 && err.contains("does not name the node's key"), "{rc} {err}");
    let (rc, _, err) = node(Path::new("no"), &derp);
    assert!(rc == 64 && err.contains("PODSSH_NET=no"), "{rc} {err}");
    // With no --derp and no pair, a node of no door has the pair's road alone,
    // which refuses as before.
    let (rc, _, err) = node(&doc, &[]);
    assert!(rc == 78 && err.contains("no pair is stored"), "{rc} {err}");
    // Once the net names its key, the node with no pair serves the road
    // unasked (Q50), the net its door.
    owner.says(&["add", "lab", node_hex().as_str()]);
    owner.give(&lab.node_home, &doc, "serial-3");
    let (unasked, _lines, started) = lab.node_with(&[], Some(doc.as_path()), &["--derp-server", &servers]);
    let said = started.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{started:#?}"));
    assert!(said.contains("no pair is stored"), "{said}");
    assert!(started.iter().any(|l| l.contains("the members of the net home are its door")), "{started:#?}");
    drop(unasked);
    drop(lab.runtime);
}
