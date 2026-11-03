//! Grants used once (T-226), offline: certificates that OpenSSH 9.6's
//! `ssh-keygen -s` minted (`tests/fixtures/grant/`) let an operator's key in
//! once through the end-to-end channel, and each other grant is refused
//! before the node dials; the grant crosses the stand-in relay encrypted.
//!
//! The fixtures: the keys of the seeds 0x11 (the operator), 0x22 (the node)
//! and 0x44 (another node), whose public halves OpenSSL derived, and an
//! issuer that `ssh-keygen -t ed25519` made, its private half thrown away
//! (`issuer.pub`). Each grant came from `ssh-keygen -s issuer -I ID -n
//! node:SHA256:<the node's> -O clear -O critical:once@podssh -V
//! 20261101000000Z:20261201000000Z -z SERIAL operator.pub`: `once` (42),
//! `route` (43, `/web`), `unknown` (44, also `critical:color@example.com=blue`),
//! `reusable` (45, no `once@podssh`), `forever` (46, no `-V`), `host` (47,
//! `-h`), `elsewhere` (48, the node of seed 0x44), and `own` (49, signed by
//! the node's own key, written as an OpenSSH key).
#![cfg(all(feature = "pair", feature = "grant"))]

mod e2e_harness;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use e2e_harness::{echo, echo_back, holds, identity, stand_in, Fault, LIMIT, PIPE};
use podssh_relay::e2e::ends::{self, Node, Redeem, GRANT_REFUSED};
use podssh_relay::e2e::{Ask, Error, Refusal};
use podssh_relay::grant::{self, Cert, Door, Mint, Spent};
use podssh_relay::identity::PublicKey;

/// 2026-11-15, inside the fixtures' window.
const NOW: u64 = 1_794_700_800;
/// The end of the fixtures' window, 2026-12-01.
const END: u64 = 1_796_083_200;
/// The start of the fixtures' window, 2026-11-01.
const START: u64 = 1_793_491_200;

fn fixture(name: &str) -> Cert {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/grant").join(name);
    Cert::from_text(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn issuer() -> PublicKey {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/grant/issuer.pub");
    grant::parse_public(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn scratch(tag: u32) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-grant-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The door of the node of seed 0x22, whose records are in `dir`, with the
/// fixtures' issuer as its one other issuer when `trusted`.
fn door(dir: &Path, trusted: bool) -> Door {
    let theirs = issuer();
    let issuers: Arc<grant::Issuers> = Arc::new(move |key: &PublicKey, _: &Ask| -> Result<(), String> {
        match trusted && *key == theirs {
            true => Ok(()),
            false => Err("not an issuer of this test's".into()),
        }
    });
    Door { node: identity(0x22).public(), issuers, spent: Spent::at(dir.join("grants-lab")), revoked: None }
}

/// A node's end and the lines that it said.
type Served = (Node, Arc<Mutex<Vec<String>>>);

/// The check of `door` at `now`, as a node's end runs it.
fn redeem_of(door: Door, now: u64) -> Arc<Redeem> {
    Arc::new(move |peer: &PublicKey, ask: &Ask, blob: &[u8]| {
        door.redeem(peer, ask, blob, now).map(|redeemed| redeemed.to_string())
    })
}

/// The node of seed 0x22 with `door` at `now`, whose allowlist names nobody.
fn node(door: Door, now: u64) -> Served {
    let (mut node, lines) = e2e_harness::node(identity(0x22), |_: &PublicKey| Err("the allowlist names nobody".into()));
    node.redeem = Some(redeem_of(door, now));
    (node, lines)
}

/// What one session gave.
struct Ran {
    result: Result<PublicKey, Error>,
    echoed: bool,
    opened: usize,
    /// Whether the node opened its target as a grant's, with its route's
    /// check done.
    granted: bool,
    carried: Vec<u8>,
    lines: Vec<String>,
}

/// One session of the operator of `seed`, with `grant`, to `route` of the
/// node, through a stand-in relay that keeps each byte.
async fn session(seed: u8, grant: Option<Vec<u8>>, route: Option<&str>, node: Served) -> Ran {
    let opened = Arc::new(AtomicUsize::new(0));
    let granted = Arc::new(AtomicBool::new(false));
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let check = |_: &PublicKey| -> Result<(), String> { Ok(()) };
    let (cipher, channel) = ends::operator_granted(app_end, identity(seed), check, route.map(str::to_string), grant);
    let (node_link, relay_end) = tokio::io::duplex(PIPE);
    let (node_end, lines) = node;
    let (target, seen) = (echo(opened.clone()), granted.clone());
    let node_task = tokio::spawn(async move {
        // Each ask opens the echo: the door alone decides here.
        ends::serve_asked(node_link, &node_end, move |_, _: Ask| async move {
            seen.store(ends::granted(), Ordering::SeqCst);
            target().await.map_err(Refusal::NoTarget)
        })
        .await
    });
    let carried = Arc::new(Mutex::new(Vec::new()));
    stand_in(cipher, relay_end, (Fault::None, Arc::default()), Fault::None, carried.clone());
    let channel = tokio::spawn(channel);
    let said = b"through the grant";
    let echoed = echo_back(&mut app, said).await.is_ok_and(|back| back == said);
    drop(app);
    let result = tokio::time::timeout(LIMIT, channel).await.expect("the channel ends").unwrap();
    let _ = tokio::time::timeout(LIMIT, node_task).await;
    let carried = carried.lock().unwrap().clone();
    let lines = lines.lock().unwrap().clone();
    let (opened, granted) = (opened.load(Ordering::SeqCst), granted.load(Ordering::SeqCst));
    Ran { result, echoed, opened, granted, carried, lines }
}

fn refused_as_a_grant(ran: &Ran) -> bool {
    matches!(&ran.result, Err(Error::Refused(Refusal::Other(why))) if why == GRANT_REFUSED)
}

/// The grant that OpenSSH minted lets its key in once: the session carries
/// its bytes, the relay never sees the grant, and a second use is refused,
/// also by a node that starts again with the same records.
#[tokio::test]
async fn a_grant_that_openssh_minted_lets_its_key_in_once() {
    let dir = scratch(line!());
    let blob = fixture("once-cert.pub").blob();
    let first = session(0x11, Some(blob.clone()), None, node(door(&dir, true), NOW)).await;
    assert_eq!(first.result.as_ref().ok(), Some(&identity(0x22).public()), "{:?} {:?}", first.result, first.lines);
    assert!(first.echoed && first.opened == 1 && first.granted, "{:?}", first.lines);
    assert!(first.lines.iter().any(|l| l.contains("serial 42")), "{:?}", first.lines);
    assert!(!holds(&first.carried, &blob[blob.len() - 64..]), "the grant's signature crossed the relay in clear");
    assert!(!holds(&first.carried, b"node:SHA256:"), "the grant's principal crossed the relay in clear");

    let again = session(0x11, Some(blob.clone()), None, node(door(&dir, true), NOW + 60)).await;
    assert!(refused_as_a_grant(&again), "{:?}", again.result);
    assert_eq!(again.opened, 0, "a replay reached the target");
    assert!(again.lines.iter().any(|l| l.contains("was used already")), "{:?}", again.lines);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A case of a grant refused: what it is, the grant's bytes, the seed of the
/// operator's key, the node's time, whether the issuer is trusted, and the
/// words of the node's log.
type Case = (&'static str, Vec<u8>, u8, u64, bool, &'static str);

/// Each grant that is not this one's is refused with its reason in the
/// node's log, and the node dials nothing.
#[tokio::test]
async fn each_other_grant_is_refused_before_the_node_dials() {
    let mut flipped = fixture("once-cert.pub").blob();
    // The serial's last byte, inside what the issuer signed.
    flipped[4 + 32 + 4 + 32 + 4 + 32 + 7] ^= 1;
    let cases: Vec<Case> = vec![
        ("another node", fixture("elsewhere-cert.pub").blob(), 0x11, NOW, true, "it names"),
        ("a window that ended", fixture("once-cert.pub").blob(), 0x11, END + grant::SKEW_SECS + 1, true, "ended"),
        ("a window to come", fixture("once-cert.pub").blob(), 0x11, START - grant::SKEW_SECS - 60, true, "starts in"),
        ("an unknown option", fixture("unknown-cert.pub").blob(), 0x11, NOW, true, "color@example.com"),
        ("no once", fixture("reusable-cert.pub").blob(), 0x11, NOW, true, "no critical option once@podssh"),
        ("no end", fixture("forever-cert.pub").blob(), 0x11, NOW, true, "has no end"),
        ("a host certificate", fixture("host-cert.pub").blob(), 0x11, NOW, true, "host certificate"),
        ("another key", fixture("once-cert.pub").blob(), 0x33, NOW, true, "is for the key"),
        ("an issuer not trusted", fixture("once-cert.pub").blob(), 0x11, NOW, false, "is not one of this node's"),
        ("a changed serial", flipped, 0x11, NOW, true, "does not verify"),
        ("no certificate", b"not a grant".to_vec(), 0x11, NOW, true, "not a grant"),
    ];
    for (n, (what, blob, seed, now, trusted, why)) in cases.into_iter().enumerate() {
        let dir = scratch(1000 + n as u32);
        let ran = session(seed, Some(blob), None, node(door(&dir, trusted), now)).await;
        assert!(refused_as_a_grant(&ran), "{what}: {:?} {:?}", ran.result, ran.lines);
        assert_eq!(ran.opened, 0, "{what}: the node dialed");
        assert!(ran.lines.iter().any(|l| l.contains(why)), "{what}: {:?}", ran.lines);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The node's own key is an issuer with no other word: OpenSSH signed this
/// grant with it, and the door trusts no other issuer.
#[tokio::test]
async fn a_grant_of_the_node_s_own_key_needs_no_other_issuer() {
    let dir = scratch(line!());
    let ran = session(0x11, Some(fixture("own-cert.pub").blob()), None, node(door(&dir, false), NOW)).await;
    assert!(ran.result.is_ok() && ran.echoed && ran.opened == 1, "{:?} {:?}", ran.result, ran.lines);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A grant of a route lets in that route alone, and stands for the key's
/// own line of it; a grant of the target lets in no route.
#[tokio::test]
async fn a_grant_names_its_route_and_stands_for_the_key_s_line() {
    let dir = scratch(line!());
    let route = fixture("route-cert.pub").blob();
    let ran = session(0x11, Some(route.clone()), Some("web"), node(door(&dir, true), NOW)).await;
    assert!(ran.result.is_ok() && ran.granted, "{:?} {:?}", ran.result, ran.lines);
    let ran = session(0x11, Some(route), None, node(door(&dir, true), NOW)).await;
    assert!(refused_as_a_grant(&ran) && ran.opened == 0, "the target with no route: {:?}", ran.lines);
    let ran = session(0x11, Some(fixture("once-cert.pub").blob()), Some("web"), node(door(&dir, true), NOW)).await;
    assert!(refused_as_a_grant(&ran) && ran.opened == 0, "a route of a grant of the target: {:?}", ran.lines);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An operator with no grant goes by the door as before; a node that reads
/// no grant sets one aside and goes by its door too.
#[tokio::test]
async fn an_operator_with_no_grant_and_a_node_that_reads_none_go_as_before() {
    let dir = scratch(line!());
    let (mut open_node, lines) = e2e_harness::node(identity(0x22), |_: &PublicKey| Ok(()));
    open_node.redeem = Some(redeem_of(door(&dir, true), NOW));
    let ran = session(0x11, None, None, (open_node, lines)).await;
    assert!(ran.result.is_ok() && ran.echoed && !ran.granted, "{:?} {:?}", ran.result, ran.lines);
    let reads_none = e2e_harness::node(identity(0x22), |_: &PublicKey| Ok(()));
    let ran = session(0x11, Some(fixture("once-cert.pub").blob()), None, reads_none).await;
    assert!(ran.result.is_ok() && ran.echoed && !ran.granted, "{:?}", ran.result);
    assert!(ran.lines.iter().any(|l| l.contains("set aside the grant")), "{:?}", ran.lines);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A serial in the file of `--revoked` is refused; a file that is missing
/// lets no grant in.
#[tokio::test]
async fn a_revoked_serial_is_refused() {
    let dir = scratch(line!());
    podssh_relay::cache::private_dir(&dir).unwrap();
    let file = dir.join("revoked");
    std::fs::write(&file, "# serials\n42\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let blob = fixture("once-cert.pub").blob();
    let revoked = Door { revoked: Some(file), ..door(&dir, true) };
    let ran = session(0x11, Some(blob.clone()), None, node(revoked, NOW)).await;
    assert!(refused_as_a_grant(&ran) && ran.lines.iter().any(|l| l.contains("revoked")), "{:?}", ran.lines);
    let missing = Door { revoked: Some(dir.join("missing")), ..door(&dir, true) };
    let ran = session(0x11, Some(blob), None, node(missing, NOW)).await;
    assert!(refused_as_a_grant(&ran) && ran.opened == 0, "{:?}", ran.lines);
    let _ = std::fs::remove_dir_all(&dir);
}

/// podssh's writer gives the bytes that `ssh-keygen -s` gave for the same
/// fields and nonce: Ed25519's signature is deterministic.
#[test]
fn podssh_mints_the_bytes_that_ssh_keygen_minted() {
    let theirs = fixture("own-cert.pub");
    let mut nonce = [0u8; 32];
    let hex = "8ff568d971cc7fd3b82b4177d2d567b4f841711dab218ec4f8f93f951365c320";
    for (i, byte) in nonce.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    let node = identity(0x22);
    let principals = vec![grant::principal(&node.public(), None)];
    let mint = Mint {
        nonce,
        key: identity(0x11).public(),
        serial: 49,
        key_id: "by the node",
        principals: &principals,
        valid_after: START,
        valid_before: END,
        critical: &[(grant::ONCE, &b""[..])],
    };
    let ours = mint.sign(&node);
    assert_eq!(ours.blob(), theirs.blob(), "the bytes of ssh-keygen -s");
    assert_eq!(theirs.issuer, node.public());
    assert_eq!(theirs.principals, principals, "the principal is node: and the node's fingerprint");
}

/// The fixtures read as OpenSSH wrote them.
#[test]
fn the_fixtures_read_as_ssh_keygen_wrote_them() {
    let once = fixture("once-cert.pub");
    assert_eq!((once.serial, once.kind, once.key_id.as_str()), (42, grant::USER, "grant for lab"));
    assert_eq!((once.valid_after, once.valid_before), (START, END));
    assert_eq!(once.critical, [(grant::ONCE.to_string(), Vec::new())]);
    assert!(once.extensions.is_empty() && once.signed_by_issuer());
    assert_eq!((once.key, once.issuer), (identity(0x11).public(), issuer()));
    assert_eq!(fixture("host-cert.pub").kind, grant::HOST);
    assert_eq!(fixture("forever-cert.pub").valid_before, u64::MAX);
    assert_eq!(fixture("route-cert.pub").principals, [grant::principal(&identity(0x22).public(), Some("web"))]);
    assert_eq!(fixture("elsewhere-cert.pub").principals, [grant::principal(&identity(0x44).public(), None)]);
}

/// A grant goes in the channel alone: a URL in the place of its file is
/// refused before a request exists.
#[test]
fn a_grant_in_a_url_is_refused_before_a_request_exists() {
    for url in ["https://relay.example/v1/grant", "wss://relay.example/v1/connect/p-a?grant=AAAA"] {
        let refused = grant::read_file(Path::new(url)).unwrap_err();
        assert!(refused.contains("never a URL"), "{url}: {refused}");
    }
}
