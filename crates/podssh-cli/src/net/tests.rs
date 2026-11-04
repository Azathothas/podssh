//! The net's document and its signature (T-429), against the signatures of
//! OpenSSH's `ssh-keygen -Y sign` (OpenSSH_9.6p1, 2026-11-02) over
//! `testdata/net.json`, a document written by hand as an owner might: by its
//! owner in the namespace `podssh-net` (`net.json.sig`), by another key
//! (`by-other.sig`), and by its owner in the namespace `file`
//! (`wrong-namespace.sig`). `ssh-keygen -Y verify` takes the first alone.

use podssh_ssh::russh::keys::{Algorithm, PrivateKey};
use serde_json::Value;

use super::doc::{self, Doc};
use super::sign;
use crate::keygen_sign::Signing;

const DOC: &[u8] = include_bytes!("testdata/net.json");
const SIG: &[u8] = include_bytes!("testdata/net.json.sig");
const BY_OTHER: &[u8] = include_bytes!("testdata/by-other.sig");
const WRONG_NAMESPACE: &[u8] = include_bytes!("testdata/wrong-namespace.sig");
const OWNER: &str = include_str!("testdata/owner.pub");
const OTHER: &str = include_str!("testdata/other.pub");

/// The fingerprint of `testdata/owner.pub`, as `ssh-keygen -Y verify` said it.
const OWNER_PRINT: &str = "SHA256:zbnY6ML2GQd70sbSPxZeNAEroWGl/t+oaOhgQqrc/no";

#[test]
fn a_document_that_openssh_signed_is_read_as_its_owner_wrote_it() {
    let signed = sign::verify(DOC, SIG).expect("OpenSSH's signature holds");
    let doc = &signed.doc;
    assert_eq!((doc.name.as_str(), doc.serial, doc.issued, doc.expires), ("home", 3, 1_793_577_600, 4_102_444_800));
    assert_eq!(doc.owner, OWNER.trim());
    assert_eq!(sign::owner_fingerprint(&doc.owner), OWNER_PRINT);
    let lab = doc.member("lab").expect("lab");
    assert_eq!(lab.key.fingerprint().len(), OWNER_PRINT.len());
    assert!(lab.has_role("node") && !lab.has_role("exit"));
    let laptop = doc.member("laptop").expect("laptop");
    assert!(laptop.key.fingerprint().starts_with("SHA256:"), "a member named by its fingerprint");
    assert!(laptop.has_role("exit"));
    // A document of before T-617 names no relay host.
    assert!(doc.members.iter().all(|m| m.relay.is_none()));
    // The signed form is the bytes, then the armour, and reads back whole.
    let again = sign::verify_signed(&signed.to_bytes()).expect("the signed form");
    assert_eq!((again.bytes.as_slice(), again.doc.serial), (DOC, 3));
}

#[test]
fn another_key_another_namespace_and_a_changed_byte_are_refused() {
    let why = sign::verify(DOC, BY_OTHER).unwrap_err();
    assert!(why.contains("not by its owner") && why.contains(OWNER_PRINT), "{why}");
    let why = sign::verify(DOC, WRONG_NAMESPACE).unwrap_err();
    assert!(why.contains("namespace"), "{why}");
    let mut changed = DOC.to_vec();
    let at = changed.iter().position(|&b| b == b'3').expect("the serial");
    changed[at] = b'9';
    let why = sign::verify(&changed, SIG).unwrap_err();
    assert!(why.contains("incorrect signature"), "{why}");
    assert!(sign::verify_signed(DOC).is_err(), "a document with no signature");
    assert_ne!(OTHER.trim(), OWNER.trim());
}

/// A key made here, and its document of serial 1.
fn owned() -> (Signing, Doc) {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let owner = key.public_key().to_openssh().unwrap();
    let first = Doc::new("home", owner.trim(), 1_793_577_600, 4_102_444_800).unwrap();
    (Signing::Key(Box::new(key)), first)
}

#[test]
fn podssh_signs_a_document_that_it_reads_back_and_each_change_raises_the_serial() {
    let (signing, first) = owned();
    let signed = sign::sign_with(&first, &signing).unwrap();
    assert!(signed.signature.starts_with("-----BEGIN SSH SIGNATURE-----\n"), "{}", signed.signature);
    assert_eq!(signed.bytes.last(), Some(&b'\n'), "one line, and its newline");
    assert_eq!(signed.bytes.iter().filter(|&&b| b == b'\n').count(), 1);
    let member = doc::Member {
        name: "lab".into(),
        key: podssh_relay::identity::KeyName::parse(&"ab".repeat(32)).unwrap(),
        roles: vec!["node".into()],
        tickets: Default::default(),
        routes: Vec::new(),
        relay: None,
    };
    let value = doc::member_value(&member);
    assert!(value.get("routes").is_none(), "a member with no route is written as before T-432");
    assert!(value.get("relay").is_none(), "a member with no relay host is written as before T-617");
    let next = first.next(1_793_577_700, 4_102_444_800, |list| list.push(value)).unwrap();
    assert_eq!((next.serial, next.members.len()), (2, 1));
    let read = sign::verify_signed(&sign::sign_with(&next, &signing).unwrap().to_bytes()).unwrap();
    assert_eq!(read.doc, next);
}

#[test]
fn a_part_that_this_podssh_does_not_know_is_kept_or_refused_as_it_asks() {
    let (_, first) = owned();
    let mut value: Value = serde_json::from_slice(&first.to_bytes()).unwrap();
    value["later"] = serde_json::json!({"rules": ["a later podssh's"]});
    let doc = Doc::parse(value.to_string().as_bytes()).expect("an unknown field is kept, not refused");
    let next = doc.next(1_793_577_700, 4_102_444_800, |_| {}).unwrap();
    let kept: Value = serde_json::from_slice(&next.to_bytes()).unwrap();
    assert_eq!(kept["later"]["rules"][0], "a later podssh's", "a change keeps the later podssh's part");
    value["requires"] = serde_json::json!(["later"]);
    let why = Doc::parse(value.to_string().as_bytes()).unwrap_err();
    assert!(why.contains("requires \"later\"") && why.contains("podssh update"), "{why}");
    // The policy is a part that this podssh reads (T-430).
    value["requires"] = serde_json::json!(["policy"]);
    value["policy"] = serde_json::json!({"rules": []});
    assert!(Doc::parse(value.to_string().as_bytes()).unwrap().policy.is_some_and(|p| p.rules.is_empty()));
    value["requires"] = serde_json::json!([]);
    value["podssh-net"] = serde_json::json!(2);
    assert!(Doc::parse(value.to_string().as_bytes()).unwrap_err().contains("form 2"));
}

#[test]
fn a_document_with_a_fault_is_refused_with_its_reason() {
    let (_, first) = owned();
    let base: Value = serde_json::from_slice(&first.to_bytes()).unwrap();
    let member = |name: &str, key: &str| serde_json::json!({"name": name, "key": key, "roles": ["node"]});
    let cases: Vec<(&str, Value)> = vec![
        ("serial is 0", serde_json::json!({"serial": 0})),
        ("ends before", serde_json::json!({"expires": 1})),
        ("not a name", serde_json::json!({"name": "home.example"})),
        (
            "two members are named",
            serde_json::json!({"members": [member("a", &"ab".repeat(32)), member("a", &"cd".repeat(32))]}),
        ),
        (
            "the key of another",
            serde_json::json!({"members": [member("a", &"ab".repeat(32)), member("b", &"ab".repeat(32))]}),
        ),
        ("not a key", serde_json::json!({"members": [member("a", "nope")]})),
        ("owner's key", serde_json::json!({"owner": "ssh-ed25519 nope"})),
    ];
    for (says, change) in cases {
        let mut value = base.clone();
        for (field, v) in change.as_object().unwrap() {
            value[field] = v.clone();
        }
        let why = Doc::parse(value.to_string().as_bytes()).unwrap_err();
        assert!(why.contains(says), "{says}: {why}");
    }
    assert!(Doc::parse(b"[]").is_err() && Doc::parse(b"not json").is_err());
    assert!(Doc::parse(&vec![b' '; doc::MAX_DOC + 1]).unwrap_err().contains("more than"));
}

#[test]
fn names_have_no_dot_and_roles_are_known() {
    for good in ["lab", "web-01", "a_b", "X"] {
        assert!(doc::check_name(good).is_ok(), "{good}");
    }
    let long = "x".repeat(64);
    for bad in ["", "lab.example", "-lab", "a b", "a/b", long.as_str()] {
        assert!(doc::check_name(bad).is_err(), "{bad}");
    }
    assert_eq!(doc::parse_roles("node, exit,node").unwrap(), ["node", "exit"]);
    assert!(doc::parse_roles("node,funnel").unwrap_err().contains("not a role"));
    assert!(doc::parse_roles(",").is_err());
}

#[test]
fn an_exit_s_routes_are_written_read_back_and_a_word_that_is_no_range_is_kept_unused() {
    let (_, first) = owned();
    let exit = doc::Member {
        name: "gw".into(),
        key: podssh_relay::identity::KeyName::parse(&"ab".repeat(32)).unwrap(),
        roles: vec!["node".into(), "exit".into()],
        tickets: Default::default(),
        routes: vec!["10.1.0.0/16".into(), "fd00::/8".into(), "a-later-form".into()],
        relay: None,
    };
    let value = doc::member_value(&exit);
    assert_eq!(value["routes"], serde_json::json!(["10.1.0.0/16", "fd00::/8", "a-later-form"]));
    let next = first.next(1_793_577_700, 4_102_444_800, |list| list.push(value)).unwrap();
    let read = Doc::parse(&next.to_bytes()).unwrap();
    let gw = read.member("gw").unwrap();
    assert_eq!(gw.routes, exit.routes, "each word is kept as the owner wrote it");
    let ranges: Vec<&str> = gw.ranges().iter().map(|(word, _)| *word).collect();
    assert_eq!(ranges, ["10.1.0.0/16", "fd00::/8"], "a word that is no range is not used");
    let mut bad: Value = serde_json::from_slice(&next.to_bytes()).unwrap();
    bad["members"][0]["routes"] = serde_json::json!("10.1.0.0/16");
    assert!(Doc::parse(bad.to_string().as_bytes()).unwrap_err().contains("\"routes\" is not a list"));
    bad["members"][0]["routes"] = serde_json::json!([7]);
    assert!(Doc::parse(bad.to_string().as_bytes()).unwrap_err().contains("a route that is not text"));
}

/// T-617: a relay role's host is written only when given, read back as the
/// owner wrote it, kept unused when this podssh does not read it as a host,
/// and refused when it is not text.
#[test]
fn a_relay_member_s_host_is_written_read_back_and_a_word_that_is_no_host_is_kept_unused() {
    let (_, first) = owned();
    let relay = doc::Member {
        name: "lab".into(),
        key: podssh_relay::identity::KeyName::parse(&"ab".repeat(32)).unwrap(),
        roles: vec!["relay".into()],
        tickets: Default::default(),
        routes: Vec::new(),
        relay: Some("relay.example.org:8443".into()),
    };
    let value = doc::member_value(&relay);
    assert_eq!(value["relay"], "relay.example.org:8443");
    let next = first.next(1_793_577_700, 4_102_444_800, |list| list.push(value)).unwrap();
    let read = Doc::parse(&next.to_bytes()).unwrap();
    assert_eq!(read.member("lab").unwrap(), &relay, "read back as written");
    let mut odd: Value = serde_json::from_slice(&next.to_bytes()).unwrap();
    odd["members"][0]["relay"] = serde_json::json!("a later form!");
    let kept = Doc::parse(odd.to_string().as_bytes()).expect("a host that this podssh does not read is kept");
    assert_eq!(kept.member("lab").unwrap().relay.as_deref(), Some("a later form!"));
    odd["members"][0]["relay"] = serde_json::json!(["relay.example.org"]);
    assert!(Doc::parse(odd.to_string().as_bytes()).unwrap_err().contains("\"relay\" is not text"));
}

/// T-617: `add --relay-host` takes one host, as `--relay-host` reads it, and
/// only with the role relay; it writes the host as `host` or `host:port`.
#[test]
fn the_relay_host_of_add_is_one_host_and_only_with_the_role_relay() {
    let roles = |list: &[&str]| list.iter().map(|r| r.to_string()).collect::<Vec<_>>();
    let relay = roles(&["node", "relay"]);
    let host = |text: &str| super::edit::relay_host(Some(text), &relay);
    assert_eq!(super::edit::relay_host(None, &relay).unwrap(), None);
    assert_eq!(host("relay.example.org").unwrap().as_deref(), Some("relay.example.org"));
    assert_eq!(host("relay.example.org:443").unwrap().as_deref(), Some("relay.example.org"));
    assert_eq!(host("wss://Relay.Example.org:8443/").unwrap().as_deref(), Some("relay.example.org:8443"));
    let no_role = super::edit::relay_host(Some("relay.example.org"), &roles(&["node", "exit"])).unwrap_err();
    assert!(no_role.code == 64 && no_role.message.contains("give --roles with relay too"), "{no_role}");
    let two = host("a.example.org,b.example.org").unwrap_err();
    assert!(two.code == 64 && two.message.contains("one host"), "{two}");
    let bad = host("not a host!").unwrap_err();
    assert!(bad.code == 64 && bad.message.starts_with("--relay-host: "), "{bad}");
}
