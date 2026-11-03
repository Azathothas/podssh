//! The net's policy (T-430) on documents made here: its words, its ranges,
//! its rules and its check, as a node gives each verdict and as `podssh net
//! policy check` says it; the strict check of a policy that the owner sets,
//! and the tolerance of one that a later podssh wrote, which lets in less,
//! never more.

use std::net::IpAddr;

use serde_json::{json, Value};

use super::doc::Doc;
use super::policy::{self, Want};
use super::policy_words::{Dest, Range, Src};

const OWNER: &str = include_str!("testdata/owner.pub");

/// A document of the net home, serial 2, with four members (gw has the role
/// exit) and `policy`, if one.
fn doc_with(policy: Option<Value>) -> Doc {
    let first = Doc::new("home", OWNER.trim(), 1_793_577_600, 4_102_444_800).unwrap();
    let member = |name: &str, seed: u8, roles: &[&str]| json!({"name": name, "key": format!("{seed:02x}").repeat(32), "roles": roles});
    let members = json!([
        member("lab", 0x21, &["node"]),
        member("gw", 0x22, &["node", "exit"]),
        member("laptop", 0x31, &["node"]),
        member("phone", 0x41, &["node"]),
    ]);
    let next = first.next_whole(1_793_577_700, 4_102_444_800, |whole| {
        whole.insert("members".into(), members);
        if let Some(policy) = policy {
            whole.insert("policy".into(), policy);
        }
    });
    next.unwrap()
}

/// The verdict of the member `from` for `want`.
fn lets(doc: &Doc, from: &str, want: Want<'_>) -> Result<String, String> {
    policy::check(doc, doc.member(from).unwrap(), want)
}

fn node<'a>(node: &'a str, route: Option<&'a str>) -> Want<'a> {
    Want::Node { node, route }
}

fn addr(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn with_no_policy_each_member_reaches_each() {
    let doc = doc_with(None);
    let wants = [node("lab", None), node("lab", Some("db")), Want::Exit("gw"), Want::Addr(addr("10.9.8.7"))];
    for want in wants.into_iter().chain([Want::AnyOf("phone")]) {
        let why = lets(&doc, "phone", want).unwrap();
        assert!(why.contains("the net home has no policy"), "{want}: {why}");
    }
}

#[test]
fn a_rule_lets_its_members_and_tags_reach_what_it_names_and_nothing_else() {
    let doc = doc_with(Some(json!({
        "tags": {"dev": ["phone"], "servers": ["lab"]},
        "rules": [
            {"from": ["laptop"], "to": ["lab", "exit:gw", "10.1.0.0/16", "fd00::/8"], "note": "the owner's laptop"},
            {"from": ["tag:dev"], "to": ["lab/web"]},
            {"from": ["*"], "to": ["tag:servers"], "ports": [22]},
        ],
    })));
    // laptop: lab whole (its target and each route), gw's exit, two ranges,
    // and the doors of the nodes that those reach.
    let wants = [node("lab", None), node("lab", Some("db")), Want::Exit("gw"), Want::AnyOf("lab"), Want::AnyOf("gw")];
    for want in wants.into_iter().chain([Want::Addr(addr("10.1.255.254")), Want::Addr(addr("fd12::1"))]) {
        let why = lets(&doc, "laptop", want).unwrap_or_else(|why| panic!("{want}: {why}"));
        assert!(why.starts_with("rule 1 of the net home's policy (serial 2): from laptop to lab"), "{why}");
        assert!(why.ends_with("(the owner's laptop)"), "the rule's note: {why}");
    }
    // phone, by its tag: lab's web alone, and lab's door to ask for it.
    for want in [node("lab", Some("web")), Want::AnyOf("lab")] {
        assert!(lets(&doc, "phone", want).unwrap().starts_with("rule 2 "), "{want}");
    }
    // Each other: refused, in the policy's words. Rule 3 has a field that
    // this podssh does not read, so it lets nobody in: the field may narrow it.
    for (from, want) in [
        ("laptop", node("gw", None)),
        ("laptop", Want::Exit("lab")),
        ("laptop", Want::Addr(addr("10.2.0.1"))),
        ("laptop", Want::Addr(addr("::ffff:10.1.0.1"))),
        ("phone", node("lab", None)),
        ("phone", node("lab", Some("db"))),
        ("phone", Want::Exit("gw")),
        ("phone", Want::AnyOf("gw")),
        ("gw", node("lab", None)),
        ("lab", node("laptop", None)),
    ] {
        let why = lets(&doc, from, want).unwrap_err();
        assert_eq!(why, format!("no rule of the net home's policy (serial 2) lets {from} reach {want}"));
    }
}

#[test]
fn an_empty_list_of_rules_lets_nobody_in() {
    let doc = doc_with(Some(json!({"rules": []})));
    for want in [node("lab", None), Want::AnyOf("lab"), Want::Exit("gw"), Want::Addr(addr("10.0.0.1"))] {
        assert!(lets(&doc, "laptop", want).unwrap_err().starts_with("no rule of the net home's policy"), "{want}");
    }
    // A policy with no list at all is no list of rules: nobody either.
    let doc = doc_with(Some(json!({"tags": {"dev": ["laptop"]}})));
    assert!(lets(&doc, "laptop", node("lab", None)).is_err());
}

#[test]
fn the_words_of_a_rule_are_read_by_their_form() {
    assert_eq!(Src::parse("*"), Src::All);
    assert_eq!(Src::parse("laptop"), Src::Member("laptop"));
    assert_eq!(Src::parse("tag:dev"), Src::Tag("dev"));
    for unknown in ["tag:", "tag:a.b", "a.b", "group:dev", ""] {
        assert_eq!(Src::parse(unknown), Src::Unknown, "{unknown}");
    }
    assert_eq!(Dest::parse("*"), Dest::All);
    assert_eq!(Dest::parse("lab"), Dest::Node("lab"));
    assert_eq!(Dest::parse("lab/web.v2"), Dest::Route("lab", "web.v2"));
    assert_eq!(Dest::parse("tag:servers"), Dest::Tag("servers"));
    assert_eq!(Dest::parse("exit:*"), Dest::Exit(None));
    assert_eq!(Dest::parse("exit:gw"), Dest::Exit(Some("gw")));
    assert_eq!(Dest::parse("10.1.0.0/16"), Dest::Range(Range::parse("10.1.0.0/16").unwrap()));
    assert_eq!(Dest::parse("fd00::1"), Dest::Range(Range::parse("fd00::1/128").unwrap()));
    assert_eq!(Dest::parse("relay:*"), Dest::Relay(None));
    assert_eq!(Dest::parse("relay:gw"), Dest::Relay(Some("gw")));
    let unknown = ["lab/", "/web", "lab/-web", "10.0.0.0/33", "10.0.0.0/+8", "fd00::/129", "exit:", "lab:22"];
    for word in unknown.into_iter().chain(["autogroup:internet", "relay:", "relay:a.b"]) {
        assert_eq!(Dest::parse(word), Dest::Unknown, "{word}");
    }
}

/// A relay role's mint (T-455): `relay:NODE` names the role of one node,
/// `relay:*` each, a role that is no member too, and neither opens a door of
/// the node; `*` reaches each relay, and with no policy each member mints.
#[test]
fn a_relay_word_lets_its_members_mint_at_that_relay_and_reach_nothing_else() {
    let doc = doc_with(Some(json!({
        "rules": [
            {"from": ["laptop"], "to": ["relay:gw"]},
            {"from": ["phone"], "to": ["relay:*"]},
            {"from": ["lab"], "to": ["exit:gw", "gw"]},
        ],
    })));
    assert!(lets(&doc, "laptop", Want::Relay(Some("gw"))).unwrap().starts_with("rule 1 "));
    for want in [Want::Relay(Some("gw")), Want::Relay(Some("lab")), Want::Relay(None)] {
        assert!(lets(&doc, "phone", want).unwrap().starts_with("rule 2 "), "{want}");
    }
    for (from, want) in [
        ("laptop", Want::Relay(Some("lab"))),
        ("laptop", Want::Relay(None)),
        ("laptop", Want::AnyOf("gw")),
        ("laptop", node("gw", None)),
        ("phone", Want::Exit("gw")),
        ("lab", Want::Relay(Some("gw"))),
    ] {
        let why = lets(&doc, from, want).unwrap_err();
        assert_eq!(why, format!("no rule of the net home's policy (serial 2) lets {from} reach {want}"));
    }
    assert_eq!(format!("{} {}", Want::Relay(Some("gw")), Want::Relay(None)), "relay:gw relay:*");
    let all = doc_with(Some(json!({"rules": [{"from": ["*"], "to": ["*"]}]})));
    assert!(lets(&all, "lab", Want::Relay(None)).is_ok(), "* reaches each relay");
    assert!(lets(&doc_with(None), "lab", Want::Relay(Some("gw"))).unwrap().contains("has no policy"));
    // The owner's check says a relay of a name that no member has.
    let set = json!({"rules": [{"from": ["laptop"], "to": ["relay:nas", "relay:*"]}]});
    let (_, said) = policy::checked(&set, &doc_with(None)).unwrap();
    assert!(said.iter().any(|line| line == "rule 1 reaches relay:nas, but the net home has no member nas"), "{said:?}");
}

#[test]
fn a_range_holds_the_addresses_of_its_first_bits() {
    let range = |text: &str| Range::parse(text).unwrap();
    let holds = |text: &str, one: &str| range(text).contains(addr(one));
    assert!(holds("10.1.0.0/16", "10.1.255.254") && !holds("10.1.0.0/16", "10.2.0.1"));
    assert!(holds("10.1.2.3", "10.1.2.3") && !holds("10.1.2.3", "10.1.2.4"), "an address alone is its own range");
    assert!(holds("192.168.0.0/20", "192.168.15.1") && !holds("192.168.0.0/20", "192.168.16.1"));
    assert!(holds("0.0.0.0/0", "8.8.8.8") && !holds("0.0.0.0/0", "::1"), "a range holds its own family only");
    assert!(holds("fd00::/8", "fdab::1") && !holds("fd00::/8", "fe80::1"));
    assert!(holds("::/0", "2001:db8::1"));
}

#[test]
fn a_policy_that_the_owner_sets_is_checked_strictly() {
    let doc = doc_with(None);
    let good = json!({"tags": {"dev": ["phone", "tablet"]}, "rules": [
        {"from": ["laptop", "tag:dev", "printer"], "to": ["lab", "exit:lab", "exit:nas", "10.0.0.0/8", "*"]},
    ]});
    let (read, said) = policy::checked(&good, &doc).unwrap();
    assert_eq!((read.rules.len(), read.tags.len()), (1, 1));
    for words in [
        "the tag dev holds tablet, but the net home has no member tablet",
        "rule 1 is from printer, but the net home has no member printer",
        "rule 1 reaches exit:lab, but lab has no role exit",
        "rule 1 reaches exit:nas, but the net home has no member nas",
    ] {
        assert!(said.iter().any(|line| line == words), "{words}: {said:?}");
    }
    let (_, said) = policy::checked(&json!({"rules": []}), &doc).unwrap();
    assert!(said.iter().any(|line| line.contains("no member reaches another")), "{said:?}");
    for (value, says) in [
        (json!([]), "not a JSON object"),
        (json!({"rules": [], "deny": []}), "field \"deny\" is not one that podssh reads"),
        (json!({"tags": {}}), "has no \"rules\""),
        (json!({"rules": [{"from": ["laptop"], "to": ["lab"], "ports": [22]}]}), "rule 1: the field \"ports\""),
        (json!({"rules": [{"from": ["laptop"]}]}), "rule 1 needs a \"from\" and a \"to\""),
        (json!({"rules": [{"from": ["tag:ops"], "to": ["lab"]}]}), "the tag ops is not in the policy's \"tags\""),
        (json!({"rules": [{"from": ["laptop"], "to": ["tag:ops"]}]}), "the tag ops is not in the policy's \"tags\""),
        (json!({"rules": [{"from": ["group:x"], "to": ["lab"]}]}), "is not who a rule is from"),
        (json!({"rules": [{"from": ["laptop"], "to": ["lab:22"]}]}), "is not what a rule reaches"),
        (json!({"rules": [{"from": "laptop", "to": ["lab"]}]}), "the \"from\" of rule 1 is not a list"),
        (json!({"rules": ["laptop"]}), "rule 1 is not an object"),
        (json!({"rules": [], "tags": {"a.b": []}}), "the tag \"a.b\" is not a name"),
    ] {
        let why = policy::checked(&value, &doc).unwrap_err();
        assert!(why.contains(says), "{value}: {why}");
    }
}

#[test]
fn a_later_podssh_s_word_or_field_lets_nobody_in_and_a_wrong_form_is_refused() {
    let doc = doc_with(Some(json!({
        "rules": [
            {"from": ["laptop"], "to": ["lab"], "when": "weekdays"},
            {"from": ["group:admins"], "to": ["*"]},
            {"from": ["laptop"], "to": ["svc:web", "lab/db"]},
        ],
        "denies": ["a later podssh's"],
    })));
    assert!(lets(&doc, "laptop", node("lab", None)).is_err(), "a rule with a field unread lets nobody in");
    assert!(lets(&doc, "phone", node("lab", None)).is_err(), "a word unread names nobody");
    assert!(lets(&doc, "laptop", node("lab", Some("db"))).unwrap().starts_with("rule 3 "), "the words read still hold");
    // A policy whose form is wrong is a document refused whole, as each other
    // fault of a document's form is.
    let mut value: Value = serde_json::from_slice(&doc_with(None).to_bytes()).unwrap();
    for (policy, says) in [
        (json!("all"), "the policy is not a JSON object"),
        (json!({"rules": {}}), "\"rules\" is not a list"),
        (json!({"rules": [{"to": [1]}]}), "holds a word that is not text"),
        (json!({"tags": []}), "\"tags\" is not an object"),
    ] {
        value["policy"] = policy;
        let why = Doc::parse(value.to_string().as_bytes()).unwrap_err();
        assert!(why.contains(says), "{why}");
    }
}
