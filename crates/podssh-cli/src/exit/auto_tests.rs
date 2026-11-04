//! `--exit auto`'s pick with no network: the narrowest route wins, then the
//! first exit by name; a member with no role exit routes nothing; a name
//! and the flags of one exit are refused.

use serde_json::json;

use super::*;

/// A document of the net home with `members`, each `(name, roles, routes)`.
fn doc_of(members: &[(&str, &[&str], &[&str])]) -> Doc {
    let list: Vec<serde_json::Value> = members
        .iter()
        .enumerate()
        .map(|(i, (name, roles, routes))| {
            json!({"name": name, "key": format!("{:02x}", i + 1).repeat(32), "roles": roles, "routes": routes})
        })
        .collect();
    let owner = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let value = json!({
        "podssh-net": 1, "name": "home", "serial": 4, "issued": 1_793_577_600_u64, "expires": 4_102_444_800_u64,
        "owner": owner, "members": list, "requires": [],
    });
    Doc::parse(value.to_string().as_bytes()).unwrap()
}

fn at(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn the_narrowest_route_that_holds_the_address_picks_the_exit_then_the_first_by_name() {
    let exit: &[&str] = &["node", "exit"];
    let doc = doc_of(&[
        ("wide", exit, &["10.0.0.0/8"]),
        ("lab2", exit, &["10.1.0.0/16"]),
        ("lab", exit, &["10.1.0.0/16", "fd00:1::/32"]),
        ("plain", &["node"], &["10.1.2.0/24"]),
    ]);
    let picked = pick_in(&doc, at("10.1.2.3")).unwrap();
    assert_eq!(picked.name, "lab", "two /16 tie, and lab comes first by name; plain has no role exit");
    assert_eq!((picked.range.as_str(), picked.also.clone()), ("10.1.0.0/16", vec!["lab2".into(), "wide".into()]));
    assert_eq!(
        picked.line("10.1.2.3"),
        "--exit auto: 10.1.2.3 is in 10.1.0.0/16, a route of the exit lab; a route of lab2, wide holds it too"
    );
    let wide = pick_in(&doc, at("10.200.0.1")).unwrap();
    assert_eq!((wide.name.as_str(), wide.also.len()), ("wide", 0));
    assert_eq!(wide.line("10.200.0.1"), "--exit auto: 10.200.0.1 is in 10.0.0.0/8, a route of the exit wide");
    assert_eq!(pick_in(&doc, at("fd00:1::9")).unwrap().name, "lab");
    let none = pick_in(&doc, at("192.168.7.1")).unwrap_err();
    assert!(none.contains("no exit of the net home (serial 4) routes 192.168.7.1"), "{none}");
    // An IPv4 address written in IPv6 is of the other family, as at the node.
    assert!(pick_in(&doc, at("::ffff:10.1.2.3")).is_err());
}

#[test]
fn a_name_and_the_flags_of_one_exit_go_with_no_auto() {
    let refusal = address("db.lab.internal").unwrap_err();
    assert!(refusal.code == 64 && refusal.message.contains("db.lab.internal is a name"), "{}", refusal.message);
    assert_eq!(address("[fd00::1]").unwrap(), at("fd00::1"));
    assert_eq!(address("10.1.2.3").unwrap(), at("10.1.2.3"));
    assert!(flags("lab", Some("pair.json"), Some("stdio")).is_ok(), "a named exit keeps its flags");
    assert!(flags(AUTO, None, None).is_ok());
    for (pair, carrier, says) in [(Some("p"), None, "--pair-file"), (None, Some("exec:cat"), "--carrier")] {
        let refusal = flags(AUTO, pair, carrier).unwrap_err();
        assert!(refusal.code == 64 && refusal.message.starts_with(says), "{says}: {}", refusal.message);
    }
}
