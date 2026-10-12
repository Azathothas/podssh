//! The hosts of a word (T-184): ranges with and without their padding,
//! lists, nesting, the limit of 1000, a group of a settings file, and a
//! cycle of groups refused as the file's fault.

use super::*;

fn hosts(word: &str) -> Vec<String> {
    expand(word, &Groups::new()).unwrap_or_else(|r| panic!("{word}: {r}"))
}

/// The settings of the fixture: a setting, then the table of groups.
fn fixture() -> crate::settings::Defaults {
    let text = include_str!("../tests/fixtures/groups.settings");
    crate::settings::parse(text, "groups.settings", None).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn a_range_gives_each_number_and_keeps_a_zero_padding() {
    assert_eq!(hosts("web{1..3}"), ["web1", "web2", "web3"]);
    let padded = hosts("{01..10}");
    assert_eq!(padded.len(), 10);
    assert_eq!((padded[0].as_str(), padded[8].as_str(), padded[9].as_str()), ("01", "09", "10"));
    assert_eq!(hosts("web{01..03}.example.org")[2], "web03.example.org");
    assert_eq!(hosts("n{8..10}"), ["n8", "n9", "n10"], "no padding with no leading 0");
    assert_eq!(hosts("n{1..010}")[0], "n001", "the wider of the two, as bash pads");
    assert_eq!(hosts("n{1..9..4}"), ["n1", "n5", "n9"]);
    assert_eq!(hosts("rack{a..c}"), ["racka", "rackb", "rackc"]);
}

#[test]
fn lists_nest_in_the_order_of_bash() {
    assert_eq!(hosts("a{b,c}d"), ["abd", "acd"]);
    assert_eq!(hosts("a{b,c{d,e}}f"), ["abf", "acdf", "acef"]);
    assert_eq!(hosts("{a,b}{1,2}"), ["a1", "a2", "b1", "b2"]);
    assert_eq!(hosts("web{1..2}.{eu,us}"), ["web1.eu", "web1.us", "web2.eu", "web2.us"]);
    assert_eq!(hosts("u@web{1,2}:2222, db"), ["u@web1:2222", "u@web2:2222", "db"]);
    assert_eq!(hosts("w{,1}"), ["w", "w1"], "an empty item gives the rest alone");
    assert_eq!(hosts("a,b,a"), ["a", "b"], "a host named twice runs once");
    assert_eq!(hosts("[2001:db8::1]:22"), ["[2001:db8::1]:22"], "brackets stay an IPv6 literal");
    assert!(!is_pattern("u@[2001:db8::1]:22") && is_pattern("a,b") && is_pattern("w{1..2}") && is_pattern("@web"));
}

#[test]
fn more_than_1000_hosts_none_or_a_range_that_runs_backwards_is_64() {
    assert_eq!(hosts("h{1..1000}").len(), 1000);
    for (word, says) in [
        ("h{1..1001}", "more than 1000"),
        ("h{0..1000}", "more than 1000"),
        ("h{1..1000},x", "more than 1000"),
        ("h{1..100}{1..100}", "more than 1000"),
        ("h{3..1}", "runs backwards"),
        ("h{c..a}", "runs backwards"),
        ("h{}", "holds nothing"),
        ("h{1..}", "neither a list"),
        ("h{1..5..0}", "neither a list"),
        ("h{a}", "neither a list"),
        ("h{1,2", "with no }"),
        ("h}", "with no {"),
        ("a,,b", "an empty host"),
        ("", "an empty host"),
        ("{,}", "an empty host"),
        ("h{1, 2}", "a blank inside braces"),
        ("@web", "no group of that name"),
    ] {
        let refusal = expand(word, &Groups::new()).expect_err(word);
        assert_eq!(refusal.code, 64, "{word}: {refusal}");
        assert!(refusal.message.contains(says), "{word}: {refusal}");
    }
}

#[test]
fn a_group_of_the_settings_file_names_hosts_and_groups() {
    let settings = fixture();
    assert_eq!(settings.relay_failover.as_ref().map(|v| v.text.as_str()), Some("serial"));
    let groups = &settings.groups;
    let web = ["web01.example.org", "web02.example.org", "web03.example.org"];
    assert_eq!(expand("@web", groups).unwrap(), web);
    let db = ["u@db1.example.org:2222", "u@db2.example.org:2222"];
    let all: Vec<&str> = web.iter().chain(&db).copied().chain(["bastion.example.org"]).collect();
    assert_eq!(expand("@all", groups).unwrap(), all);
    assert_eq!(expand("web02.example.org,@web", groups).unwrap()[..2], ["web02.example.org", "web01.example.org"]);
    // A command that logs in to one host takes a group of one, and refuses
    // more, naming podssh each.
    assert_eq!(one("plain.example.org", groups).unwrap(), "plain.example.org");
    assert_eq!(one("@one", groups).unwrap(), "bastion.example.org");
    assert_eq!(one("web{01..01}.example.org", groups).unwrap(), "web01.example.org");
    let refusal = one("@web", groups).unwrap_err();
    assert_eq!(refusal.code, 64);
    assert!(refusal.message.contains("gives 3 hosts") && refusal.message.contains("podssh each"), "{refusal}");
    let refusal = expand("@nope", groups).unwrap_err();
    assert!(refusal.message.contains("which has all, db, one, web"), "{refusal}");
}

#[test]
fn a_cycle_of_groups_is_the_fault_of_the_file() {
    let err = crate::settings::parse("[groups]\na b @c\nc @a\n", "f", None).unwrap_err();
    assert!(err.starts_with("f:2: the groups a, c, a make a cycle"), "{err}");
    let err = crate::settings::parse("[groups]\nme @me\n", "f", None).unwrap_err();
    assert!(err.starts_with("f:2: the groups me, me make a cycle"), "{err}");
    for (text, says) in [
        ("[groups]\nweb a\nweb b\n", "f:3: the group web is given at f:2 already"),
        ("[groups]\n-x a\n", "f:2: -x is not the name of a group"),
        ("[groups]\nRelayHost a\n", "f:2: RelayHost is a setting"),
        ("[hosts]\n", "f:1: [hosts] is not a table"),
        ("[groups]\nweb h{3..1}\n", "f:2: the group web: "),
        ("[groups]\nweb @nope\n", "f:2: the group web: @nope: no group of that name"),
    ] {
        let err = crate::settings::parse(text, "f", None).unwrap_err();
        assert!(err.starts_with(says), "{text:?}: {err}");
    }
    // A table that was not read through the file: the fault is still the
    // file's, 78.
    let mut groups = Groups::new();
    groups.insert("a".into(), Value { text: "@a".into(), at: "f:9".into() });
    let refusal = expand("@a", &groups).unwrap_err();
    assert_eq!(refusal.code, 78, "{refusal}");
}
