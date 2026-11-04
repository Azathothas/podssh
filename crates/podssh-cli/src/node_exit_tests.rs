//! The exit's checks with no network (T-431): the flags, the ranges of
//! `--routes`, and the check of each address of a name. No test here passes
//! each check of `check`, which would make this process an exit for the
//! other tests of the library.

use std::net::SocketAddr;

use super::*;

fn at(list: &[&str]) -> Vec<SocketAddr> {
    list.iter().map(|text| text.parse().unwrap()).collect()
}

/// A net that lets each address in.
fn open_net(_: std::net::IpAddr, _: bool) -> Verdict {
    Verdict::Member("a".into())
}

#[test]
fn the_exit_s_flags_go_with_a_road_of_the_channel() {
    let exit = NodeArgs { name: Some("lab".into()), exit: true, ..NodeArgs::default() };
    let routes = NodeArgs { routes: Some("10.0.0.0/8".into()), ..NodeArgs::default() };
    assert!(check(&routes).unwrap_err().message.contains("give --exit too"));
    for (args, words) in [
        (NodeArgs { no_e2e: true, ..exit.clone() }, "--no-e2e"),
        (NodeArgs { temporary: Some("k".into()), ..exit.clone() }, "--temporary"),
        (NodeArgs { targets: vec!["dns=udp:127.0.0.1:53".into()], ..exit.clone() }, "udp:"),
        (NodeArgs { routes: Some("10.0.0.0/8,nope".into()), ..exit.clone() }, "\"nope\" is not a range"),
        (NodeArgs { routes: Some("10.0.0.0/33".into()), ..exit.clone() }, "is not a range"),
    ] {
        let refusal = check(&args).unwrap_err();
        assert!(refusal.code == 64 && refusal.message.contains(words), "{words}: {}", refusal.message);
    }
    assert!(!asked(), "a refused plan is no exit");
    assert!(check(&NodeArgs::default()).is_ok());
}

#[test]
fn the_ranges_of_routes_are_those_of_the_policy() {
    let read = ranges("10.0.0.0/8, 127.0.0.1,fd00::/8").unwrap();
    let words: Vec<&str> = read.iter().map(|(w, _)| w.as_str()).collect();
    assert_eq!(words, ["10.0.0.0/8", "127.0.0.1", "fd00::/8"]);
    assert!(read[0].1.contains("10.9.8.7".parse().unwrap()) && !read[0].1.contains("11.0.0.1".parse().unwrap()));
    assert!(read[1].1.contains("127.0.0.1".parse().unwrap()) && !read[1].1.contains("127.0.0.2".parse().unwrap()));
    assert!(ranges("10.0.0.0/8,").is_err(), "an empty range");
}

#[test]
fn each_address_is_public_or_in_a_range_and_one_that_is_not_refuses_the_name() {
    let none: Vec<Range> = Vec::new();
    let found = checked("github.com:22", at(&["140.82.112.3:22", "[2606:4700::1111]:22"]), &none, &[], &open_net);
    assert_eq!(found.unwrap().len(), 2);
    for (list, inside) in [
        (vec!["127.0.0.1:22"], "127.0.0.1"),
        (vec!["10.1.2.3:22"], "10.1.2.3"),
        (vec!["169.254.169.254:80"], "169.254.169.254"),
        (vec!["[::1]:22"], "::1"),
        (vec!["[::ffff:10.0.0.1]:22"], "::ffff:10.0.0.1"),
        // A name with one private address among public ones is refused
        // whole, as it could be steered to it.
        (vec!["140.82.112.3:22", "10.0.0.1:22"], "10.0.0.1"),
    ] {
        match checked("name.example:22", at(&list), &none, &[], &open_net) {
            Err(NodeRefusal::Other(why)) => {
                assert!(why.contains(&format!("resolves to {inside}, which is not a public address")), "{why}")
            }
            other => panic!("{list:?}: {other:?}"),
        }
    }
    // A range of --routes lets its private addresses through, and no other.
    let ranges = vec![Range::parse("127.0.0.1").unwrap(), Range::parse("10.0.0.0/8").unwrap()];
    assert_eq!(checked("x:22", at(&["127.0.0.1:22", "10.9.9.9:22"]), &ranges, &[], &open_net).unwrap().len(), 2);
    assert!(checked("x:22", at(&["127.0.0.2:22"]), &ranges, &[], &open_net).is_err());
    // The host's own address and the loopback need a range that names them
    // alone (T-432): 10.0.0.0/8 holds the host's 10.9.9.1, and does not let it.
    let own: Vec<std::net::IpAddr> = vec!["10.9.9.1".parse().unwrap()];
    match checked("x:22", at(&["10.9.9.1:22"]), &ranges, &own, &open_net) {
        Err(NodeRefusal::Other(why)) => assert!(why.contains("an address of the exit's host"), "{why}"),
        other => panic!("the host's own address was let through a wide range: {other:?}"),
    }
    assert!(checked("x:22", at(&["10.9.9.2:22"]), &ranges, &own, &open_net).is_ok(), "another host of the range");
    let alone = vec![Range::parse("10.0.0.0/8").unwrap(), Range::parse("10.9.9.1/32").unwrap()];
    assert!(checked("x:22", at(&["10.9.9.1:22"]), &alone, &own, &open_net).is_ok(), "named alone");
    let loopback = vec![Range::parse("127.0.0.0/8").unwrap()];
    match checked("x:22", at(&["127.0.0.1:22"]), &loopback, &[], &open_net) {
        Err(NodeRefusal::Other(why)) => assert!(why.contains("a loopback address of the exit's host"), "{why}"),
        other => panic!("{other:?}"),
    }
    // A public address of the host itself needs it too.
    let public_own: Vec<std::net::IpAddr> = vec!["140.82.112.3".parse().unwrap()];
    assert!(checked("x:22", at(&["140.82.112.3:22"]), &none, &public_own, &open_net).is_err());
    assert!(matches!(checked("x:22", Vec::new(), &ranges, &[], &open_net), Err(NodeRefusal::NoTarget(_))));
}

#[test]
fn the_net_decides_for_each_address_with_its_words() {
    let none: Vec<Range> = Vec::new();
    let seen = std::cell::RefCell::new(Vec::new());
    let refuse = |addr: std::net::IpAddr, public: bool| {
        seen.borrow_mut().push((addr, public));
        Verdict::Refused("no rule of the net home's policy (serial 5) lets b reach exit:lab".into())
    };
    match checked("github.com:22", at(&["140.82.112.3:22"]), &none, &[], &refuse) {
        Err(NodeRefusal::Other(why)) => assert!(why.contains("lets b reach exit:lab"), "{why}"),
        other => panic!("{other:?}"),
    }
    let egress: (std::net::IpAddr, bool) = ("140.82.112.3".parse().unwrap(), true);
    assert_eq!(*seen.borrow(), vec![egress]);
    // A private address of a range is asked as an address, not as the egress.
    let ranges = vec![Range::parse("10.0.0.0/8").unwrap()];
    let _ = checked("db:5432", at(&["10.1.2.3:5432"]), &ranges, &[], &refuse);
    assert_eq!(seen.borrow()[1], ("10.1.2.3".parse().unwrap(), false));
    let outside = |_: std::net::IpAddr, _: bool| Verdict::Outside;
    let gone = checked("a:1", at(&["1.1.1.1:1"]), &none, &[], &outside);
    assert!(matches!(&gone, Err(NodeRefusal::Other(w)) if w.contains("in no net")), "{gone:?}");
}

#[test]
fn an_exit_with_no_target_has_a_stand_in_that_names_no_host() {
    let stand_in = first(&[]);
    assert!(stand_in.host.is_empty() && stand_in.name.is_none());
    let one = Route { name: None, host: "127.0.0.1".into(), port: 22 };
    assert_eq!(first(std::slice::from_ref(&one)), one);
}

#[test]
fn a_node_says_when_the_net_lists_other_routes_than_its_own() {
    let mine = ranges("10.1.0.0/16,fd00::/8").unwrap();
    assert!(listed_apart(&mine, &["fd00::/8".into(), "10.1.0.0/16".into()]).is_none(), "the same, in any order");
    let note = listed_apart(&mine, &["10.1.0.0/24".into()]).unwrap();
    assert!(
        note.contains("lists the routes 10.1.0.0/24") && note.contains("--routes gives 10.1.0.0/16, fd00::/8"),
        "{note}"
    );
    let none = listed_apart(&mine, &[]).unwrap();
    assert!(none.contains("lists the routes none"), "{none}");
    assert!(listed_apart(&[], &[]).is_none(), "an exit with no range, listed with none");
}
