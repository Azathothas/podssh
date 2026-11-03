//! The tests of what the role knows of IPv6 out of its host (T-253): the
//! table of routes read in the kernel's form, the faults of a dial that name
//! no route, and the plan of a target with each.

use super::*;

/// A dual-stack host's table, in the form of `/proc/net/ipv6_route`: the
/// loopback, its own prefix (of the documentation range), link-local, a
/// default route by a router's link-local address (up, gateway, default, from
/// a router's advertisement), and multicast.
const DUAL: &str = "\
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001       lo
20010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003     eth0
ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000004 00000000 00000001     eth0
";

/// A host with link-local alone: the kernel's null route, which rejects, is
/// the one route of `::/0`.
const LINK_LOCAL: &str = "\
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
";

fn v6(text: &str) -> Ipv6Addr {
    text.parse().unwrap()
}

fn at(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

#[test]
fn the_table_carries_what_its_longest_usable_route_covers() {
    let dual = routes(DUAL);
    assert_eq!(dual.len(), 5, "{dual:?}");
    for routed in ["2001:db8:2::5", "2606:4700::1111", "2001:db8:1::7", "fe80::9"] {
        assert!(carries(&dual, v6(routed)), "{routed}");
    }
    let alone = routes(LINK_LOCAL);
    assert!(!carries(&alone, ANY_PUBLIC), "the null route rejects");
    assert!(carries(&alone, v6("fe80::9")), "its own link");
    // An unreachable default that its owner set: up, and rejecting.
    let refused = routes(
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
         00000000000000000000000000000000 00000400 00000001 00000000 00000201 lo\n",
    );
    assert!(!carries(&refused, ANY_PUBLIC));
    // The null route beside a real default: the real one carries.
    let both = routes(&format!("{LINK_LOCAL}{DUAL}"));
    assert!(carries(&both, ANY_PUBLIC));
    assert!(routes("not a table\n00 zz\n").is_empty(), "a line of another form is passed over");
}

#[test]
fn a_fault_of_no_route_is_named_and_kept_and_a_refusal_is_not() {
    use std::io::{Error, ErrorKind};
    for kind in [ErrorKind::NetworkUnreachable, ErrorKind::NetworkDown, ErrorKind::AddrNotAvailable] {
        assert!(unrouted(&Error::from(kind)), "{kind:?}");
    }
    assert!(unrouted(&Error::from_raw_os_error(EAFNOSUPPORT)), "no address of the family");
    for kind in [ErrorKind::ConnectionRefused, ErrorKind::TimedOut, ErrorKind::HostUnreachable] {
        assert!(!unrouted(&Error::from(kind)), "{kind:?}: the target's, or a router's on the way");
    }
    // A host with no table: the dials tell.
    let out = Ipv6Out::reading(std::path::PathBuf::from("/nonexistent/podssh-t253-no-routes"));
    assert_eq!(out.routes(v6("2001:db8::7")), (None, "nothing before a dial"));
    let refused = out.missed(&at("[2001:db8::7]:22"), &Error::from(ErrorKind::ConnectionRefused));
    assert!(!refused.contains(NO_IPV6_ROUTE), "{refused}");
    assert_eq!(out.routes(v6("2001:db8::7")).0, None, "a refusal is the target's");
    let said = out.missed(&at("[2001:db8::7]:22"), &Error::from(ErrorKind::NetworkUnreachable));
    assert!(said.starts_with(NO_IPV6_ROUTE) && said.contains("[2001:db8::7]:22"), "{said}");
    assert_eq!(out.routes(v6("2001:db8::8")), (Some(false), "a dial that met no route"));
    // The loopback is no route out, met or not.
    let local = out.missed(&at("[::1]:22"), &Error::from(ErrorKind::NetworkUnreachable));
    assert!(!local.contains(NO_IPV6_ROUTE), "{local}");
    let other = Ipv6Out::reading(std::path::PathBuf::from("/nonexistent/podssh-t253-no-routes"));
    other.reached(&at("[2001:db8::7]:22"));
    assert_eq!(other.routes(v6("2001:db8::9")), (Some(true), "a dial that connected"));
}

#[test]
fn a_table_in_a_file_is_read_and_wins_over_a_dial() {
    let dir = std::env::temp_dir().join(format!("podssh-t253-routes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("ipv6_route");
    std::fs::write(&file, LINK_LOCAL).unwrap();
    let out = Ipv6Out::reading(file.clone());
    assert_eq!(out.routes(ANY_PUBLIC), (Some(false), "the routes of this host"));
    out.reached(&at("[2001:db8::7]:22"));
    assert_eq!(out.routes(ANY_PUBLIC).0, Some(false), "the table wins");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_plan_keeps_what_this_host_can_route_and_refuses_when_nothing_is_left() {
    let none = Ipv6Out::none();
    let both = Plan::Addresses(vec![at("[2001:db8::7]:22"), at("192.0.2.7:22")]);
    assert_eq!(none.keep(both, "both.example", &Egress::Direct), Ok(Plan::Addresses(vec![at("192.0.2.7:22")])));
    let six = Plan::Addresses(vec![at("[2001:db8::7]:22")]);
    assert_eq!(none.keep(six.clone(), "2001:db8::7", &Egress::Direct), Err(NO_IPV6_ROUTE.to_string()));
    // The loopback, and IPv4 written as IPv6, are this host's own.
    for own in ["[::1]:22", "[::ffff:192.0.2.7]:22"] {
        let plan = Plan::Addresses(vec![at(own)]);
        assert_eq!(none.keep(plan.clone(), "own.example", &Egress::Direct), Ok(plan), "{own}");
    }
    // A routed host keeps each; a name for the proxy is the proxy's.
    assert_eq!(Ipv6Out::routed().keep(six.clone(), "2001:db8::7", &Egress::Direct), Ok(six.clone()));
    let named = Plan::Name("target.invalid".into(), 22);
    assert_eq!(none.keep(named.clone(), "target.invalid", &Egress::Direct), Ok(named));
    // Through the host's proxy, its way out decides, and the role keeps the
    // address; NO_PROXY's goes direct, and is refused.
    let vars = [("HTTPS_PROXY", "http://proxy.test:3128"), ("NO_PROXY", "skip.test")];
    let proxied = Egress::from_vars(|n| vars.iter().find(|(v, _)| *v == n).map(|(_, x)| x.to_string())).unwrap();
    assert_eq!(none.keep(six.clone(), "2001:db8::7", &proxied), Ok(six.clone()));
    assert_eq!(none.keep(six, "skip.test", &proxied), Err(NO_IPV6_ROUTE.to_string()));
    // The word of /relays.json.
    assert_eq!(none.doc(&Egress::Direct), json!({ "ipv6": false, "known_by": "given" }));
    assert_eq!(none.doc(&proxied)["ipv6"], Value::Null);
}
