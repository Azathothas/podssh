//! The plan of `doctor --exit` and the words of a refusal (T-458).

use super::*;

fn refused(kind: Kind, line: &str) -> Refused {
    Refused { code: 69, line: line.into(), kind }
}

#[test]
fn a_target_reads_as_host_and_port_an_ipv6_address_in_brackets() {
    assert_eq!(target("github.com:22").unwrap(), ("github.com".into(), 22));
    assert_eq!(target("[2001:db8::1]:443").unwrap(), ("2001:db8::1".into(), 443));
    for bad in ["github.com", "h:0", "h:x", ":22", "2001:db8::1:22", "[::1]", "h/x:22", "h :22"] {
        assert!(target(bad).is_err(), "{bad}");
    }
}

/// A flag of the exit with no `--exit` is a usage error; with none of them,
/// there is no plan; the default target is GitHub's SSH port.
#[test]
fn the_flags_of_the_exit_go_with_exit_name() {
    let none = Flags::default();
    assert!(asked(&none, None).unwrap().is_none());
    for (flags, flag) in [
        (Flags { target: Some("h:1".into()), ..Flags::default() }, "--exit-target"),
        (Flags { client_key: Some("k".into()), ..Flags::default() }, "--client-key"),
    ] {
        let refusal = asked(&flags, None).err().unwrap();
        assert_eq!((refusal.code, refusal.message), (64, format!("{flag} is for --exit NAME")));
    }
    let plan = asked(&Flags { name: Some("gw".into()), ..Flags::default() }, Some("ca.pem")).unwrap().unwrap();
    assert_eq!((plan.host.as_str(), plan.port, plan.to.name.as_str()), (FORWARD_HOST, 22, "gw"));
    assert_eq!(plan.to.ca_file.as_deref(), Some("ca.pem"));
    let flags = Flags { name: Some("gw".into()), target: Some("h:x".into()), ..Flags::default() };
    let refusal = asked(&flags, None).err().unwrap();
    assert!(refusal.code == 64 && refusal.message.starts_with("--exit-target h:x: "), "{}", refusal.message);
}

/// Each refusal is named by whose words it carries: the road's, the
/// channel's, the net's policy, the exit's check of an address, its dial.
#[test]
fn a_refusal_says_whose_it_is() {
    let road = refused(Kind::Failed, "the relay refused the pair's connect token (403)");
    assert!(whose(&road).starts_with("the road"));
    let key = "the node refused this client's key ab: not in its allowlist, nor a member that its net's policy lets";
    assert!(whose(&refused(Kind::NotAllowed, key)).starts_with("the channel"));
    let policy = "the node refused: no rule of the net home's policy (serial 6) lets b reach 127.0.0.1";
    assert_eq!(whose(&refused(Kind::NotAllowed, policy)), "the net's policy");
    let address = "the node refused: 10.0.0.1:9 resolves to 10.0.0.1, which is not a public address, and no range";
    assert_eq!(whose(&refused(Kind::NotAllowed, address)), "the exit's check of the address");
    let gone = "the node refused: this node is in no net now, so its exit lets nobody out";
    assert_eq!(whose(&refused(Kind::NotAllowed, gone)), "the exit");
    let dial = refused(Kind::Unreachable, "the node could not reach its target: h:22: connection refused");
    assert!(whose(&dial).starts_with("the exit's dial"));
    assert_eq!(shown(b"SSH-2.0-OpenSSH_9.6\r\n"), "SSH-2.0-OpenSSH_9.6");
    assert!(shown(&[b'x'; 200]).ends_with("...") && shown(&[b'x'; 200]).len() == 83);
}
