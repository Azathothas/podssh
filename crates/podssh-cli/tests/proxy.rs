//! `podssh proxy`: what it parses, and how it refuses bad input. The relay
//! path itself is exercised by `proxy_live.rs` (network, ignored by default).

use podssh_cli::dispatch::{run, Streams};
use podssh_cli::proxy::parse_target;
use podssh_cli::tree::{parse, Parsed};

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn run_case(argv: &[&str]) -> (i32, String, String) {
    let p = parse(args(argv));
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    (rc, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

#[test]
fn the_positionals_and_options_reach_the_verb() {
    let p = parse(args(&["proxy", "--relay-host", "relay.example:8443", "--ca-file", "ca.pem", "host.example", "22"]));
    assert_eq!(
        p,
        Parsed::Proxy {
            target: Some("host.example".into()),
            port: Some("22".into()),
            relay_host: Some("relay.example:8443".into()),
            relay_addr: None,
            ca_file: Some("ca.pem".into()),
            refused: vec![],
        }
    );
}

#[test]
fn host_and_port_may_come_as_one_argument() {
    assert_eq!(parse_target(Some("host.example:2222"), None).unwrap(), ("host.example".into(), 2222));
    assert_eq!(parse_target(Some("host.example"), Some("22")).unwrap(), ("host.example".into(), 22));
}

#[test]
fn bad_targets_are_refused_before_anything_is_dialled() {
    assert!(parse_target(None, None).is_err());
    assert!(parse_target(Some("host.example"), None).is_err(), "no port anywhere");
    for port in ["0", "65536", "ssh", "-1"] {
        assert!(parse_target(Some("host.example"), Some(port)).is_err(), "port {port:?}");
    }
    for host in ["a/b", "a b", "-oProxyCommand=x", "a?b", "[host.example]", "[::1"] {
        assert!(parse_target(Some(host), Some("22")).is_err(), "host {host:?}");
    }
}

/// OpenSSH gives `%h` as a bare IPv6 address; brackets are accepted too,
/// and one word needs them before a port (GitHub #2).
#[test]
fn ipv6_forms_of_the_target() {
    let v6 = |host: &str, port: Option<&str>| parse_target(Some(host), port);
    assert_eq!(v6("2001:db8::1", Some("22")).unwrap(), ("2001:db8::1".into(), 22));
    assert_eq!(v6("[2001:db8::1]", Some("22")).unwrap(), ("2001:db8::1".into(), 22));
    assert_eq!(v6("[2001:db8::1]:8079", None).unwrap(), ("2001:db8::1".into(), 8079));
    assert_eq!(v6("::1", Some("22")).unwrap(), ("::1".into(), 22));
    let bad: [(&str, Option<&str>); 6] = [
        ("2001:db8::1:22", None),
        ("[2001:db8::1]", None),
        ("[2001:db8::1", Some("22")),
        ("[host.example]", Some("22")),
        ("fe80::1%eth0", Some("22")),
        ("[2001:db8::1]x", None),
    ];
    for (host, port) in bad {
        assert!(v6(host, port).is_err(), "{host:?} {port:?}");
    }
    let err = v6("2001:db8::1:22", None).unwrap_err();
    assert!(err.contains("brackets"), "the refusal names the remedy: {err}");
}

#[test]
fn usage_errors_exit_64_with_nothing_on_stdout() {
    for argv in [&["proxy"][..], &["proxy", "a/b", "22"][..], &["proxy", "host.example", "0"][..]] {
        let (rc, out, err) = run_case(argv);
        assert_eq!(rc, 64, "{argv:?}: {err}");
        assert!(out.is_empty(), "{argv:?} wrote to stdout");
        assert!(err.contains("podssh proxy:"), "{argv:?}: {err}");
    }
}

#[test]
fn a_bad_relay_override_is_a_usage_error() {
    let (rc, out, err) = run_case(&["proxy", "--relay-host", "not a host", "host.example", "22"]);
    assert_eq!(rc, 64, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("bad relay"), "{err}");
}

#[test]
fn jsonl_is_still_refused_because_stdout_is_the_byte_stream() {
    let (rc, out, _) = run_case(&["proxy", "--jsonl", "host.example", "22"]);
    assert_eq!(rc, 64);
    assert!(out.is_empty());
}

#[test]
fn the_help_lists_the_relay_and_trust_options() {
    let (rc, out, _) = run_case(&["proxy", "--help"]);
    assert_eq!(rc, 0);
    for flag in ["--relay-host HOST", "--ca-file FILE"] {
        assert!(out.contains(flag), "missing {flag} in:\n{out}");
    }
    // Every description sits beside its flag with at least two spaces.
    for line in out.lines().filter(|l| l.trim_start().starts_with("--") && !l.contains("--help")) {
        assert!(line.contains("  "), "flag and description run together: {line:?}");
    }
}
