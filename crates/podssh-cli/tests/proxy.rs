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

/// Run the binary with `vars` and no other relay or proxy setting; the code
/// and stderr. A refusal comes before any network use, so 30 s is plenty.
fn podssh_with(argv: &[&str], vars: &[(&str, &str)]) -> (i32, String) {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(argv).env("PODSSH_OFFLINE", "1");
    // The ssh_config of the machine that runs the test must not change it.
    cmd.env("PODSSH_SSH_CONFIG", "none");
    for name in [
        "PODSSH_RELAY",
        "PODSSH_RELAY_ADDR",
        "PODSSH_RELAY_TOKEN",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        cmd.env_remove(name);
    }
    cmd.envs(vars.iter().copied());
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("podssh runs");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for podssh") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{argv:?} with {vars:?} did not end within 30 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut err = String::new();
    child.stderr.take().expect("stderr").read_to_string(&mut err).expect("stderr is text");
    (status.code().unwrap_or(-1), err)
}

/// A bad PODSSH_RELAY or PODSSH_RELAY_ADDR is a configuration error (78),
/// and the message names the variable; the command line is right. The same
/// value as a flag stays a usage error (64).
#[test]
fn a_bad_variable_is_a_configuration_error() {
    let commands: [&[&str]; 3] = [&["proxy", "example.org", "22"], &["ssh", "-l", "u", "host", "true"], &["doctor"]];
    for (var, value) in [("PODSSH_RELAY", "bad host!"), ("PODSSH_RELAY_ADDR", "nonsense")] {
        for argv in commands {
            let (rc, err) = podssh_with(argv, &[(var, value)]);
            assert_eq!(rc, 78, "{var} {argv:?}: {err}");
            assert!(err.contains(&format!("{var}: ")), "{var} {argv:?}: {err}");
        }
    }
    for flag in [["--relay-host", "bad host!"], ["--relay-addr", "nonsense"]] {
        let argv = ["proxy", flag[0], flag[1], "example.org", "22"];
        let (rc, err) = podssh_with(&argv, &[]);
        assert_eq!(rc, 64, "{argv:?}: {err}");
        assert!(err.contains(&format!("{}: ", flag[0])), "{argv:?}: {err}");
    }
}
