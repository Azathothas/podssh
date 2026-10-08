//! `podssh ssh`'s command line, parsed the way OpenSSH parses it, and
//! resolved into a connection without touching the network.

use std::path::PathBuf;

use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::resolve::{parse_hop, resolve, Env, Transport};
use podssh_cli::tree::{parse, Parsed};
use podssh_ssh::{Agent, LogLevel, Method, Request, RequestTty, StrictHostKeyChecking};

fn ssh(words: &[&str]) -> SshArgs {
    let argv: Vec<std::ffi::OsString> = std::iter::once("ssh").chain(words.iter().copied()).map(Into::into).collect();
    match parse(argv) {
        Parsed::Command { verb: "ssh", ssh: Some(args), refused, .. } => {
            assert!(refused.is_empty(), "{words:?} was refused: {refused:?}");
            *args
        }
        other => panic!("{words:?} did not parse as ssh: {other:?}"),
    }
}

fn env() -> Env {
    Env { home: Some(PathBuf::from("/home/u")), user: Some("envuser".into()), relay: None, ssl_cert_file: None }
}

#[test]
fn the_first_word_after_the_host_starts_the_command_and_keeps_its_flags() {
    let a = ssh(&["host", "ls", "-la", "/tmp"]);
    assert_eq!(a.destination.as_deref(), Some("host"));
    assert_eq!(a.command, vec!["ls", "-la", "/tmp"]);
    let a = ssh(&["host", "--", "echo", "-n", "x"]);
    assert_eq!(a.command, vec!["echo", "-n", "x"]);
}

#[test]
fn options_may_follow_the_destination_as_in_openssh() {
    let a = ssh(&["host", "-p", "2222", "-l", "bob", "uname", "-a"]);
    assert_eq!(a.port.as_deref(), Some("2222"));
    assert_eq!(a.login.as_deref(), Some("bob"));
    assert_eq!(a.command, vec!["uname", "-a"]);
}

#[test]
fn attached_values_counts_and_repeats() {
    let a = ssh(&["-p22", "-oBatchMode=yes", "-o", "Port=7", "-tt", "-vvv", "-i", "a", "-i", "b", "host"]);
    assert_eq!(a.port.as_deref(), Some("22"));
    assert_eq!(a.options, vec!["BatchMode=yes", "Port=7"]);
    assert_eq!(a.tty, 2);
    assert_eq!(a.verbose, 3);
    assert_eq!(a.identity_files, vec!["a", "b"]);
    // A repeated switch is allowed, as OpenSSH allows it.
    let a = ssh(&["-T", "-T", "-n", "host"]);
    assert!(a.no_tty && a.stdin_null);
}

#[test]
fn the_long_spellings_of_options_become_options() {
    let a = ssh(&["--StrictHostKeyChecking", "accept-new", "--ConnectTimeout", "5", "host"]);
    assert_eq!(a.long_options, vec!["StrictHostKeyChecking=accept-new", "ConnectTimeout=5"]);
    let r = resolve(&a, &env()).unwrap();
    assert_eq!(r.options.strict_host_key_checking, StrictHostKeyChecking::AcceptNew);
    assert_eq!(r.options.connect_timeout.as_secs(), 5);
}

#[test]
fn destinations_in_every_form() {
    let h = parse_hop("alice@example.org").unwrap();
    assert_eq!((h.user.as_deref(), h.host.as_str(), h.port), (Some("alice"), "example.org", 22));
    let h = parse_hop("ssh://bob@example.org:2222").unwrap();
    assert_eq!((h.user.as_deref(), h.host.as_str(), h.port), (Some("bob"), "example.org", 2222));
    let h = parse_hop("example.org:2200").unwrap();
    assert_eq!((h.host.as_str(), h.port), ("example.org", 2200));
    let h = parse_hop("[2001:db8::1]:2222").unwrap();
    assert_eq!((h.host.as_str(), h.port), ("2001:db8::1", 2222));
    let h = parse_hop("2001:db8::1").unwrap();
    assert_eq!((h.host.as_str(), h.port), ("2001:db8::1", 22), "an unbracketed IPv6 literal has no port");
    let h = parse_hop("user@domain@host").unwrap();
    assert_eq!((h.user.as_deref(), h.host.as_str()), (Some("user@domain"), "host"), "the last @ splits");
    for bad in ["@host", "host:0", "host:x", "[::1", "user@"] {
        assert!(parse_hop(bad).is_err(), "{bad:?} must be refused");
    }
}

#[test]
fn the_user_comes_from_l_then_the_option_then_the_destination_then_the_environment() {
    let r = resolve(&ssh(&["-l", "l", "-o", "User=o", "d@host"]), &env()).unwrap();
    assert_eq!(r.options.user, "l");
    let r = resolve(&ssh(&["-o", "User=o", "d@host"]), &env()).unwrap();
    assert_eq!(r.options.user, "o");
    let r = resolve(&ssh(&["d@host"]), &env()).unwrap();
    assert_eq!(r.options.user, "d");
    let r = resolve(&ssh(&["host"]), &env()).unwrap();
    assert_eq!(r.options.user, "envuser");
    let no_user = Env { user: None, ..env() };
    let err = resolve(&ssh(&["host"]), &no_user).unwrap_err();
    assert!(err.contains("user"), "{err}");
}

#[test]
fn defaults_follow_openssh_and_keepalives_are_on() {
    let r = resolve(&ssh(&["host"]), &env()).unwrap();
    let o = &r.options;
    assert_eq!(o.destination.port, 22);
    assert_eq!(o.strict_host_key_checking, StrictHostKeyChecking::Ask);
    assert_eq!(o.request, Request::Shell);
    assert_eq!(o.request_tty, RequestTty::Auto);
    assert_eq!(o.escape_char, Some(b'~'));
    assert_eq!(o.methods, vec![Method::PublicKey, Method::KeyboardInteractive, Method::Password]);
    assert_eq!(o.agent, Agent::FromEnvironment);
    assert_eq!(o.keepalive_interval.map(|d| d.as_secs()), Some(60));
    assert_eq!(o.log_level, LogLevel::Info);
    let home = PathBuf::from("/home/u/.ssh");
    assert_eq!(o.identity_files, vec![home.join("id_rsa"), home.join("id_ecdsa"), home.join("id_ed25519")]);
    assert_eq!(o.user_known_hosts[0], home.join("known_hosts"));
    assert!(matches!(r.transport, Transport::Relay { family: None, .. }));
}

#[test]
fn an_explicit_identity_replaces_the_defaults() {
    let r = resolve(&ssh(&["-i", "~/k", "-o", "IdentityFile=%d/x-%r", "bob@host"]), &env()).unwrap();
    assert_eq!(r.options.identity_files, vec![PathBuf::from("/home/u").join("k"), PathBuf::from("/home/u/x-bob")]);
}

#[test]
fn the_request_follows_the_flags() {
    let r = |w: &[&str]| resolve(&ssh(w), &env()).map(|r| (r.options.request, r.options.request_tty));
    assert_eq!(r(&["host", "exit", "3"]).unwrap().0, Request::Exec("exit 3".into()));
    assert_eq!(r(&["-N", "host"]).unwrap(), (Request::Nothing, RequestTty::No));
    assert_eq!(r(&["-s", "host", "sftp"]).unwrap().0, Request::Subsystem("sftp".into()));
    assert!(r(&["-s", "host"]).is_err(), "-s needs a subsystem name");
    assert_eq!(
        r(&["-W", "db:5432", "host"]).unwrap(),
        (Request::StdioForward { host: "db".into(), port: 5432 }, RequestTty::No)
    );
    assert!(r(&["-W", "db", "host"]).is_ok_and(|(req, _)| req == Request::StdioForward { host: "db".into(), port: 22 }));
    assert!(r(&["-W", "db:5432", "host", "ls"]).is_err());
    assert_eq!(r(&["-t", "host"]).unwrap().1, RequestTty::Yes);
    assert_eq!(r(&["-tt", "host"]).unwrap().1, RequestTty::Force);
    assert_eq!(r(&["-T", "host"]).unwrap().1, RequestTty::No);
    assert_eq!(r(&["-o", "RemoteCommand=uptime", "host"]).unwrap().0, Request::Exec("uptime".into()));
}

#[test]
fn jump_hosts_transport_and_family() {
    let r = resolve(&ssh(&["-J", "a@j1,j2:2222", "host"]), &env()).unwrap();
    assert_eq!(r.options.jump.len(), 2);
    assert_eq!(r.options.jump[1].port, 2222);
    let r = resolve(&ssh(&["-4", "host"]), &env()).unwrap();
    assert!(matches!(r.transport, Transport::Relay { family: Some(4), .. }));
    let r = resolve(&ssh(&["--direct", "host"]), &env()).unwrap();
    assert_eq!(r.transport, Transport::Direct);
    assert!(resolve(&ssh(&["--direct", "-6", "host"]), &env()).is_err());
    assert!(resolve(&ssh(&["-4", "-6", "host"]), &env()).is_err());
    let err = resolve(&ssh(&["--relay-host", "relay.example:8443", "invalid!host"]), &env()).unwrap_err();
    assert!(err.contains("invalid!host"), "{err}");
}

#[test]
fn a_config_file_is_refused_unless_it_is_none() {
    assert!(resolve(&ssh(&["-F", "none", "host"]), &env()).is_ok());
    let err = resolve(&ssh(&["-F", "/etc/ssh/ssh_config", "host"]), &env()).unwrap_err();
    assert!(err.contains("-o"), "the refusal names the alternative: {err}");
}

#[test]
fn quiet_and_verbose_set_the_log_level() {
    let level = |w: &[&str]| resolve(&ssh(w), &env()).unwrap().options.log_level;
    assert_eq!(level(&["-q", "host"]), LogLevel::Quiet);
    assert_eq!(level(&["-vv", "host"]), LogLevel::Debug2);
    assert_eq!(level(&["-o", "LogLevel=ERROR", "host"]), LogLevel::Error);
}

#[test]
fn keepalives_off_over_the_relay_earn_a_note() {
    let r = resolve(&ssh(&["-o", "ServerAliveInterval=0", "host"]), &env()).unwrap();
    assert_eq!(r.options.keepalive_interval, None);
    assert!(r.notes.iter().any(|n| n.contains("180")), "{:?}", r.notes);
}
