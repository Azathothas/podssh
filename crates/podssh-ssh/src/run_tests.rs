use russh::SshId;

use super::*;

const DROP: &str = "railway.new: the connection closed unexpectedly";

/// The first line from each kind of relay end, from a server disconnect
/// and from a bare error (GitHub #17).
#[test]
fn first_line_names_the_hop_that_broke() {
    let lost = RelayEnd::Closed { code: Some(1011), reason: "write failed: Network connection lost.".into() };
    let lines = failure_lines(DROP, Some(&lost), "railway.new:22");
    assert_eq!(
        lines[0],
        "railway.new: the relay lost its connection to railway.new:22 (relay close 1011: write failed: Network connection lost.)"
    );
    assert!(lines[1].contains("--relay-host"), "{lines:?}");
    let cap = RelayEnd::Closed { code: Some(1009), reason: "session byte cap".into() };
    let lines = failure_lines(DROP, Some(&cap), "railway.new:22");
    assert!(lines[0].contains("at one of its limits (relay close 1009: session byte cap)"), "{lines:?}");
    assert!(lines[1].contains("64 MiB"), "{lines:?}");
    let gone = RelayEnd::Failed(podssh_ws::SessionError::Idle("the relay sent nothing for 40 s".into()));
    let lines = failure_lines(DROP, Some(&gone), "railway.new:22");
    assert!(lines[0].starts_with("railway.new: the connection between podssh and the relay broke"), "{lines:?}");
    // A normal close of the relay: the message, then the relay's words.
    let done = RelayEnd::Closed { code: Some(1000), reason: "target closed".into() };
    let server = "railway.new: the server ended the connection: too many sessions (TooManyConnections)";
    let lines = failure_lines(server, Some(&done), "railway.new:22");
    assert_eq!(lines[0], server);
    assert!(lines[1].contains("target closed"), "{lines:?}");
    // No relay (--direct): the message as it is.
    assert_eq!(failure_lines(DROP, None, "railway.new:22"), vec![DROP.to_string()]);
}

/// Each hop files its key under its own name and port, and the destination
/// alone takes `HostKeyAlias`, as it is, with no port, as OpenSSH files it
/// (T-030).
#[test]
fn hop_key_name_is_each_hops_own() {
    let hop = |host: &str, port| Hop { user: None, host: host.into(), port, tls: false };
    let mut opts = Options::new(hop("dest.example", 2203), "u".into());
    let dest = opts.destination.clone();
    assert_eq!(hop_key_name(&hop("jump.example", 22), false, &opts), "jump.example");
    assert_eq!(hop_key_name(&hop("jump.example", 2222), false, &opts), "[jump.example]:2222");
    assert_eq!(hop_key_name(&dest, true, &opts), "[dest.example]:2203");
    opts.host_key_alias = Some("alias.example".into());
    assert_eq!(hop_key_name(&dest, true, &opts), "alias.example");
    assert_eq!(hop_key_name(&hop("jump.example", 2222), false, &opts), "[jump.example]:2222");
    assert_eq!(hop_key_name(&hop("jump.example", 22), false, &opts), "jump.example");
    // A jump hop's own options, from its own blocks, give it its own alias.
    let jump = hop("jump.example", 2222);
    let mut own = Options::new(jump.clone(), "u".into());
    own.host_key_alias = Some("jump-alias".into());
    assert_eq!(hop_key_name(&jump, false, &own), "jump-alias");
}

/// The identification string names podssh and its version, with `_` for
/// each `-`: RFC 4253, section 4.2, allows no minus sign and no space in
/// the software version, and a beta's version holds one.
#[test]
fn the_banner_has_no_minus_sign_in_its_software_version() {
    let opts = Options::new(Hop { user: None, host: "dest.example".into(), port: 22, tls: false }, "u".into());
    let policy = Policy {
        name: "dest.example".into(),
        strict: crate::options::StrictHostKeyChecking::No,
        user_files: Vec::new(),
        no_user_file: None,
        global_files: Vec::new(),
        batch_mode: true,
        pin: None,
        fingerprints: Vec::new(),
    };
    let config = client_config(&opts, &policy);
    let SshId::Standard(id) = &config.client_id else { panic!("not a standard identification") };
    let software = id.strip_prefix("SSH-2.0-").expect("protocol 2.0");
    assert!(!software.contains('-') && !software.contains(' '), "{id}");
    assert_eq!(software, format!("podssh_{}", env!("CARGO_PKG_VERSION").replace('-', "_")));
}

/// Each hop takes its own options when the caller resolved them, with the
/// run's memory of its logins; else the connection's (T-290).
#[test]
fn a_hop_takes_its_own_options_and_the_runs_memory() {
    let hop = |host: &str| Hop { user: Some("u".into()), host: host.into(), port: 22, tls: false };
    let mut opts = Options::new(hop("dest.example"), "u".into());
    opts.jump = vec![hop("a.example"), hop("b.example")];
    opts.remembered = Some(Default::default());
    let mut own = Options::new(hop("a.example"), "u".into());
    own.connect_timeout = std::time::Duration::from_secs(7);
    opts.jump_options = vec![own];
    let first = hop_options(&opts, 0);
    assert_eq!(first.connect_timeout.as_secs(), 7);
    assert!(first.remembered.is_some(), "the run's memory is the hop's too");
    assert_eq!(hop_options(&opts, 1).destination.host, "dest.example", "no options of its own: the connection's");
    opts.set_batch_mode();
    assert!(opts.batch_mode && opts.jump_options[0].batch_mode);
}
