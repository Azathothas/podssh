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
    let hop = |host: &str, port| Hop { user: None, host: host.into(), port };
    let mut opts = Options::new(hop("dest.example", 2203), "u".into());
    let dest = opts.destination.clone();
    assert_eq!(hop_key_name(&hop("jump.example", 22), false, &opts), "jump.example");
    assert_eq!(hop_key_name(&hop("jump.example", 2222), false, &opts), "[jump.example]:2222");
    assert_eq!(hop_key_name(&dest, true, &opts), "[dest.example]:2203");
    opts.host_key_alias = Some("alias.example".into());
    assert_eq!(hop_key_name(&dest, true, &opts), "alias.example");
    assert_eq!(hop_key_name(&hop("jump.example", 2222), false, &opts), "[jump.example]:2222");
    assert_eq!(hop_key_name(&hop("jump.example", 22), false, &opts), "jump.example");
}
