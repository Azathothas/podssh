//! `podssh proxy node://NAME[/ROUTE]` (T-587): the pipe of `podssh operator
//! NAME[/ROUTE]`, by the destination form that `ssh`, `cp` and the other
//! verbs take, so that a ProxyCommand names a node as they do. One function
//! of `operator.rs` carries both verbs, so that they cannot drift. The
//! node's TARGET, or its route, names the service, so a PORT is refused, as
//! `cf://HOST` takes none; so are the relay's flags and each road that takes
//! the relay's place, as the pair names its relay. The flags of the pair and
//! of the channel go with `node://` alone, and so does `--carrier ADDR`,
//! the node at the other end of a stream that exists already, with no relay
//! and no pair, as `operator --carrier` reaches it (T-595).

use std::io::Write;

use clap::ArgMatches;

use crate::operator::OperatorArgs;
use crate::proxy::ProxyArgs;
use crate::relay_settings::Refusal;

/// The form of a node's destination.
const SCHEME: &str = crate::ssh::node::SCHEME;

/// The ProxyCommand of a node in each of its forms, for a refusal of a word
/// that starts with `node:`, which a user meant as a node.
const FORMS: &str =
    "a node's ProxyCommand is podssh proxy node://NAME, podssh operator NAME, or podssh pipe - node:NAME";

/// Why a flag of the relay goes with no node: the pair names its relay.
const RELAY: &str = "the pair names its relay";
/// Why a road in the relay's place goes with no node.
const ROAD: &str = "it takes the relay's place, and a node is reached through the relay of its pair";
/// Why `--idle-warn` goes with no node.
const IDLE: &str = "it warns before the idle cut of the relay's forward road, which a node's session does not take";

/// The flags of `proxy` that go with `node://` alone. `--client-key` goes
/// with `--exit` too, and is the exit's field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    /// `--pair-file`: a pair, or its operator's part, in a file.
    pub pair_file: Option<String>,
    /// `--node-key`: the node's key or fingerprint, in place of the pins.
    pub node_key: Option<String>,
    /// `--no-e2e`: no end-to-end channel.
    pub no_e2e: bool,
    /// `--resume-deadline`: this client's own deadline, unparsed.
    pub resume_deadline: Option<String>,
    /// `--carrier ADDR`: the node at the other end of a stream (T-595),
    /// unparsed.
    pub carrier: Option<String>,
}

impl Flags {
    /// The flags out of `proxy`'s matches, whose table has each row.
    pub fn from_matches(m: &ArgMatches) -> Flags {
        let get = |id: &str| m.get_one::<String>(id).cloned();
        Flags {
            pair_file: get("pair-file"),
            node_key: get("node-key"),
            no_e2e: m.get_flag("no-e2e"),
            resume_deadline: get("resume-deadline"),
            carrier: get("carrier"),
        }
    }

    /// The first of these flags that was given, as a user types it.
    fn given(&self) -> Option<&'static str> {
        [
            (self.pair_file.is_some(), "--pair-file"),
            (self.node_key.is_some(), "--node-key"),
            (self.no_e2e, "--no-e2e"),
            (self.resume_deadline.is_some(), "--resume-deadline"),
            (self.carrier.is_some(), "--carrier"),
        ]
        .into_iter()
        .find_map(|(given, flag)| given.then_some(flag))
    }
}

/// Run `podssh proxy` when its target names a node, or refuse a flag of a
/// node beside another target (64); `None` to go on with another road.
pub fn run(args: &ProxyArgs, err: &mut dyn Write) -> Option<i32> {
    let Some(text) = args.target.as_deref().filter(|t| names_a_node(t)) else {
        let flag = args.node.given()?;
        let why = format!("{flag} goes with node://NAME, the node of a pair or of a carrier");
        return Some(Refusal::usage(why).report("proxy", err));
    };
    let operator = match to_operator(text, args) {
        Ok(operator) => operator,
        Err(refusal) => {
            let code = refusal.report("proxy", err);
            let _ = writeln!(err, "podssh proxy: {FORMS}");
            return Some(code);
        }
    };
    crate::session_log::target(text.trim_end_matches('/'), None, "node");
    // The pair's road, or the carrier of --carrier (T-595), as operator.
    let code = crate::operator::run_as(&operator, "proxy", err);
    // A session that the node took, and that ended well, had opened.
    if code == 0 {
        crate::session_log::opened(None);
    }
    Some(code)
}

/// Whether `text` is meant as a node: `node://...`, or `node:` and a word
/// that is no port, as `pipe` writes a node. `node:22` stays the host `node`
/// and its port, in one word.
fn names_a_node(text: &str) -> bool {
    match text.strip_prefix("node:") {
        Some(rest) => rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// The operator's arguments of `node://NAME[/ROUTE]`, or the refusal (64).
/// The label and the route are checked where `operator` checks them.
fn to_operator(text: &str, args: &ProxyArgs) -> Result<OperatorArgs, Refusal> {
    let Some(rest) = text.strip_prefix(SCHEME) else {
        return Err(Refusal::usage(format!("{text:?} is not the form of a node: node://NAME[/ROUTE]")));
    };
    let name = rest.trim_end_matches('/');
    let why = if name.is_empty() {
        Some(format!("{text:?}: no NAME after {SCHEME}"))
    } else if name.contains('@') {
        Some(format!("{text}: the SSH client logs in, so the node takes no user here"))
    } else if name.contains(':') || args.port.is_some() {
        Some(format!(
            "{text} takes no PORT: the node's TARGET, or its route, names the service, as cf://HOST takes none"
        ))
    } else {
        beside(args).map(|(flag, why)| format!("{flag} does not apply to {text}: {why}"))
    };
    if let Some(why) = why {
        return Err(Refusal::usage(why));
    }
    Ok(OperatorArgs {
        name: Some(name.to_string()),
        relay_addr: args.relay_addr.clone(),
        ca_file: args.ca_file.clone(),
        pair_file: args.node.pair_file.clone(),
        client_key: args.exit.client_key.clone(),
        node_key: args.node.node_key.clone(),
        no_e2e: args.node.no_e2e,
        resume_deadline: args.node.resume_deadline.clone(),
        // The bound of the node's steps, as `operator` takes it (T-589).
        connect_timeout: args.connect_timeout.clone(),
        // The node at the other end of a stream, as `operator --carrier`
        // reaches it (T-595); its checks are operator's.
        carrier: args.node.carrier.clone(),
        refused: Vec::new(),
    })
}

/// The first flag of the relay, or of a road in the relay's place, that a
/// node does not take, with why.
fn beside(args: &ProxyArgs) -> Option<(&'static str, &'static str)> {
    [
        (args.relay_host.is_some(), "--relay-host", RELAY),
        (args.relay_failover.is_some(), "--relay-failover", RELAY),
        (args.forwarder.is_some(), "--forwarder", ROAD),
        (args.shadowsocks.is_some(), "--shadowsocks", ROAD),
        (args.via != crate::via::Flags::default(), "--via", ROAD),
        (args.vless.is_some(), "--vless", ROAD),
        (args.wstunnel != crate::wstunnel::Flags::default(), "--wstunnel", ROAD),
        (args.exit.name.is_some(), "--exit", ROAD),
        (args.idle_warn.is_some(), "--idle-warn", IDLE),
    ]
    .into_iter()
    .find_map(|(given, flag, why)| given.then_some((flag, why)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(target: &str) -> ProxyArgs {
        ProxyArgs { target: Some(target.into()), ..Default::default() }
    }

    #[test]
    fn a_word_of_node_is_a_node_and_node_with_a_port_is_a_host() {
        for text in ["node://lab", "node://lab/web", "node:lab", "node:", "node:lab:22"] {
            assert!(names_a_node(text), "{text}");
        }
        for text in ["node:22", "node", "nodes.example:22", "lab"] {
            assert!(!names_a_node(text), "{text}");
        }
    }

    #[test]
    fn a_node_gives_the_operator_its_name_route_and_flags() {
        let mut args = node("node://lab/web/");
        args.node.pair_file = Some("lab.json".into());
        args.node.no_e2e = true;
        args.ca_file = Some("ca.pem".into());
        let operator = to_operator("node://lab/web/", &args).unwrap();
        assert_eq!(operator.name.as_deref(), Some("lab/web"));
        assert_eq!(operator.pair_file.as_deref(), Some("lab.json"));
        assert_eq!(operator.ca_file.as_deref(), Some("ca.pem"));
        assert!(operator.no_e2e);
        assert_eq!(operator.carrier, None, "the pair's road, with no --carrier");
        // The carrier goes to operator, whose checks it meets (T-595).
        let mut carried = node("node://lab");
        carried.node.carrier = Some("exec:cat".into());
        assert_eq!(to_operator("node://lab", &carried).unwrap().carrier.as_deref(), Some("exec:cat"));
        assert_eq!(carried.node.given(), Some("--carrier"));
    }

    #[test]
    fn a_port_a_user_and_each_road_of_the_relay_are_refused() {
        let mut port = node("node://lab");
        port.port = Some("22".into());
        let mut relay = node("node://lab");
        relay.relay_host = Some("relay.example".into());
        let mut exit = node("node://lab");
        exit.exit.name = Some("gw".into());
        let cases = [
            (port, "node://lab", "takes no PORT"),
            (node("node://lab:22"), "node://lab:22", "takes no PORT"),
            (node("node://u@lab"), "node://u@lab", "takes no user"),
            (node("node://"), "node://", "no NAME"),
            (node("node:lab"), "node:lab", "is not the form of a node"),
            (relay, "node://lab", "--relay-host does not apply"),
            (exit, "node://lab", "--exit does not apply"),
        ];
        for (args, text, says) in cases {
            let refusal = to_operator(text, &args).unwrap_err();
            assert_eq!(refusal.code, 64, "{text}");
            assert!(refusal.message.contains(says), "{text}: {}", refusal.message);
        }
    }
}
