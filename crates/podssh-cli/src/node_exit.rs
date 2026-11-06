//! `podssh node NAME [TARGET] --exit` (T-431): the node lends this host's
//! egress to the members of its net, as a Tailscale exit node does. An
//! operator names a target of its own in the end-to-end channel, as the word
//! of its proof (`podssh_relay::e2e::Ask`), and the node:
//!
//! 1. lets in a member that the net's policy lets reach its egress or a
//!    range, and only where the owner gave this node the role `exit`
//!    (`crate::net::admit`); never a key of `--allow`, nor an operator of
//!    the pair's connect token alone;
//! 2. resolves the name itself, with podssh's resolver;
//! 3. checks each address: a public one, by the relay role's check of a
//!    public address (`podssh_relay::serve::policy::public`), for a member
//!    that the policy lets reach `exit:NODE`; another one only inside a
//!    range of `--routes`, for a member that the policy lets reach that
//!    address; a loopback address, or one of the node's own host, only
//!    where a range names it alone (T-432, `crate::node_exit_own`); a name
//!    with one address that fails is refused whole, as the relay refuses it;
//! 4. dials those addresses alone, never the name again, so that a name
//!    that resolves anew to another address (DNS rebinding) reaches nothing
//!    that was not checked; through HTTPS_PROXY when one is set, as a node
//!    dials each TARGET, with the address in place of the name.
//!
//! A process is one node, so the exit is the process's, as the net's
//! documents are; each road's routes take its dial (`crate::node::routes_of`).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use podssh_relay::e2e::Refusal as NodeRefusal;
use podssh_relay::identity::PublicKey;
use podssh_relay::reverse::routes::{ExitDial, Route};
use podssh_ws::dial::ProxyChoice;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::net::admit::{verdict, Asks, Verdict};
use crate::net::policy_words::Range;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The bound on the resolution of a target's name, within the operator's
/// wait for the node's verdict (`podssh_relay::e2e::ends::TARGET_WAIT`).
const RESOLVE_LIMIT: Duration = Duration::from_secs(6);
/// The bound on the dials of its addresses, after it.
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// What `--exit` asked: the private ranges that it dials too, each as given.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub ranges: Vec<(String, Range)>,
}

static PLAN: OnceLock<Plan> = OnceLock::new();

/// The flags of the exit, checked before anything is read: `--routes` goes
/// with `--exit`, and `--exit` with a road that carries the channel and
/// TCP. The plan is kept for the process.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if !args.exit {
        return match args.routes {
            // The ranges of the relay role behind a quick tunnel (T-635),
            // which its own check reads.
            Some(_) if args.relay => Ok(()),
            Some(_) => Err(Refusal::usage(
                "--routes names the private ranges of an exit, or of the relay role of --quick-tunnel --relay: give \
                 --exit too, or --relay",
            )),
            None => Ok(()),
        };
    }
    let udp = args.targets.iter().any(|t| t.starts_with("udp:") || t.contains("=udp:"));
    let why = if args.no_e2e {
        Some("--exit names each target in the end-to-end channel, which --no-e2e turns off")
    } else if args.temporary.is_some() {
        Some("--exit does not go with --temporary, the far end of podssh ssh --upgrade")
    } else if udp {
        Some("--exit carries TCP: a udp: TARGET goes on a node with no --exit")
    } else {
        None
    };
    if let Some(why) = why {
        return Err(Refusal::usage(why));
    }
    let ranges = match args.routes.as_deref() {
        Some(text) => ranges(text)?,
        None => Vec::new(),
    };
    let _ = PLAN.set(Plan { ranges });
    Ok(())
}

/// The ranges of `--routes`: `ADDR/BITS` or one address, separated by
/// commas, as a rule of the net's policy names a range; a prefix that sets
/// bits past it is refused with the network that it names (T-635), as the
/// relay role's `--routes` refuses it.
fn ranges(text: &str) -> Result<Vec<(String, Range)>, Refusal> {
    podssh_relay::serve::ranges::list(text).map_err(|why| Refusal::usage(format!("--routes {text}: {why}")))
}

/// Whether this node is an exit (`--exit`).
pub(crate) fn asked() -> bool {
    PLAN.get().is_some()
}

/// The exit's line as the node `label` starts, once its key `me` is
/// loaded, or why it cannot be one (78): a member of a net in force that
/// gives it the role `exit`. Each road calls it.
pub(crate) fn ready(label: &str, me: &PublicKey) -> Result<(), Refusal> {
    let Some(plan) = PLAN.get() else { return Ok(()) };
    let (line, listed) = crate::net::admit::exit_ready(me).map_err(|why| Refusal::config(format!("--exit: {why}")))?;
    let ranges: Vec<&str> = plan.ranges.iter().map(|(word, _)| word.as_str()).collect();
    let inside = match ranges.is_empty() {
        true => ", and to no private range (--routes names some)".to_string(),
        false => format!(", and to the private ranges {}", ranges.join(", ")),
    };
    podssh_ssh::err_line!("podssh node: {label}: {line}{inside}; each name is resolved here, and each address checked");
    if let Some(note) = listed_apart(&plan.ranges, &listed) {
        podssh_ssh::err_line!("podssh node: {label}: {note}");
    }
    Ok(())
}

/// What the net's document lists as this exit's routes (T-432), when it
/// is not what `--routes` dials: `--exit auto` sends a member's session here
/// by the document, and this node dials by its own flag.
fn listed_apart(ranges: &[(String, Range)], listed: &[String]) -> Option<String> {
    let dialled: Vec<Range> = ranges.iter().map(|(_, range)| *range).collect();
    let read: Vec<Range> = listed.iter().filter_map(|word| Range::parse(word)).collect();
    let same = dialled.iter().all(|r| read.contains(r)) && read.iter().all(|r| dialled.contains(r));
    if same {
        return None;
    }
    let shown = |words: Vec<&str>| match words.is_empty() {
        true => "none".to_string(),
        false => words.join(", "),
    };
    Some(format!(
        "the net's document lists the routes {} for this exit, and --routes gives {}: --exit auto sends a session \
         here by the document's, and this node dials only inside its own; its owner lists them with podssh net add \
         NAME KEY --roles node,exit --routes RANGES",
        shown(listed.iter().map(String::as_str).collect()),
        shown(ranges.iter().map(|(word, _)| word.as_str()).collect())
    ))
}

/// What the node's first line says that it serves: its targets, and its
/// exit; `none` when it has no target of its own.
pub(crate) fn beside(served: String, none: bool) -> String {
    match (asked(), none) {
        (false, _) => served,
        (true, true) => "an exit for its net, with no target of its own".into(),
        (true, false) => format!("{served}, and an exit for its net"),
    }
}

/// The first target, for a handler of the target with no route. An exit
/// with no target has none: its routes then answer each session, and the
/// stand-in, with no host, is never dialled.
pub(crate) fn first(targets: &[Route]) -> Route {
    targets.first().cloned().unwrap_or(Route { name: None, host: String::new(), port: 0 })
}

/// The dial of the exit at the node `me`, when it is one.
pub(crate) fn dial(me: PublicKey) -> Option<Arc<ExitDial>> {
    let plan = PLAN.get()?;
    let ranges: Arc<Vec<Range>> = Arc::new(plan.ranges.iter().map(|(_, range)| *range).collect());
    let dial: Arc<ExitDial> = Arc::new(move |peer: PublicKey, host: String, port: u16| {
        let ranges = ranges.clone();
        let opened: Pin<Box<dyn Future<Output = Result<TcpStream, NodeRefusal>> + Send>> =
            Box::pin(async move { open(&me, &peer, &host, port, &ranges).await });
        opened
    });
    Some(dial)
}

/// The exit's connection to `host:port` for the member `peer`: the name
/// resolved here, each address checked, and only those dialled.
async fn open(
    me: &PublicKey,
    peer: &PublicKey,
    host: &str,
    port: u16,
    ranges: &[Range],
) -> Result<TcpStream, NodeRefusal> {
    let shown = podssh_ws::dial::authority(host, port);
    let deadline = Instant::now() + RESOLVE_LIMIT;
    let found = podssh_ws::resolve::resolve(host, port, deadline)
        .await
        .map_err(|why| NodeRefusal::NoTarget(format!("could not resolve {host}: {why}")))?;
    let own = crate::node_exit_own::addresses();
    let net = |addr, public| verdict(me, peer, Asks::Dial { addr, public });
    let addresses = checked(&shown, found, ranges, &own, &net)?;
    dial_each(&shown, addresses, ranges).await
}

/// The addresses of `shown` that the exit may dial, each checked: public,
/// or inside one of `ranges`; the host's own (a loopback one, or one of
/// `own`) only where a range names it alone; and each one let by `net`, the
/// net's verdict on the member for that address. `Err` names the first
/// that fails, and none is dialled then.
pub(crate) fn checked(
    shown: &str,
    found: Vec<SocketAddr>,
    ranges: &[Range],
    own: &[std::net::IpAddr],
    net: &dyn Fn(std::net::IpAddr, bool) -> Verdict,
) -> Result<Vec<SocketAddr>, NodeRefusal> {
    if found.is_empty() {
        return Err(NodeRefusal::NoTarget(format!("{shown} has no address")));
    }
    for addr in &found {
        let ip = addr.ip();
        let public = podssh_relay::serve::policy::public(ip);
        if !public && !ranges.iter().any(|range| range.contains(ip)) {
            return Err(NodeRefusal::Other(format!(
                "{shown} resolves to {ip}, which is not a public address, and no range of the exit's --routes holds it"
            )));
        }
        if let Some(what) = crate::node_exit_own::kind(ip, own) {
            if let Some(why) = crate::node_exit_own::refused(shown, ip, what, ranges) {
                return Err(NodeRefusal::Other(why));
            }
        }
        match net(ip, public) {
            Verdict::Member(_) => {}
            Verdict::Refused(why) => return Err(NodeRefusal::Other(why)),
            Verdict::Outside => {
                return Err(NodeRefusal::Other("this node is in no net now, so its exit lets nobody out".into()))
            }
        }
    }
    Ok(found)
}

/// Each address in turn, IPv6 and IPv4 interleaved, within the dial's
/// bound: an address, never the name again, so what was checked is what is
/// dialled. A connection that went to the host itself, which the list of
/// its addresses missed, is closed unread unless a range names it alone.
async fn dial_each(shown: &str, addresses: Vec<SocketAddr>, ranges: &[Range]) -> Result<TcpStream, NodeRefusal> {
    let deadline = Instant::now() + DIAL_LIMIT;
    let mut last = String::from("no address was tried in time");
    for addr in podssh_ws::dial::interleave(addresses) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let ip = addr.ip().to_string();
        match podssh_ws::dial::dial(&ip, addr.port(), &ProxyChoice::FromEnvironment, left).await {
            Ok(stream) => {
                let ends = stream.local_addr().ok().zip(stream.peer_addr().ok());
                let looped = ends.is_some_and(|(local, peer)| crate::node_exit_own::looped(local, peer, addr));
                let what = "an address of the exit's host";
                match looped.then(|| crate::node_exit_own::refused(shown, addr.ip(), what, ranges)).flatten() {
                    Some(why) => return Err(NodeRefusal::Other(why)),
                    None => return Ok(stream),
                }
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(NodeRefusal::NoTarget(format!("{shown}: {last}")))
}

#[cfg(test)]
#[path = "node_exit_tests.rs"]
mod tests;
