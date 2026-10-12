//! A node whose TARGET is `udp:HOST:PORT` (T-168). The relay carries TCP
//! only, so a datagram leaves from the node, on a host that allows UDP:
//! each session that an operator opens is one flow, a UDP socket from this
//! host to TARGET, with each datagram after its 16-bit length in the
//! session's bytes (`podssh pipe udp:node:NAME` speaks it). The flow ends
//! with its session, or after 60 s with no datagram either way.
//!
//! Before it registers, the node opens a UDP socket to TARGET and closes it,
//! which sends nothing: a host that refuses UDP (a sandbox gives EPERM)
//! stops the node with 78, as a mode whose probe failed. A UDP TARGET is the
//! node's only one, with no route, and on the pair's road alone.

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::UdpHandler;
use podssh_relay::udp::flow;

use crate::exitmap::Fault;
use crate::relay_settings::Refusal;

/// The kind of a UDP TARGET.
pub(crate) const PREFIX: &str = "udp:";

/// Whether a TARGET word, or the target of its route, names UDP.
pub(crate) fn is_udp(word: &str) -> bool {
    let target = word.split_once('=').map_or(word, |(_, target)| target);
    target.starts_with(PREFIX)
}

/// The UDP TARGET of the command line, when one is named: alone, with no
/// route. `None` when each TARGET is TCP.
pub(crate) fn target_of(words: &[String]) -> Result<Option<Route>, Refusal> {
    if !words.iter().any(|w| is_udp(w)) {
        return Ok(None);
    }
    let [word] = words else {
        return Err(Refusal::usage("a node with a udp: TARGET serves it alone: name no other TARGET and no route"));
    };
    let Some(rest) = word.strip_prefix(PREFIX) else {
        return Err(Refusal::usage(format!("{word}: a udp: TARGET has no route: podssh node NAME udp:HOST:PORT")));
    };
    let (host, port) =
        crate::proxy::parse_target(Some(rest), None).map_err(|why| Refusal::usage(format!("TARGET {word}: {why}")))?;
    Ok(Some(Route { name: None, host, port }))
}

/// TARGET as the node's lines say it.
pub(crate) fn shown(target: &Route) -> String {
    format!("{PREFIX}{}", podssh_ws::dial::authority(&target.host, target.port))
}

/// The probe: a UDP socket to TARGET, closed again with nothing sent. A host
/// that refuses UDP gives 78; a name with no address, 69.
pub(crate) async fn probe(target: &Route, limit: Duration) -> Result<(), Refusal> {
    let shown = shown(target);
    match flow::probe(&target.host, target.port, limit).await {
        Ok(_) => Ok(()),
        Err(e) if e.host_refuses() => Err(Refusal {
            message: format!("TARGET {shown}: {e}; a node that sends UDP needs a host that allows it"),
            code: Fault::Capability.code(),
        }),
        Err(e) => Err(Refusal { message: format!("TARGET {shown}: {e}"), code: Fault::RelayUnreachable.code() }),
    }
}

/// The handler of each session: a flow to TARGET, its lines on `say`.
pub(crate) fn handler(target: &Route, limit: Duration, say: Arc<dyn Fn(String) + Send + Sync>) -> UdpHandler {
    UdpHandler { say, ..UdpHandler::new(target.host.clone(), target.port, limit) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn a_udp_target_is_the_node_s_only_one_with_no_route() {
        let target = target_of(&words(&["udp:127.0.0.1:53"])).unwrap().expect("a UDP target");
        assert_eq!((target.name, target.host.as_str(), target.port), (None, "127.0.0.1", 53));
        let v6 = target_of(&words(&["udp:[2001:db8::1]:5353"])).unwrap().unwrap();
        assert_eq!(v6.host, "2001:db8::1");
        assert_eq!(shown(&v6), "udp:[2001:db8::1]:5353");
        assert!(target_of(&words(&["127.0.0.1:22", "web=127.0.0.1:80"])).unwrap().is_none());
        for bad in [
            &["udp:127.0.0.1:53", "127.0.0.1:22"][..],
            &["dns=udp:127.0.0.1:53"][..],
            &["udp:127.0.0.1"][..],
            &["udp:127.0.0.1:0"][..],
            &["udp:"][..],
        ] {
            assert_eq!(target_of(&words(bad)).unwrap_err().code, 64, "{bad:?}");
        }
    }
}
