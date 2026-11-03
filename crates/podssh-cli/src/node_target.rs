//! The check of a node's targets before it goes online (T-166): each one
//! dialled once, and a roost's read for its sshd's version line, so that a
//! node that could serve no session does not start, and never reaches the
//! relay. Apart from `node.rs`, for the length of that file.

use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::sshd;
use podssh_ws::dial::{DialError, ProxyChoice};

use crate::exitmap::Fault;
use crate::node::{shown, DIAL_LIMIT};
use crate::relay_settings::Refusal;

/// Each target, dialled once: a node that cannot reach one would refuse its
/// sessions, so it does not start (69). A roost's targets must each send an
/// SSH version line first (T-166): their lines, in order, for the node's
/// first line. Another service there is a TARGET set up wrong (78); a
/// silence or a close, one out of reach (69).
pub(crate) async fn probe(targets: &[Route], roost: bool) -> Result<Vec<String>, Refusal> {
    let (proxy, unreachable) = (ProxyChoice::FromEnvironment, Fault::RelayUnreachable.code());
    let mut versions = Vec::new();
    for t in targets {
        let shown = shown(std::slice::from_ref(t));
        let dialled = podssh_ws::dial::dial(&t.host, t.port, &proxy, DIAL_LIMIT).await;
        let stream = dialled.map_err(|e| Refusal { message: failed(&shown, t, roost, &e), code: unreachable })?;
        if !roost {
            continue;
        }
        match sshd::check(&stream, sshd::BANNER_LIMIT).await {
            Ok(line) => versions.push(line),
            Err(why) => {
                let fault = if why.is_other() { Fault::Config } else { Fault::RelayUnreachable };
                let message = format!("TARGET {shown} is not an SSH server: it {why}; --sshd serves a standard sshd");
                return Err(Refusal { message, code: fault.code() });
            }
        }
    }
    Ok(versions)
}

/// The words of a dial of TARGET that failed. A roost's TARGET on the
/// loopback where nothing listens also says whether this host has an sshd,
/// and what installs or starts one (T-590): the dial's words alone read as
/// a firewall or a wrong port. They stay first, as they are true.
fn failed(shown: &str, t: &Route, roost: bool, e: &DialError) -> String {
    let words = format!("TARGET {shown}: {e}");
    // Each address refused, or none answered: on the loopback, no listener.
    let nothing = matches!(e, DialError::Connect { .. }) && podssh_ws::dial::is_loopback(&t.host);
    if !roost || !nothing {
        return words;
    }
    let places = crate::local_sshd::places();
    let found = crate::local_sshd::look(std::env::var_os("PATH"), &places);
    let at = podssh_ws::dial::authority(&t.host, t.port);
    format!("{words}; {}", crate::local_sshd::nothing_listens(&at, &found, &places))
}

/// The targets as the node's first line says them: a roost's, each with the
/// version line that its sshd sent; and an exit's egress (T-431).
pub(crate) fn serving(targets: &[Route], versions: &[String]) -> String {
    crate::node_exit::beside(served(targets, versions), targets.is_empty())
}

fn served(targets: &[Route], versions: &[String]) -> String {
    if versions.len() != targets.len() || targets.is_empty() {
        return shown(targets);
    }
    let each = targets.iter().zip(versions).map(|(t, line)| format!("{} ({line})", shown(std::slice::from_ref(t))));
    format!("the sshd {}", each.collect::<Vec<_>>().join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(host: &str) -> Route {
        Route { name: None, host: host.into(), port: 2222 }
    }

    /// The look comes only for a roost, a TARGET on the loopback, and a
    /// dial that each address refused; the dial's words come first.
    #[test]
    fn only_a_roost_on_the_loopback_looks_for_its_sshd() {
        let refused = DialError::Connect {
            target: "x:2222".into(),
            detail: "Connection refused".into(),
            cut: Some(podssh_ws::Cut::Refused),
        };
        let alone = "TARGET x: could not connect to x:2222: Connection refused";
        assert_eq!(failed("x", &route("192.0.2.7"), true, &refused), alone);
        assert_eq!(failed("x", &route("127.0.0.1"), false, &refused), alone);
        let late = DialError::Timeout { step: "the TCP connection".into(), after: std::time::Duration::from_secs(8) };
        assert!(!failed("x", &route("127.0.0.1"), true, &late).contains("sshd"));
        for host in ["127.0.0.1", "localhost", "::1"] {
            let looked = failed("x", &route(host), true, &refused);
            assert!(looked.starts_with(&format!("{alone}; ")) && looked.contains(" sshd is installed "), "{looked}");
        }
    }
}
