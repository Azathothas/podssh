//! The check of a node's targets before it goes online (T-166): each one
//! dialled once, and a roost's read for its sshd's version line, so that a
//! node that could serve no session does not start, and never reaches the
//! relay. Apart from `node.rs`, for the length of that file.

use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::sshd;
use podssh_ws::dial::ProxyChoice;

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
        let stream = dialled.map_err(|e| Refusal { message: format!("TARGET {shown}: {e}"), code: unreachable })?;
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

/// The targets as the node's first line says them: a roost's, each with the
/// version line that its sshd sent.
pub(crate) fn serving(targets: &[Route], versions: &[String]) -> String {
    if versions.len() != targets.len() {
        return shown(targets);
    }
    let each = targets.iter().zip(versions).map(|(t, line)| format!("{} ({line})", shown(std::slice::from_ref(t))));
    format!("the sshd {}", each.collect::<Vec<_>>().join(", "))
}
