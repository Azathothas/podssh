//! `upterm://SESSION@HOST[:PORT]` (T-495): a session of upterm's host
//! (owenthereal/upterm) as an SSH server, reached as a guest reaches it, by
//! a WebSocket on port 443 to uptermd through `HTTPS_PROXY`
//! (`podssh_ws::upterm`), SSH inside it as the user `SESSION`. uptermd
//! checks the guest's key against the host's list and carries the guest's
//! channels to the host: as the first hop of `-J`, the next hop goes in a
//! `direct-tcpip` channel to the host's loopback, where `upterm host
//! --allow-forwarding=loopback` lets it, so that the host's own sshd checks
//! the user end to end. As the destination, the session itself: the host's
//! shared terminal.
//!
//! uptermd's host key is a certificate: `known_hosts` checks it under its
//! `@cert-authority` line, as upterm's README gives it, for the name
//! `[HOST]:443` that upterm's own client keys it by. podssh names no
//! uptermd of its own: the community server is a service of another party,
//! whose name the user gives (`docs/decisions.md`, pod-services). `ws://`
//! goes to this host alone, as the session's ID would cross the network in
//! the clear: `upterm+ws://SESSION@127.0.0.1:PORT`.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::upterm::{self, Server};
use podssh_ws::{ProxyChoice, Trust};

use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};
use crate::ssh::transport::{NotReached, Reached};

/// The form of a destination on this road.
pub const SCHEME: &str = "upterm://";
/// Its form over `ws://`, for an uptermd on this host.
pub const PLAIN_SCHEME: &str = "upterm+ws://";
/// uptermd's port over `wss://`, as upterm's client dials it.
const TLS_PORT: u16 = 443;

/// A session on an uptermd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub server: Server,
}

impl Target {
    /// The session as messages show it: no port of the scheme's.
    pub fn shown(&self) -> String {
        let s = &self.server;
        let scheme = if s.tls { SCHEME } else { PLAIN_SCHEME };
        format!("{scheme}{}@{}", s.session, s.host_header())
    }
}

/// `upterm://SESSION@HOST[:PORT]` (or `upterm+ws://`) as its user and its
/// target; `None` for another destination. The SSH user is the session's
/// ID, which `SESSION@` names: a user given apart is refused, as uptermd
/// takes no other.
pub fn destination(text: &str) -> Result<Option<(Option<String>, Target)>, String> {
    let (rest, tls) = match (text.strip_prefix(SCHEME), text.strip_prefix(PLAIN_SCHEME)) {
        (Some(rest), _) => (rest, true),
        (None, Some(rest)) => (rest, false),
        (None, None) => return Ok(None),
    };
    let form =
        || format!("{text:?}: give it as {SCHEME}SESSION@HOST[:PORT], with the session's ID that its host shows");
    let (session, place) = rest.trim_end_matches('/').split_once('@').ok_or_else(form)?;
    if session.is_empty() || !session.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        return Err(form());
    }
    let default = if tls { TLS_PORT } else { 80 };
    let (host, port) = host_port(text, place, default)?;
    let usable = !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._:".contains(&b));
    if !usable {
        return Err(form());
    }
    if !tls && !loopback(&host) {
        return Err(format!(
            "{text:?}: {PLAIN_SCHEME} goes to this host alone, as the session's ID would cross the network in the \
             clear; use {SCHEME}"
        ));
    }
    let server = Server { host, port, tls, session: session.to_string() };
    Ok(Some((Some(session.to_string()), Target { server })))
}

/// `HOST[:PORT]` or `[V6][:PORT]`, the port `default` when none is given.
fn host_port(text: &str, place: &str, default: u16) -> Result<(String, u16), String> {
    let (host, port) = match place.strip_prefix('[') {
        Some(inner) => {
            let (v6, after) = inner.split_once(']').ok_or_else(|| format!("{text:?}: no ] after the address"))?;
            (v6, after.strip_prefix(':'))
        }
        None if place.matches(':').count() > 1 => {
            return Err(format!("{text:?}: an IPv6 address goes in brackets, as {SCHEME}SESSION@[ADDRESS]:PORT"))
        }
        None => match place.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (place, None),
        },
    };
    let port = match port {
        None => default,
        Some(text_port) => match text_port.parse::<u16>() {
            Ok(port) if port != 0 => port,
            _ => return Err(format!("{text:?}: {text_port:?} is not a port")),
        },
    };
    Ok((host.to_string(), port))
}

/// `localhost` or a loopback address.
fn loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether `destination` names a session on this road.
pub fn is_upterm(destination: &str) -> bool {
    destination.starts_with(SCHEME) || destination.starts_with(PLAIN_SCHEME)
}

/// The stream of SSH to uptermd, or the line and code of its failure.
pub async fn open(target: &Target, trust: &Trust) -> Result<Box<dyn crate::ssh::transport::Duplex>, (String, i32)> {
    let proxy = ProxyChoice::FromEnvironment;
    let dial = upterm::Dial { trust, proxy: &proxy, timeout: podssh_relay::open::CONNECT_TIMEOUT };
    let shown = target.shown();
    match upterm::open(&target.server, &dial).await {
        Ok(carried) => Ok(Box::new(carried.stream)),
        Err(e) => {
            // A session that uptermd knows not is the user's to put right.
            let code = match e {
                upterm::UptermError::Closed { .. } => EX_NOPERM,
                _ => EX_UNAVAILABLE,
            };
            Err((e.line(&shown, &target.server.session), code))
        }
    }
}

/// The stream to uptermd, as `podssh ssh` reaches a first hop.
pub(super) async fn reach(target: &Target, trust: &Trust, log: &Arc<Log>) -> Result<Reached, NotReached> {
    log.verbose(&format!("{}: a WebSocket to {}, as an upterm guest", target.shown(), upterm::PEER));
    match open(target, trust).await {
        Ok(stream) => Ok(Reached { stream, relay: None, direct_proxy: None, layer: None }),
        Err((line, code)) => Err(NotReached { lines: vec![line], code }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upterm_a_session_is_read_with_its_server() {
        let (user, t) = destination("upterm://abc123@uptermd.test").unwrap().unwrap();
        assert_eq!(user.as_deref(), Some("abc123"));
        assert_eq!((t.server.host.as_str(), t.server.port, t.server.tls), ("uptermd.test", 443, true));
        assert_eq!(t.shown(), "upterm://abc123@uptermd.test");
        let (_, t) = destination("upterm://abc123@uptermd.test:8443/").unwrap().unwrap();
        assert_eq!((t.server.port, t.shown().as_str()), (8443, "upterm://abc123@uptermd.test:8443"));
        let (_, t) = destination("upterm+ws://abc123@127.0.0.1:2280").unwrap().unwrap();
        assert_eq!((t.server.host.as_str(), t.server.port, t.server.tls), ("127.0.0.1", 2280, false));
        assert_eq!(destination("tor://github.com").unwrap(), None);
    }

    #[test]
    fn upterm_a_bad_form_or_ws_to_another_host_is_refused() {
        for bad in [
            "upterm://uptermd.test",
            "upterm://@uptermd.test",
            "upterm://a b@uptermd.test",
            "upterm://abc@",
            "upterm://abc@uptermd.test:0",
            "upterm://abc@uptermd.test:http",
        ] {
            assert!(destination(bad).is_err(), "{bad}");
        }
        let far = destination("upterm+ws://abc@uptermd.test").unwrap_err();
        assert!(far.contains("this host alone"), "{far}");
    }
}
