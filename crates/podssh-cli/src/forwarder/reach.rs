//! The stream to the first hop through the forwarders of a run (T-369),
//! each in turn until one carries it, as the relay hosts are tried. A
//! forwarder's text frames are shown with -v; a Close that it sends with a
//! code other than 1000 is said once, naming it, before SSH reads the end of
//! its stream.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::forwarder::{Dial, Ended, ForwarderError, Note};
use podssh_ws::{ConnectError, DialError, ProxyChoice, Trust};

use super::Forwarder;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use crate::ssh::cloud::told::Told;
use crate::ssh::transport::{NotReached, Reached};

/// The stream to `host:port` through the first of `forwarders` that
/// carries it. Each failure is logged as it comes, so the error of the last
/// is the one that the run ends with.
pub async fn reach(
    forwarders: &[Forwarder],
    trust: &Trust,
    host: &str,
    port: u16,
    log: &Arc<Log>,
) -> Result<Reached, NotReached> {
    if podssh_relay::open::offline() {
        let line = format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Err(NotReached { lines: vec![line], code: EX_UNAVAILABLE });
    }
    let target = podssh_ws::dial::authority(host, port);
    let mut code = EX_UNAVAILABLE;
    for forwarder in forwarders {
        log.verbose(&format!("connecting to {target} through the forwarder {}", forwarder.name));
        let dial = Dial {
            trust,
            proxy: &ProxyChoice::FromEnvironment,
            timeout: podssh_relay::open::CONNECT_TIMEOUT,
            close_at_end: true,
            note: noted(log, &forwarder.name),
        };
        match podssh_ws::forwarder::open(&forwarder.template, host, port, &dial).await {
            Ok(carried) => {
                log.verbose(&format!("the forwarder {} carries the session to {target}", forwarder.name));
                let status = carried.status.clone();
                let name = forwarder.name.clone();
                let why = move || status.get().and_then(|end| ended(&name, &end));
                let stream = Box::new(Told::new(carried.stream, why, log.clone()));
                return Ok(Reached { stream, relay: None, direct_proxy: None, layer: None });
            }
            Err(e) => {
                log.error(&e.line(&forwarder.name));
                code = exit_code(&e);
                // A target that no template takes: the next would refuse it too.
                if code == EX_USAGE {
                    break;
                }
            }
        }
    }
    Err(NotReached { lines: Vec::new(), code })
}

/// The note of a forwarder's text frames: a line with -v.
pub fn noted(log: &Arc<Log>, name: &str) -> Note {
    let (log, name) = (log.clone(), name.to_string());
    Arc::new(move |text: &str| log.verbose(&format!("the forwarder {name} says: {text}")))
}

/// The line of a session that the forwarder ended, or `None` for an
/// ordinary end (a Close 1000, as a Worker sends when the target closed).
pub fn ended(name: &str, end: &Ended) -> Option<String> {
    match end {
        Ended::Closed { code: None | Some(1000), .. } => None,
        Ended::Closed { code: Some(code), reason } if reason.is_empty() => {
            Some(format!("the forwarder {name} closed the WebSocket: {code}"))
        }
        Ended::Closed { code: Some(code), reason } => {
            Some(format!("the forwarder {name} closed the WebSocket: {code} {}", podssh_ws::text::one_line(reason)))
        }
        Ended::Failed(why) => Some(format!("the forwarder {name}: {why}")),
    }
}

/// The exit code of a forwarder that carried nothing, as `proxy` exits: 64
/// for a target that cannot go, 78 for a setting, 77 for a refusal of the
/// forwarder or the proxy, else 69.
pub fn exit_code(e: &ForwarderError) -> i32 {
    match e {
        ForwarderError::Target(_) => EX_USAGE,
        ForwarderError::Connect(c) => match c {
            ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)) => {
                EX_CONFIG
            }
            ConnectError::Refused { status: 401 | 403, .. } => EX_NOPERM,
            ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
            _ => EX_UNAVAILABLE,
        },
        ForwarderError::Answer(_) | ForwarderError::Closed { .. } => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_end_says_nothing_and_another_names_the_forwarder() {
        let name = "wss://web-proxy.mudlet.org/";
        assert_eq!(ended(name, &Ended::Closed { code: Some(1000), reason: "TCP connection closed".into() }), None);
        assert_eq!(ended(name, &Ended::Closed { code: None, reason: String::new() }), None);
        let cut = Ended::Closed { code: Some(1011), reason: "Proxy: TCP read error: reset".into() };
        assert_eq!(
            ended(name, &cut).unwrap(),
            "the forwarder wss://web-proxy.mudlet.org/ closed the WebSocket: 1011 Proxy: TCP read error: reset"
        );
        assert!(ended(name, &Ended::Failed("no data for 90s".into())).unwrap().ends_with(": no data for 90s"));
    }

    #[test]
    fn each_failure_has_the_code_of_proxy() {
        assert_eq!(exit_code(&ForwarderError::Target("x".into())), EX_USAGE);
        let refused = ForwarderError::Connect(ConnectError::Refused { status: 403, body: String::new() });
        assert_eq!(exit_code(&refused), EX_NOPERM);
        assert_eq!(exit_code(&ForwarderError::Closed { code: Some(1011), reason: String::new() }), EX_UNAVAILABLE);
        assert_eq!(exit_code(&ForwarderError::Connect(ConnectError::Config("bad".into()))), EX_CONFIG);
    }
}
