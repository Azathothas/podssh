//! The stream to the first hop through the wstunnel server of `--wstunnel`
//! (T-441), with `ConnectionAttempts` as `--direct` takes them: each try
//! says why it failed as it comes, and a refusal of the server's, an answer
//! that is not wstunnel's, or a setting that cannot work ends the tries.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::wstunnel::{Dial, Ended, WstunnelError};
use podssh_ws::{ConnectError, DialError, ProxyChoice};

use super::Road;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use crate::ssh::cloud::told::Told;
use crate::ssh::transport::{NotReached, Reached};

/// The stream to `host:port` through `road`, in at most `rounds` tries.
pub async fn reach(road: &Road, host: &str, port: u16, rounds: u32, log: &Arc<Log>) -> Result<Reached, NotReached> {
    if podssh_relay::open::offline() {
        let line = format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Err(NotReached { lines: vec![line], code: EX_UNAVAILABLE });
    }
    let (target, shown) = (podssh_ws::dial::authority(host, port), road.shown());
    let dial = Dial {
        trust: &road.trust,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        close_at_end: true,
    };
    let rounds = rounds.max(1);
    let mut code = EX_UNAVAILABLE;
    for round in 1..=rounds {
        if round > 1 {
            let wait = podssh_relay::open::backoff(round - 1);
            log.info(&format!("retrying in {:.1} s (attempt {round} of {rounds})", wait.as_secs_f32()));
            tokio::time::sleep(wait).await;
        }
        log.verbose(&format!("connecting to {target} through the wstunnel server {shown}"));
        match podssh_ws::wstunnel::open(&road.server, &road.secret, host, port, &dial).await {
            Ok(carried) => {
                log.verbose(&format!("the wstunnel server {shown} carries the session to {target}"));
                let status = carried.status.clone();
                let name = shown.clone();
                let why = move || status.get().and_then(|end| ended(&name, &end));
                let stream = Box::new(Told::new(carried.stream, why, log.clone()));
                return Ok(Reached { stream, relay: None, direct_proxy: None, layer: None });
            }
            Err(e) => {
                log.error(&format!("could not connect to {target}: {}", e.line(&shown)));
                code = exit_code(&e);
                // The server's answer, or a setting, is the same at each try.
                if code != EX_UNAVAILABLE || matches!(e, WstunnelError::NotWstunnel(_)) {
                    break;
                }
            }
        }
    }
    Err(NotReached { lines: Vec::new(), code })
}

/// The line of a session that the server ended, or `None` for an ordinary
/// end (a Close 1000, as wstunnel sends when the target closed).
pub fn ended(shown: &str, end: &Ended) -> Option<String> {
    let server = podssh_ws::wstunnel::PEER;
    match end {
        Ended::Closed { code: None | Some(1000), .. } => None,
        Ended::Closed { code: Some(code), reason } if reason.is_empty() => {
            Some(format!("{server} {shown} closed the WebSocket: {code}"))
        }
        Ended::Closed { code: Some(code), reason } => {
            Some(format!("{server} {shown} closed the WebSocket: {code} {}", podssh_ws::text::one_line(reason)))
        }
        Ended::Failed(why) => Some(format!("{server} {shown}: {why}")),
    }
}

/// The exit code of a tunnel that did not open, as `proxy` exits: 64 for a
/// target that cannot go, 78 for a setting, 77 for the server's refusal
/// (each is a 400, also a wrong secret's) and for a 401 or 403 of a server
/// in front of it, else 69.
pub fn exit_code(e: &WstunnelError) -> i32 {
    match e {
        WstunnelError::Target(_) => EX_USAGE,
        WstunnelError::Connect(c) => match c {
            ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)) => {
                EX_CONFIG
            }
            ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
            _ => EX_UNAVAILABLE,
        },
        WstunnelError::Refused { status: 400 | 401 | 403, .. } => EX_NOPERM,
        WstunnelError::Refused { .. } | WstunnelError::NotWstunnel(_) => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_of_the_server_is_77_and_a_setting_78() {
        let refused = |status| WstunnelError::Refused { status, words: "Invalid request".into() };
        assert_eq!(exit_code(&refused(400)), EX_NOPERM);
        assert_eq!(exit_code(&refused(403)), EX_NOPERM);
        assert_eq!(exit_code(&refused(502)), EX_UNAVAILABLE);
        assert_eq!(exit_code(&WstunnelError::NotWstunnel("no v1".into())), EX_UNAVAILABLE);
        assert_eq!(exit_code(&WstunnelError::Connect(ConnectError::Config("x".into()))), EX_CONFIG);
        assert_eq!(exit_code(&WstunnelError::Target("x".into())), EX_USAGE);
    }

    #[test]
    fn an_ordinary_end_says_nothing_and_another_names_the_server() {
        let shown = "wss://wst.example.org";
        assert_eq!(ended(shown, &Ended::Closed { code: Some(1000), reason: String::new() }), None);
        let cut = ended(shown, &Ended::Closed { code: Some(1011), reason: "reset".into() }).unwrap();
        assert_eq!(cut, "the wstunnel server wss://wst.example.org closed the WebSocket: 1011 reset");
        assert!(ended(shown, &Ended::Failed("no data for 90s".into())).unwrap().ends_with(": no data for 90s"));
    }
}
