//! The stream to the first hop through the servers of `--trojan` (T-491),
//! each in turn until one carries it. An SSH server speaks first, so each
//! waits for its version line: a server whose fallback answers, or that ends
//! the session before it, did not take the password or could not reach the
//! target, and the next is tried. Each failure is said as it comes, so the
//! last line is the one that the run ends with.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::trojan::{self, Dial, TrojanError};
use podssh_ws::{DialError, ProxyChoice, Trust};

use super::Servers;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use crate::ssh::transport::{NotReached, Reached};

/// The stream to `host:port` through the first server that carries it.
pub async fn reach(
    servers: &Servers,
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
    let dial = Dial {
        trust,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        answer: trojan::ANSWER_WAIT,
        silence_is_ready: false,
        close_at_end: true,
    };
    let mut code = EX_UNAVAILABLE;
    for server in &servers.servers {
        let shown = server.shown();
        log.verbose(&format!(
            "connecting to {target} through the Trojan server {shown}, in {}",
            server.transport.name()
        ));
        match trojan::open(server, host, port, &dial).await {
            Ok(opened) => {
                log.verbose(&format!("the Trojan server {shown} carries the session to {target} in {}", opened.how));
                // A write that makes no progress fails as on the relay leg,
                // never a wait for ever (T-227).
                let stream = podssh_ws::write_limit::WriteLimit::new(opened.stream, podssh_ws::client::WRITE_TIMEOUT);
                return Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: None });
            }
            Err(e) => {
                log.error(&e.line(&shown, &target));
                code = exit_code(&e);
                // A target that no server takes: the next would refuse it too.
                if code == EX_USAGE {
                    break;
                }
            }
        }
    }
    Err(NotReached { lines: Vec::new(), code })
}

/// The exit code of a server that carried nothing, as `proxy` exits: 64
/// for a target that Trojan cannot name, 78 for a setting of the host's
/// proxy, 77 for a password that the server did not take (its fallback
/// answered), a refusal of the host's proxy, or a refused upgrade (401,
/// 403), else 69.
pub fn exit_code(e: &TrojanError) -> i32 {
    match e {
        TrojanError::Target(_) => EX_USAGE,
        TrojanError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)) => EX_CONFIG,
        TrojanError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
        TrojanError::Refused { status: 401 | 403, .. } | TrojanError::Fallback(_) => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_has_the_code_of_proxy() {
        assert_eq!(exit_code(&TrojanError::Target("x".into())), EX_USAGE);
        assert_eq!(exit_code(&TrojanError::Fallback("HTTP/1.1 400".into())), EX_NOPERM);
        assert_eq!(exit_code(&TrojanError::Refused { status: 403, why: "w".into() }), EX_NOPERM);
        assert_eq!(exit_code(&TrojanError::Refused { status: 404, why: "w".into() }), EX_UNAVAILABLE);
        assert_eq!(exit_code(&TrojanError::Ended), EX_UNAVAILABLE);
    }
}
