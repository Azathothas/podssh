//! The stream to the first hop through the servers of `--vless` (T-440),
//! each in turn until one carries it. An SSH server speaks first, so each
//! waits for VLESS's answer, which comes with the server's version line: a
//! server that ends the session before it has refused the ID or could not
//! reach the target, and the next is tried. Each failure is said as it comes,
//! so the last line is the one that the run ends with.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::vless::{self, Dial, VlessError};
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
        answer: vless::ANSWER_WAIT,
        silence_is_ready: false,
        close_at_end: true,
    };
    let mut code = EX_UNAVAILABLE;
    for server in &servers.servers {
        let shown = server.shown();
        log.verbose(&format!("connecting to {target} through the VLESS server {shown}, {}", server.transport.name()));
        match vless::open(server, host, port, &dial).await {
            Ok(opened) => {
                log.verbose(&format!("the VLESS server {shown} carries the session to {target} over {}", opened.how));
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
/// for a target that VLESS cannot name, 78 for a setting, 77 for a refusal
/// of the host's proxy or of the server's HTTP (401, 403), else 69.
pub fn exit_code(e: &VlessError) -> i32 {
    match e {
        VlessError::Target(_) => EX_USAGE,
        VlessError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)) | VlessError::Http1(_) => EX_CONFIG,
        VlessError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
        VlessError::Refused { status: 401 | 403, .. } => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_has_the_code_of_proxy() {
        assert_eq!(exit_code(&VlessError::Target("x".into())), EX_USAGE);
        assert_eq!(exit_code(&VlessError::Http1("h2".into())), EX_CONFIG);
        assert_eq!(exit_code(&VlessError::Refused { status: 403, why: "w".into() }), EX_NOPERM);
        assert_eq!(exit_code(&VlessError::Refused { status: 404, why: "w".into() }), EX_UNAVAILABLE);
        assert_eq!(exit_code(&VlessError::Ended), EX_UNAVAILABLE);
        let (proxy, target, reason) = ("p:3128".to_string(), "h:443".to_string(), "no".to_string());
        let refused = DialError::ProxyRefused { proxy, target, status: 407, reason };
        assert_eq!(exit_code(&VlessError::Dial(refused)), EX_NOPERM);
    }
}
