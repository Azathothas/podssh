//! The stream to the first hop through the chisel server of `--chisel`
//! (T-490), with `ConnectionAttempts` as `--direct` takes them: each try
//! says why it failed as it comes, and a refusal of the server's, a key
//! whose fingerprint is not the file's, or a setting that cannot work ends
//! the tries.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::chisel::ChiselError;
use podssh_ws::{ConnectError, DialError};

use super::Road;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::ssh::transport::{NotReached, Reached};

/// The stream to `host:port` through `road`, in at most `rounds` tries.
pub async fn reach(road: &Road, host: &str, port: u16, rounds: u32, log: &Arc<Log>) -> Result<Reached, NotReached> {
    if podssh_relay::open::offline() {
        let line = format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Err(NotReached { lines: vec![line], code: EX_UNAVAILABLE });
    }
    let (target, shown) = (podssh_ws::dial::authority(host, port), road.shown());
    if road.secret.fingerprint.is_none() {
        log.verbose(&format!(
            "the chisel server {shown}: no fingerprint in --chisel-auth-file, so its key is not checked; TLS names the \
             server, and the first hop's own host key protects the session"
        ));
    }
    let limit = podssh_relay::open::CONNECT_TIMEOUT;
    let rounds = rounds.max(1);
    let mut code = EX_UNAVAILABLE;
    for round in 1..=rounds {
        if round > 1 {
            let wait = podssh_relay::open::backoff(round - 1);
            log.info(&format!("retrying in {:.1} s (attempt {round} of {rounds})", wait.as_secs_f32()));
            tokio::time::sleep(wait).await;
        }
        log.verbose(&format!("connecting to {target} through the chisel server {shown}"));
        match super::link::open(road, host, port, limit).await {
            Ok(stream) => {
                log.verbose(&format!("the chisel server {shown} carries the session to {target}"));
                return Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: None });
            }
            Err(failed) => {
                log.error(&format!("could not connect to {target}: {}", failed.line));
                code = failed.code;
                // The server's answer, or a setting, is the same at each try.
                if code != EX_UNAVAILABLE {
                    break;
                }
            }
        }
    }
    Err(NotReached { lines: Vec::new(), code })
}

/// The exit code of a WebSocket that did not open, as `proxy` exits: 78
/// for a setting, 77 for a 401 or 403 of a server in front of it or of the
/// host's proxy, else 69. chisel's own refusals come inside the SSH
/// ([`super::link`]).
pub fn exit_code(e: &ChiselError) -> i32 {
    match e {
        ChiselError::Connect(c) => match c {
            ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)) => {
                EX_CONFIG
            }
            ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
            _ => EX_UNAVAILABLE,
        },
        ChiselError::Refused { status: 401 | 403, .. } => EX_NOPERM,
        ChiselError::Refused { .. } => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_404_is_69_a_403_77_and_a_setting_78() {
        let refused = |status| ChiselError::Refused { status, words: "Not found".into() };
        assert_eq!(exit_code(&refused(404)), EX_UNAVAILABLE);
        assert_eq!(exit_code(&refused(403)), EX_NOPERM);
        assert_eq!(exit_code(&ChiselError::Connect(ConnectError::Config("x".into()))), EX_CONFIG);
    }
}
