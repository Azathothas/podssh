//! The stream to the first hop: through the relay, with failover, or over
//! TCP with `--direct`. `ssh` runs a session on it, and `cp` an SFTP session.

use std::sync::Arc;

use podssh_relay::open::Request;
use podssh_ssh::{Log, RelayStatus};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncRead, AsyncWrite};

use super::resolve::{Resolved, Transport};
use crate::exitmap::sysexits;

/// A stream of either transport.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// The first hop, reached.
pub struct Reached {
    /// The bytes to and from the first hop.
    pub stream: Box<dyn Duplex>,
    /// The relay leg's status, when the relay carries the stream.
    pub relay: Option<RelayStatus>,
}

/// Why the first hop was not reached: the lines that say so, and the
/// sysexits code of a command that uses them (`ssh` exits 255 instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotReached {
    /// Each line, for the log; empty when each attempt was logged already.
    pub lines: Vec<String>,
    /// 64 for a target that the relay cannot carry, else as `proxy` exits.
    pub code: i32,
}

/// Reach the first `-J` hop, or the destination, as `resolved` says. A
/// `node://` destination is not reached here: its road has its own runner.
pub async fn reach(resolved: &Resolved, log: &Arc<Log>) -> Result<Reached, NotReached> {
    let opts = &resolved.options;
    let first = opts.jump.first().unwrap_or(&opts.destination);
    let target = podssh_ws::dial::authority(&first.host, first.port);
    match &resolved.transport {
        Transport::Relay { relays, trust, family } => {
            let mut path = podssh_relay::relay::forward_path(&first.host, first.port)
                .map_err(|why| NotReached { lines: vec![why], code: sysexits::EX_USAGE })?;
            if let Some(f) = family {
                path.push_str(&format!("?family={f}"));
            }
            let hosts: Vec<&str> = relays.hosts.iter().map(|r| r.host.as_str()).collect();
            log.verbose(&format!("connecting to {target} through the relay ({})", hosts.join(", ")));
            let request = Request { relays, path: &path, trust, target: &target, rounds: resolved.connection_attempts };
            let note_log = log.clone();
            match podssh_relay::open(&request, &mut |note: &str| note_log.info(note)).await {
                Ok(opened) => {
                    log.verbose(&format!("the relay host {} opened the session", opened.relay.host));
                    let (stream, status) = podssh_ssh::relay_stream::spawn(opened.session);
                    Ok(Reached { stream: Box::new(stream), relay: Some(status) })
                }
                Err(failure) => {
                    Err(NotReached { lines: failure.lines(&target), code: crate::proxy::sysexit(failure.last()) })
                }
            }
        }
        Transport::Node { .. } => Err(NotReached {
            lines: vec!["a node:// destination is reached through its pair, not here".into()],
            code: sysexits::EX_USAGE,
        }),
        Transport::Direct => {
            if podssh_relay::open::offline() {
                return Err(NotReached {
                    lines: vec![format!(
                        "{} is set, so podssh does not connect anywhere",
                        podssh_relay::open::OFFLINE_ENV
                    )],
                    code: sysexits::EX_UNAVAILABLE,
                });
            }
            let rounds = resolved.connection_attempts.max(1);
            for round in 1..=rounds {
                if round > 1 {
                    let wait = podssh_relay::open::backoff(round - 1);
                    log.info(&format!("retrying in {:.1} s (attempt {round} of {rounds})", wait.as_secs_f32()));
                    tokio::time::sleep(wait).await;
                }
                log.verbose(&format!("connecting to {target} directly"));
                let dialled = podssh_ws::dial::dial(
                    &first.host,
                    first.port,
                    &ProxyChoice::FromEnvironment,
                    podssh_relay::open::CONNECT_TIMEOUT,
                )
                .await;
                match dialled {
                    Ok(tcp) => {
                        let _ = tcp.set_nodelay(true);
                        return Ok(Reached { stream: Box::new(tcp), relay: None });
                    }
                    Err(e) => log.error(&format!("could not connect to {target}: {e}")),
                }
            }
            Err(NotReached { lines: Vec::new(), code: sysexits::EX_UNAVAILABLE })
        }
    }
}
