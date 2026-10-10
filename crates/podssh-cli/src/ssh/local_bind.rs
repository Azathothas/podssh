//! The listeners of `-L` and `-D` (T-038), bound before anything connects:
//! the bind and the listen are the probe of the operator's ruling of
//! 2026-10-08. A listener that cannot be made refuses the run, with the
//! system's words and `-W HOST:PORT`, which needs none (255);
//! `PODSSH_LISTEN=no` refuses each (78), as for `podssh pipe` and
//! `podssh agent`.
//!
//! A port with no address listens on loopback, 127.0.0.1 and ::1, or with
//! `-g` on each address, 0.0.0.0 and ::; `localhost` is loopback, and `""`
//! and `*` are each address, as OpenSSH reads them. One of the two may fail,
//! not both. A socket path is `podssh pipe`'s `unix-listen:`: mode 0600, for
//! this user's programs only, and a socket that nobody serves is removed
//! first.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use podssh_ssh::local::{Accepted, Listen, LocalForward};
use podssh_ssh::{Log, EXIT_FAILURE};

use super::local_spec::{self, LocalSpec};
use crate::pipe::address::Address;
use crate::pipe::listen::Listener;

/// What carries one connection with no listener, for a refusal.
const INSTEAD: &str = "-W HOST:PORT carries one connection with no listener";

/// Each spec's listeners, or the exit code and the line of the first that
/// could not listen.
pub async fn listeners(
    specs: &[LocalSpec],
    gateway_ports: bool,
    log: &Arc<Log>,
) -> Result<Vec<LocalForward>, (i32, String)> {
    if let Err(refusal) = crate::pipe::listen::allowed() {
        return Err((refusal.code, format!("{}: {}", specs[0].shown, refusal.message)));
    }
    let mut forwards = Vec::new();
    for spec in specs {
        let listeners = match &spec.listen {
            local_spec::Listen::Port { bind, port } => ports(spec, bind.as_deref(), *port, gateway_ports, log).await?,
            local_spec::Listen::Path(path) => vec![socket(spec, path, log).await?],
        };
        forwards.push(LocalForward { shown: spec.shown.clone(), target: spec.target.clone(), listeners });
    }
    Ok(forwards)
}

/// The addresses of a port, as OpenSSH's `channel_fwd_bind_addr` chooses
/// them for a client.
fn addresses(bind: Option<&str>, gateway_ports: bool) -> Vec<&str> {
    match bind {
        None if gateway_ports => vec!["0.0.0.0", "::"],
        None | Some("localhost") => vec!["127.0.0.1", "::1"],
        Some("" | "*") => vec!["0.0.0.0", "::"],
        Some(other) => vec![other],
    }
}

async fn ports(
    spec: &LocalSpec,
    bind: Option<&str>,
    port: u16,
    gateway_ports: bool,
    log: &Arc<Log>,
) -> Result<Vec<Arc<dyn Listen>>, (i32, String)> {
    let mut listeners: Vec<Arc<dyn Listen>> = Vec::new();
    let mut failed = Vec::new();
    let mut at = Vec::new();
    for address in addresses(bind, gateway_ports) {
        match tokio::net::TcpListener::bind((address, port)).await {
            Ok(listener) => {
                at.push(
                    listener.local_addr().map_or_else(|_| podssh_ws::dial::authority(address, port), |a| a.to_string()),
                );
                listeners.push(Arc::new(Tcp(listener)));
            }
            Err(e) => failed.push((podssh_ws::dial::authority(address, port), e)),
        }
    }
    if listeners.is_empty() {
        let (address, e) = failed.into_iter().next().expect("one address at least");
        let instead = if e.kind() == io::ErrorKind::PermissionDenied { "; this host refuses the listener" } else { "" };
        return Err((EXIT_FAILURE, format!("{}: cannot listen on {address}: {e}{instead}; {INSTEAD}", spec.shown)));
    }
    for (address, e) in failed {
        log.verbose(&format!("{}: not on {address}: {e}", spec.shown));
    }
    let loopback = (bind.is_none() && !gateway_ports) || bind == Some("localhost") || is_loopback(bind);
    let line = format!("{}: listening on {}", spec.shown, at.join(" and "));
    if loopback {
        log.verbose(&format!("{line}: each user of this host can connect"));
    } else {
        log.info(&format!("{line}: other hosts can connect, as each user of this host can"));
    }
    Ok(listeners)
}

fn is_loopback(bind: Option<&str>) -> bool {
    bind.and_then(|b| b.parse::<std::net::IpAddr>().ok()).is_some_and(|ip| ip.is_loopback())
}

async fn socket(spec: &LocalSpec, path: &str, log: &Arc<Log>) -> Result<Arc<dyn Listen>, (i32, String)> {
    let said = log.clone();
    let shown = spec.shown.clone();
    let mut say = move |line: &str| said.verbose(&format!("{shown}: {line}"));
    match Listener::bind(&Address::UnixListen(path.to_string()), &mut say).await {
        Ok(listener) => Ok(Arc::new(Socket { listener: tokio::sync::Mutex::new(listener), log: log.clone() })),
        Err((_, line)) => {
            // pipe's words name its own ways with no listener.
            let line = line.split("; this host refuses the listener").next().unwrap_or(&line).to_string();
            Err((EXIT_FAILURE, format!("{}: {line}; {INSTEAD}", spec.shown)))
        }
    }
}

/// A TCP listener: each client's address is the channel's originator.
struct Tcp(tokio::net::TcpListener);

impl Listen for Tcp {
    fn accept(&self) -> Pin<Box<dyn Future<Output = io::Result<Accepted>> + Send + '_>> {
        Box::pin(async move {
            let (stream, from) = self.0.accept().await?;
            let _ = stream.set_nodelay(true);
            let (read, write) = stream.into_split();
            Ok(Accepted { read: Box::new(read), write: Box::new(write), from: Some(from) })
        })
    }
}

/// A socket of `podssh pipe`'s listener, which closes a client of another
/// user itself.
struct Socket {
    listener: tokio::sync::Mutex<Listener>,
    log: Arc<Log>,
}

impl Listen for Socket {
    fn accept(&self) -> Pin<Box<dyn Future<Output = io::Result<Accepted>> + Send + '_>> {
        Box::pin(async move {
            let mut listener = self.listener.lock().await;
            let log = self.log.clone();
            let end = listener.accept(&mut |line: &str| log.verbose(line)).await?;
            Ok(Accepted { read: end.read, write: end.write, from: None })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_addresses_of_a_port_follow_openssh() {
        assert_eq!(addresses(None, false), ["127.0.0.1", "::1"]);
        assert_eq!(addresses(None, true), ["0.0.0.0", "::"]);
        assert_eq!(addresses(Some("localhost"), true), ["127.0.0.1", "::1"]);
        assert_eq!(addresses(Some(""), false), ["0.0.0.0", "::"]);
        assert_eq!(addresses(Some("*"), false), ["0.0.0.0", "::"]);
        assert_eq!(addresses(Some("192.0.2.7"), false), ["192.0.2.7"]);
    }
}
