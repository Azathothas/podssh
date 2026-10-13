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
//!
//! `~C` (T-291) adds a forward to a running session with the same reading
//! of its spec and the same listeners, and its `-KL` and `-KD` close them.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use podssh_ssh::escape_command::{Commands, Forwarder, Made};
use podssh_ssh::local::{Accepted, Listen, Listening, LocalForward};
use podssh_ssh::{Log, RemoteForward, EXIT_FAILURE};
use tokio::sync::watch;

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
                listeners.push(Arc::new(Tcp::new(listener)));
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
        Ok(listener) => Ok(Arc::new(Socket {
            listener: tokio::sync::Mutex::new(Some(listener)),
            path: path.to_string(),
            log: log.clone(),
            closing: watch::channel(false).0,
        })),
        Err((_, line)) => {
            // pipe's words name its own ways with no listener.
            let line = line.split("; this host refuses the listener").next().unwrap_or(&line).to_string();
            Err((EXIT_FAILURE, format!("{}: {line}; {INSTEAD}", spec.shown)))
        }
    }
}

/// The error of an accept on a listener that `~C` closed.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "the listener is closed")
}

/// A TCP listener: each client's address is the channel's originator. `~C`
/// closes it: the socket goes once no accept holds it.
struct Tcp {
    listener: std::sync::Mutex<Option<Arc<tokio::net::TcpListener>>>,
    at: Option<SocketAddr>,
    closing: watch::Sender<bool>,
}

impl Tcp {
    fn new(listener: tokio::net::TcpListener) -> Tcp {
        let at = listener.local_addr().ok();
        Tcp { listener: std::sync::Mutex::new(Some(Arc::new(listener))), at, closing: watch::channel(false).0 }
    }
}

impl Listen for Tcp {
    fn accept(&self) -> Pin<Box<dyn Future<Output = io::Result<Accepted>> + Send + '_>> {
        Box::pin(async move {
            // Before the listener is taken: a close from then on ends the wait.
            let mut closing = self.closing.subscribe();
            let listener = self.listener.lock().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(closed)?;
            let (stream, from) = tokio::select! {
                accepted = listener.accept() => accepted?,
                _ = closing.wait_for(|c| *c) => return Err(closed()),
            };
            let _ = stream.set_nodelay(true);
            let (read, write) = stream.into_split();
            Ok(Accepted { read: Box::new(read), write: Box::new(write), from: Some(from) })
        })
    }

    fn place(&self) -> Option<Listening> {
        self.at.map(Listening::Tcp)
    }

    fn close(&self) -> bool {
        self.listener.lock().unwrap_or_else(|e| e.into_inner()).take();
        self.closing.send_replace(true);
        true
    }

    fn closed(&self) -> bool {
        *self.closing.borrow()
    }
}

/// A socket of `podssh pipe`'s listener, which closes a client of another
/// user itself. `~C` closes it: the socket and its file go once no accept
/// holds it.
struct Socket {
    listener: tokio::sync::Mutex<Option<Listener>>,
    path: String,
    log: Arc<Log>,
    closing: watch::Sender<bool>,
}

impl Listen for Socket {
    fn accept(&self) -> Pin<Box<dyn Future<Output = io::Result<Accepted>> + Send + '_>> {
        Box::pin(async move {
            let mut closing = self.closing.subscribe();
            let mut guard = tokio::select! {
                guard = self.listener.lock() => guard,
                _ = closing.wait_for(|c| *c) => return Err(closed()),
            };
            let log = self.log.clone();
            let mut say = |line: &str| log.verbose(line);
            let accepted = match guard.as_mut() {
                Some(listener) => tokio::select! {
                    end = listener.accept(&mut say) => Some(end),
                    _ = closing.wait_for(|c| *c) => None,
                },
                None => None,
            };
            match accepted {
                Some(end) => {
                    let end = end?;
                    Ok(Accepted { read: end.read, write: end.write, from: None })
                }
                None => {
                    *guard = None;
                    Err(closed())
                }
            }
        })
    }

    fn place(&self) -> Option<Listening> {
        Some(Listening::Path(self.path.clone()))
    }

    fn close(&self) -> bool {
        self.closing.send_replace(true);
        // With no accept waiting, the socket goes now; else that accept
        // drops it.
        if let Ok(mut listener) = self.listener.try_lock() {
            *listener = None;
        }
        true
    }

    fn closed(&self) -> bool {
        *self.closing.borrow()
    }
}

/// What `~C` asks of `podssh ssh` (T-291): a spec of `-L`, `-D` or `-R`
/// read as the command line reads it, and the listeners of `-L` and `-D`
/// made as those of the command line are, after the same probe.
pub fn command_line(gateway_ports: bool, log: Arc<Log>) -> Commands {
    Commands(Arc::new(EscapeForwards { gateway_ports, log }))
}

struct EscapeForwards {
    gateway_ports: bool,
    log: Arc<Log>,
}

impl Forwarder for EscapeForwards {
    fn local(&self, spec: &str, dynamic: bool) -> Made<'_> {
        let spec = if dynamic { local_spec::dynamic(spec) } else { local_spec::local(spec) };
        Box::pin(async move {
            let spec = spec?;
            let mut forwards = listeners(std::slice::from_ref(&spec), self.gateway_ports, &self.log)
                .await
                .map_err(|(_, line)| line)?;
            forwards.pop().ok_or_else(|| "no listener was made".to_string())
        })
    }

    fn remote(&self, spec: &str) -> Result<RemoteForward, String> {
        super::forward::parse_remote(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `~C -KL` closes a listener (T-291): its accept ends, said as closed,
    /// and its port takes no connection after it.
    #[tokio::test]
    async fn a_closed_listener_takes_no_connection() {
        let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let at = bound.local_addr().expect("its address");
        let tcp = Arc::new(Tcp::new(bound));
        assert_eq!(tcp.place(), Some(Listening::Tcp(at)));
        let waiting = tokio::spawn({
            let tcp = tcp.clone();
            async move { tcp.accept().await.err().map(|e| e.kind()) }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!tcp.closed());
        assert!(tcp.close() && tcp.closed());
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), waiting).await;
        assert_eq!(ended.expect("the accept ended").expect("no panic"), Some(io::ErrorKind::NotConnected));
        assert!(tcp.accept().await.is_err(), "a closed listener took a connection");
        assert!(tokio::net::TcpStream::connect(at).await.is_err(), "the port still listens");
    }

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
