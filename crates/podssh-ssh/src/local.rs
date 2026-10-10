//! `-L` and `-D` (T-038): each connection that a local listener takes goes
//! to the destination over a new channel: `direct-tcpip` to HOST:PORT,
//! `direct-streamlocal@openssh.com` to a socket on the server, or, for
//! `-D`, where its SOCKS request says. The caller binds the listeners
//! before anything connects, as the probe of the operator's ruling of
//! 2026-10-08 asks; this crate binds nothing.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use russh::client::{Handle, Msg};
use russh::{Channel, ChannelOpenFailure};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::handler::Client;
use crate::log::Log;
use crate::socks;

/// How long the server may take to open a channel: a target that does not
/// answer must not hold a local client for ever.
const OPEN_LIMIT: Duration = Duration::from_secs(60);
/// How long a SOCKS client may take to say where it goes.
const SOCKS_LIMIT: Duration = Duration::from_secs(30);

pub type Reader = Box<dyn AsyncRead + Send + Unpin>;
pub type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// A connection that a listener took.
pub struct Accepted {
    pub read: Reader,
    pub write: Writer,
    /// The client's address, which the channel names as its originator; a
    /// Unix socket's client has none.
    pub from: Option<SocketAddr>,
}

/// A listener that the caller bound.
pub trait Listen: Send + Sync {
    /// The next connection.
    fn accept(&self) -> Pin<Box<dyn Future<Output = io::Result<Accepted>> + Send + '_>>;
}

/// Where the connections of a forward go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `direct-tcpip` to HOST:PORT, which the server opens.
    Tcp { host: String, port: u16 },
    /// `direct-streamlocal@openssh.com` to a socket on the server.
    Socket(String),
    /// `-D`: where each SOCKS request says.
    Socks,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Tcp { host, port } => f.write_str(&podssh_ws::dial::authority(host, *port)),
            Target::Socket(path) => write!(f, "the socket {path} of the server"),
            Target::Socks => f.write_str("where each SOCKS request says"),
        }
    }
}

/// One `-L` or `-D`: its listeners and its target; `shown` names it in a
/// line, as `-L 8080:db:5432`.
#[derive(Clone)]
pub struct LocalForward {
    pub shown: String,
    pub target: Target,
    pub listeners: Vec<Arc<dyn Listen>>,
}

impl fmt::Debug for LocalForward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalForward")
            .field("shown", &self.shown)
            .field("target", &self.target)
            .field("listeners", &self.listeners.len())
            .finish()
    }
}

/// `work`, with the forwards served on `handle` meanwhile.
pub async fn alongside<T>(
    handle: &Handle<Client>,
    forwards: &[LocalForward],
    log: &Arc<Log>,
    work: impl Future<Output = T>,
) -> T {
    if forwards.is_empty() {
        return work.await;
    }
    tokio::pin!(work);
    let serving = serve(handle, forwards, log);
    tokio::pin!(serving);
    tokio::select! {
        out = &mut work => out,
        () = &mut serving => work.await,
    }
}

/// Until the connection behind `handle` has ended: what `-N` waits for while
/// its forwards serve, which hold the handle too.
pub async fn closed(handle: &Handle<Client>) {
    while !handle.is_closed() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

type Next<'a> =
    Pin<Box<dyn Future<Output = (&'a LocalForward, &'a Arc<dyn Listen>, io::Result<Accepted>)> + Send + 'a>>;

fn next<'a>(forward: &'a LocalForward, listener: &'a Arc<dyn Listen>) -> Next<'a> {
    Box::pin(async move { (forward, listener, listener.accept().await) })
}

/// Each listener's connections, until no listener is left: a listener whose
/// accept fails is closed with a line. Channels open at the same time.
pub async fn serve(handle: &Handle<Client>, forwards: &[LocalForward], log: &Arc<Log>) {
    let mut accepting: FuturesUnordered<Next> =
        forwards.iter().flat_map(|f| f.listeners.iter().map(move |l| next(f, l))).collect();
    let mut opening = FuturesUnordered::new();
    loop {
        tokio::select! {
            Some((forward, listener, accepted)) = accepting.next() => match accepted {
                Ok(conn) => {
                    accepting.push(next(forward, listener));
                    opening.push(carry(handle, forward, conn, log));
                }
                Err(e) => log.info(&format!("{}: a listener failed and is closed: {e}", forward.shown)),
            },
            Some(()) = opening.next() => {}
            else => break,
        }
    }
}

/// One connection: its channel opened, then its bytes copied both ways in a
/// task of its own, so that a slow one holds no other.
async fn carry(handle: &Handle<Client>, forward: &LocalForward, conn: Accepted, log: &Arc<Log>) {
    let Accepted { mut read, mut write, from } = conn;
    let (target, socks) = match &forward.target {
        Target::Socks => match tokio::time::timeout(SOCKS_LIMIT, socks::read_request(&mut read, &mut write)).await {
            Ok(Ok(request)) => (Target::Tcp { host: request.host, port: request.port }, Some(request.version)),
            Ok(Err(why)) => {
                log.verbose(&format!("{}: a SOCKS client: {why}", forward.shown));
                return;
            }
            Err(_) => {
                log.verbose(&format!(
                    "{}: a SOCKS client asked nothing within {} s",
                    forward.shown,
                    SOCKS_LIMIT.as_secs()
                ));
                return;
            }
        },
        other => (other.clone(), None),
    };
    let channel = match tokio::time::timeout(OPEN_LIMIT, open(handle, &target, from)).await {
        Ok(Ok(channel)) => channel,
        failed => {
            let (why, refusal) = match failed {
                Ok(Err(e)) => (open_failure(&e), refusal_of(&e)),
                _ => (format!("no answer within {} s", OPEN_LIMIT.as_secs()), socks::Refusal::General),
            };
            log.info(&format!("{}: the server could not open {target}: {why}", forward.shown));
            if let Some(version) = socks {
                let _ = socks::answer(&mut write, version, Err(refusal)).await;
            }
            return;
        }
    };
    if let Some(version) = socks {
        if socks::answer(&mut write, version, Ok(())).await.is_err() {
            return;
        }
    }
    log.verbose(&format!("{}: a connection to {target}", forward.shown));
    tokio::spawn(async move {
        let mut local = tokio::io::join(read, write);
        let mut remote = channel.into_stream();
        let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
    });
}

/// The channel to `target`, with the client's address as its originator.
async fn open(
    handle: &Handle<Client>,
    target: &Target,
    from: Option<SocketAddr>,
) -> Result<Channel<Msg>, russh::Error> {
    let (address, port) = from.map_or(("127.0.0.1".to_string(), 0), |a| (a.ip().to_string(), u32::from(a.port())));
    match target {
        Target::Tcp { host, port: to } => {
            handle.channel_open_direct_tcpip(host.clone(), u32::from(*to), address, port).await
        }
        Target::Socket(path) => handle.channel_open_direct_streamlocal(path.clone()).await,
        Target::Socks => unreachable!("a SOCKS request names its target first"),
    }
}

/// The server's reason, as RFC 4254 names it.
fn open_failure(e: &russh::Error) -> String {
    match e {
        russh::Error::ChannelOpenFailure(reason) => match reason {
            ChannelOpenFailure::AdministrativelyProhibited => "administratively prohibited".into(),
            ChannelOpenFailure::ConnectFailed => "connect failed".into(),
            ChannelOpenFailure::UnknownChannelType => "unknown channel type".into(),
            ChannelOpenFailure::ResourceShortage => "resource shortage".into(),
            other => format!("{other:?}"),
        },
        other => crate::run::describe(other),
    }
}

/// The SOCKS5 code of a channel that did not open.
fn refusal_of(e: &russh::Error) -> socks::Refusal {
    match e {
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited) => socks::Refusal::NotAllowed,
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed) => socks::Refusal::Refused,
        _ => socks::Refusal::General,
    }
}

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
