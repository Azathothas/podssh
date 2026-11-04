//! The connections of the road in this process (T-321), each host's by its
//! name, its port, the name of its certificate, the trust and the proxy:
//! each connection carries [`STREAMS`] sessions at most, or the fewer that
//! the server's SETTINGS allow, and a session past them opens another. One
//! connection of a host is made at a time, so that sessions that start
//! together share it; each host is made apart, so that the race between
//! relay hosts waits for none. A connection whose sessions ended closes
//! after [`IDLE`], and one that ended goes. A host that took HTTP/1.1 at the
//! cost of a connection is remembered for [`REMEMBERED`].

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use tokio::time::Instant;

use super::dial::{self, Dialed};
use super::{Fallback, IDLE, REMEMBERED, STREAMS};
use crate::client::{ConnectError, RelayStream, WsClientConfig};
use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// The most hosts kept: a run names a few.
const HOSTS: usize = 32;

/// How often a connection looks at its sessions.
const TICK: Duration = Duration::from_secs(1);

/// What one host's connections are kept by.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    host: String,
    port: u16,
    server_name: String,
    trust: Trust,
    proxy: ProxyChoice,
}

impl Key {
    fn of(config: &WsClientConfig) -> Key {
        Key {
            host: config.endpoint.host.clone(),
            port: config.endpoint.port,
            server_name: config.server_name.clone(),
            trust: config.trust.clone(),
            proxy: config.proxy.clone(),
        }
    }
}

/// What a connection's task shares with its [`Conn`].
pub(super) struct Driven {
    open: Arc<AtomicUsize>,
    retired: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Driven {
    /// End the connection, and wait until its TCP is closed.
    pub(super) async fn close(self) {
        self.retired.store(true, Ordering::SeqCst);
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Drive `connection`, HTTP/2's, in a task until it ends, or until it had no
/// session for [`IDLE`]; the task's end closes the TCP.
pub(super) fn drive<F>(connection: F) -> Driven
where
    F: Future<Output = ()> + Send + 'static,
{
    let open = Arc::new(AtomicUsize::new(0));
    let retired = Arc::new(AtomicBool::new(false));
    let (sessions, ended) = (open.clone(), retired.clone());
    let task = tokio::spawn(async move {
        tokio::select! {
            () = connection => {}
            () = idle(sessions) => {}
        }
        ended.store(true, Ordering::SeqCst);
    });
    Driven { open, retired, task }
}

/// Until `open` has been 0 for [`IDLE`].
async fn idle(open: Arc<AtomicUsize>) {
    let mut quiet = Duration::ZERO;
    while quiet < IDLE {
        tokio::time::sleep(TICK).await;
        quiet = if open.load(Ordering::SeqCst) == 0 { quiet + TICK } else { Duration::ZERO };
    }
}

/// One connection of the road, whose SETTINGS offered extended CONNECT.
#[derive(Clone)]
pub(super) struct Conn {
    sender: SendRequest<Bytes>,
    peer: Option<SocketAddr>,
    /// Its sessions now, and the most at once.
    open: Arc<AtomicUsize>,
    most: usize,
    /// Whether a session took it before.
    used: Arc<AtomicBool>,
    /// No session more: it ended, idled out, or went away.
    retired: Arc<AtomicBool>,
    task: tokio::task::AbortHandle,
}

impl Conn {
    /// The connection of `sender`, at `peer`, which `driven` drives, for
    /// `most` sessions at once.
    pub(super) fn of(sender: SendRequest<Bytes>, peer: Option<SocketAddr>, most: usize, driven: Driven) -> Conn {
        let task = driven.task.abort_handle();
        let most = most.clamp(1, STREAMS);
        let used = Arc::new(AtomicBool::new(false));
        Conn { sender, peer, open: driven.open, most, used, retired: driven.retired, task }
    }

    pub(super) fn sender(&self) -> SendRequest<Bytes> {
        self.sender.clone()
    }

    /// The address of its TCP: the relay's, or the proxy's.
    pub(super) fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// No session more on it, as it went away; the sessions on it go on.
    pub(super) fn retire(&self) {
        self.retired.store(true, Ordering::SeqCst);
    }

    fn retired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
    }

    fn room(&self) -> bool {
        !self.retired() && self.open.load(Ordering::SeqCst) < self.most
    }

    fn unused(&self) -> bool {
        self.open.load(Ordering::SeqCst) == 0
    }

    /// A session's place on it, and whether another took it before.
    fn take(&self) -> (Place, bool) {
        self.open.fetch_add(1, Ordering::SeqCst);
        (Place(self.open.clone()), self.used.swap(true, Ordering::SeqCst))
    }

    fn close(&self) {
        self.retire();
        self.task.abort();
    }
}

/// A session's place on a connection, given back as it drops.
pub(super) struct Place(Arc<AtomicUsize>);

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One host's connections, and what the process found of it.
struct Host {
    key: Key,
    /// Held while a session takes a place or makes a connection.
    state: tokio::sync::Mutex<State>,
}

#[derive(Default)]
struct State {
    conns: Vec<Conn>,
    lacks: Option<(Fallback, Instant)>,
}

static KEPT: Mutex<Vec<Arc<Host>>> = Mutex::new(Vec::new());

fn lock() -> MutexGuard<'static, Vec<Arc<Host>>> {
    KEPT.lock().unwrap_or_else(|e| e.into_inner())
}

fn host(key: Key) -> Arc<Host> {
    let mut kept = lock();
    if let Some(found) = kept.iter().find(|h| h.key == key) {
        return found.clone();
    }
    // A host let go keeps its sessions; its connections take no more.
    if kept.len() >= HOSTS {
        kept.remove(0);
    }
    let made = Arc::new(Host { key, state: tokio::sync::Mutex::new(State::default()) });
    kept.push(made.clone());
    made
}

/// What a session gets of the pool.
pub(super) enum Got {
    /// A place on a connection that offers extended CONNECT.
    Place { conn: Conn, place: Place, shared: bool },
    /// A connection whose TLS chose HTTP/1.1, for the upgrade.
    Http1(Box<RelayStream>),
    /// The upgrade on a new connection, and why.
    Fallback(Fallback),
}

/// A place for a session of `config`: on a connection kept, else on a new
/// one; or why the session takes HTTP/1.1.
pub(super) async fn place(config: &WsClientConfig) -> Result<Got, ConnectError> {
    let host = host(Key::of(config));
    let mut state = host.state.lock().await;
    let remembered = state.lacks.as_ref().filter(|(_, at)| at.elapsed() < REMEMBERED).map(|(why, _)| why.clone());
    if let Some(why) = remembered {
        return Ok(Got::Fallback(Fallback::Remembered(Box::new(why))));
    }
    state.lacks = None;
    state.conns.retain(|c| !c.retired());
    if let Some(conn) = state.conns.iter().find(|c| c.room()) {
        let (place, shared) = conn.take();
        return Ok(Got::Place { conn: conn.clone(), place, shared });
    }
    match dial::dial(config).await? {
        Dialed::H2(conn) => {
            let (place, shared) = conn.take();
            state.conns.push(conn.clone());
            Ok(Got::Place { conn, place, shared })
        }
        Dialed::Http1(tls) => Ok(Got::Http1(tls)),
        Dialed::Lacks(why) => {
            state.lacks = Some((why.clone(), Instant::now()));
            Ok(Got::Fallback(why))
        }
    }
}

/// The host of `config` takes HTTP/1.1, for `why`, for [`REMEMBERED`]; its
/// connections with no session close now.
pub(super) async fn remember(config: &WsClientConfig, why: Fallback) {
    let host = host(Key::of(config));
    let mut state = host.state.lock().await;
    state.lacks = Some((why, Instant::now()));
    state.conns.retain(|c| {
        let idle = c.unused();
        if idle {
            c.close();
        }
        !idle
    });
}
