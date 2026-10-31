//! The client of the iroh road (T-163): a connection to a node by the
//! address of its ticket, a session of the resumable layer on a stream of
//! it, and a new stream, or a new connection, for each lost link. When the
//! ticket's relay does not reach the node, the node's record of pkarr names
//! where it is now (T-350, [`crate::pkarr`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{ConnectError, ConnectingError, Connection, ConnectionError, VarInt};
use iroh::{Endpoint, EndpointAddr, RelayUrl};
use n0_future::StreamExt;
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{Ask, Hearing, OsEntropy, Settings};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::allow::{REFUSED, REFUSED_REASON};
use crate::pkarr::Finder;
use crate::stream::{open_session, Stream};

/// How long a connection to a node may take, its handshake included.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(30);
/// How long the ticket's relay has to reach the node before its record is
/// asked: a relay that holds the node answers in a few round trips through
/// the proxy; one that does not drops the packets with no word.
pub const FIND_AFTER: Duration = Duration::from_secs(10);
/// How long a connection whose link failed may take to say why it closed.
const CLOSE_WAIT: Duration = Duration::from_secs(2);
/// What `-v` says at the end of a session that no direct path carried, and
/// of one that a direct path carried at some time (T-335).
pub const RELAY_ONLY: &str = "the relay carried each byte of the session";
pub const WENT_DIRECT: &str = "a direct path carried the session";

/// Why no link was had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The node refused this client's key: no other attempt gets in.
    Refused,
    /// Anything else, which another attempt may get past.
    Failed(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Refused => f.write_str(REFUSED_REASON),
            Failure::Failed(why) => f.write_str(why),
        }
    }
}

/// The links of one session to one node.
pub struct Dialer {
    endpoint: Endpoint,
    /// The ticket's address, and the one dialled: the ticket's, with the
    /// relay of the node's record once a lookup found one.
    ticket: EndpointAddr,
    addr: std::sync::Mutex<EndpointAddr>,
    connection: Mutex<Option<Connection>>,
    /// Whether a connection was had, and whether a direct path carried one.
    linked: AtomicBool,
    direct: Arc<AtomicBool>,
    /// The way to the node's record, if any; whether it was asked before
    /// the first dial; and the relay that it named, once a connection was
    /// had after it named one that the ticket lacks.
    finder: Option<Finder>,
    looked: AtomicBool,
    moved: std::sync::Mutex<Option<RelayUrl>>,
}

impl Dialer {
    pub fn new(endpoint: Endpoint, addr: EndpointAddr) -> Dialer {
        Dialer {
            endpoint,
            ticket: addr.clone(),
            addr: std::sync::Mutex::new(addr),
            connection: Mutex::new(None),
            linked: AtomicBool::new(false),
            direct: Arc::default(),
            finder: None,
            looked: AtomicBool::new(false),
            moved: std::sync::Mutex::new(None),
        }
    }

    /// With `finder`, which asks for the node's record when the ticket's
    /// relay does not reach the node (T-350).
    pub fn finding(mut self, finder: Finder) -> Dialer {
        self.finder = Some(finder);
        self
    }

    /// The node's ticket at the relay that its record named, once a
    /// connection was had there and the ticket names another: the ticket to
    /// give next time.
    pub fn moved(&self) -> Option<String> {
        let relay = lock(&self.moved).clone()?;
        Some(crate::ticket::format(&EndpointAddr::new(self.ticket.id).with_relay_url(relay)))
    }

    /// Which path carried the session, in words for `-v`: [`WENT_DIRECT`]
    /// once a direct path was the one in use, else [`RELAY_ONLY`]; nothing
    /// before a connection was had.
    pub fn path(&self) -> Option<&'static str> {
        match (self.linked.load(Ordering::SeqCst), self.direct.load(Ordering::SeqCst)) {
            (false, _) => None,
            (true, true) => Some(WENT_DIRECT),
            (true, false) => Some(RELAY_ONLY),
        }
    }

    /// A new link: a stream on the connection while it lives, else on a new
    /// connection.
    pub async fn link(&self) -> Result<Stream, Failure> {
        let mut slot = self.connection.lock().await;
        if let Some(connection) = slot.as_ref() {
            match connection.close_reason() {
                Some(reason) if refused(&reason) => return Err(Failure::Refused),
                Some(_) => {}
                None => {
                    if let Ok(stream) = open_session(connection).await {
                        return Ok(stream);
                    }
                }
            }
        }
        let connection = self.connect().await?;
        self.linked.store(true, Ordering::SeqCst);
        watch_paths(&connection, self.direct.clone());
        let stream = open_session(&connection).await;
        *slot = Some(connection);
        stream.map_err(|e| Failure::Failed(format!("no stream to the node: {e}")))
    }

    /// Whether the node refused this client, as the close of the connection
    /// says after a link failed; it may take a moment to come.
    pub async fn refused(&self) -> bool {
        let slot = self.connection.lock().await;
        let Some(connection) = slot.as_ref() else { return false };
        let reason = match connection.close_reason() {
            Some(reason) => reason,
            None => match tokio::time::timeout(CLOSE_WAIT, connection.closed()).await {
                Ok(reason) => reason,
                Err(_) => return false,
            },
        };
        refused(&reason)
    }

    /// Close the connection, if there is one.
    pub async fn close(&self) {
        if let Some(connection) = self.connection.lock().await.take() {
            connection.close(VarInt::from(0u32), b"the session ended");
        }
    }

    /// A new connection to the node. With no finder, the address has
    /// [`CONNECT_LIMIT`]. With one, the ticket's relay has [`FIND_AFTER`]
    /// first (none, when it did not answer `/ping`), then the node's record
    /// is asked, and the dial goes on with the relay that it names too: iroh
    /// sends to each relay of the address until one path is chosen.
    async fn connect(&self) -> Result<Connection, Failure> {
        let Some(finder) = &self.finder else { return self.dial(CONNECT_LIMIT).await };
        if finder.first && !self.looked.swap(true, Ordering::SeqCst) {
            let host = finder.server.host();
            (finder.say)(format!("the ticket's relay did not answer; asking the node's record at {host}"));
            let found = self.find(finder).await;
            return self.after_find(found, CONNECT_LIMIT).await;
        }
        let why = match self.dial(FIND_AFTER).await {
            Err(Failure::Failed(why)) => why,
            other => return other,
        };
        (finder.say)(format!("{why}; asking the node's record at {}", finder.server.host()));
        let found = self.find(finder).await;
        self.after_find(found, CONNECT_LIMIT.saturating_sub(FIND_AFTER)).await
    }

    /// The dial after a lookup, within `limit`: the relay that the record
    /// named is kept once it carried a connection, and a failure says what
    /// the lookup found.
    async fn after_find(&self, found: Found, limit: Duration) -> Result<Connection, Failure> {
        match self.dial(limit).await {
            Ok(connection) => {
                if let Found::Moved(relay) = found {
                    *lock(&self.moved) = Some(relay);
                }
                Ok(connection)
            }
            Err(Failure::Failed(why)) => Err(Failure::Failed(format!("{why} ({})", found.said()))),
            Err(refused) => Err(refused),
        }
    }

    /// One dial of the address that the dialer has, within `limit`.
    async fn dial(&self, limit: Duration) -> Result<Connection, Failure> {
        let addr = lock(&self.addr).clone();
        let connecting = self.endpoint.connect(addr, crate::ALPN);
        match tokio::time::timeout(limit, connecting).await {
            Ok(Ok(connection)) => Ok(connection),
            Ok(Err(e)) if connect_refused(&e) => Err(Failure::Refused),
            Ok(Err(e)) => Err(Failure::Failed(format!("no connection to the node: {e}"))),
            Err(_) => Err(Failure::Failed(format!("no connection to the node within {} s", limit.as_secs()))),
        }
    }

    /// Ask for the node's record: a relay that it names and the ticket does
    /// not joins the address that is dialled, in place of one that an
    /// earlier lookup named.
    async fn find(&self, finder: &Finder) -> Found {
        let host = finder.server.host().to_string();
        let found = match finder.find(&self.ticket.id).await {
            Ok(Some(record)) => {
                let new: Vec<RelayUrl> =
                    record.relays.iter().filter(|r| !self.ticket.relay_urls().any(|t| t == *r)).cloned().collect();
                match new.first().cloned() {
                    None => Found::Same(host.clone()),
                    Some(relay) => {
                        *lock(&self.addr) = new.into_iter().fold(self.ticket.clone(), EndpointAddr::with_relay_url);
                        Found::Moved(relay)
                    }
                }
            }
            Ok(None) => Found::Nothing(host.clone()),
            Err(why) => Found::Failed(why),
        };
        let said = match &found {
            Found::Moved(relay) => format!("its record at {host} names the home relay {relay}; dialling it too"),
            other => other.said(),
        };
        (finder.say)(said);
        found
    }
}

/// What a lookup of the node's record found.
enum Found {
    /// A relay that the ticket lacks.
    Moved(RelayUrl),
    /// The ticket's relay, at this server.
    Same(String),
    /// No record, at this server.
    Nothing(String),
    /// No answer, or one that was refused.
    Failed(String),
}

impl Found {
    fn said(&self) -> String {
        match self {
            Found::Moved(relay) => format!("its record names the home relay {relay}"),
            Found::Same(host) => format!("its record at {host} names the ticket's relay"),
            Found::Nothing(host) => format!("it has no record at {host}"),
            Found::Failed(why) => format!("its record: {why}"),
        }
    }
}

/// The value behind `mutex`, also after a panic elsewhere.
fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Carry `app` to the node of `dialer`: the first link and the layer's
/// handshake on it, then a new link after each lost one, until the session
/// ends. `note` hears each step of the session across links.
pub async fn carry<A, N>(dialer: &Dialer, app: A, settings: Settings, note: N) -> Result<Outcome, Failure>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    carry_heard(dialer, app, settings, note, Arc::default()).await
}

/// [`carry`], with the session's `hearing`, which a notice of the far end's
/// silence reads (T-302).
pub async fn carry_heard<A, N>(
    dialer: &Dialer,
    app: A,
    settings: Settings,
    note: N,
    hearing: Arc<Hearing>,
) -> Result<Outcome, Failure>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    let first = dialer.link().await?;
    let client = match client::start(first, Ask::New, settings, &mut OsEntropy).await {
        Ok(client) => client.with_hearing(hearing),
        Err(_) if dialer.refused().await => return Err(Failure::Refused),
        Err(e) => return Err(Failure::Failed(e.to_string())),
    };
    let connect = |_: &podssh_relay::session::Ended| async move {
        match dialer.link().await {
            Ok(stream) => Next::Link(stream),
            Err(Failure::Refused) => Next::Stop(REFUSED_REASON.to_string()),
            Err(Failure::Failed(why)) => Next::Retry(why),
        }
    };
    let mut entropy = OsEntropy;
    Ok(resume::run(client, app, connect, note, &mut entropy).await)
}

/// Note in `direct` when a direct path is the one that carries the data of
/// `connection`, from its first path to its close.
fn watch_paths(connection: &Connection, direct: Arc<AtomicBool>) {
    let connection = connection.clone();
    tokio::spawn(async move {
        let mut paths = connection.paths_stream();
        while let Some(list) = paths.next().await {
            if list.iter().any(|path| path.is_selected() && path.is_ip()) {
                direct.store(true, Ordering::SeqCst);
            }
        }
    });
}

/// Whether a connection closed because the node refused this client.
fn refused(reason: &ConnectionError) -> bool {
    matches!(reason, ConnectionError::ApplicationClosed(close) if close.error_code == VarInt::from(REFUSED))
}

/// Whether a connection failed in its handshake because the node refused
/// this client.
fn connect_refused(e: &ConnectError) -> bool {
    match e {
        ConnectError::Connection { source, .. } => refused(source),
        ConnectError::Connecting { source: ConnectingError::ConnectionError { source, .. }, .. } => refused(source),
        _ => false,
    }
}
