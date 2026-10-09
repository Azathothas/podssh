//! The client of the iroh road (T-163): a connection to a node by the
//! address of its ticket, a session of the resumable layer on a stream of
//! it, and a new stream, or a new connection, for each lost link.

use std::time::Duration;

use iroh::endpoint::{ConnectError, ConnectingError, Connection, ConnectionError, VarInt};
use iroh::{Endpoint, EndpointAddr};
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{Ask, OsEntropy, Settings};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::allow::{REFUSED, REFUSED_REASON};
use crate::stream::{open_session, Stream};

/// How long a connection to a node may take, its handshake included.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(30);
/// How long a connection whose link failed may take to say why it closed.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

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
    addr: EndpointAddr,
    connection: Mutex<Option<Connection>>,
}

impl Dialer {
    pub fn new(endpoint: Endpoint, addr: EndpointAddr) -> Dialer {
        Dialer { endpoint, addr, connection: Mutex::new(None) }
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
        let connecting = self.endpoint.connect(self.addr.clone(), crate::ALPN);
        let connection = match tokio::time::timeout(CONNECT_LIMIT, connecting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(e)) if connect_refused(&e) => return Err(Failure::Refused),
            Ok(Err(e)) => return Err(Failure::Failed(format!("no connection to the node: {e}"))),
            Err(_) => {
                return Err(Failure::Failed(format!("no connection to the node within {} s", CONNECT_LIMIT.as_secs())))
            }
        };
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
}

/// Carry `app` to the node of `dialer`: the first link and the layer's
/// handshake on it, then a new link after each lost one, until the session
/// ends. `note` hears each step of the session across links.
pub async fn carry<A, N>(dialer: &Dialer, app: A, settings: Settings, note: N) -> Result<Outcome, Failure>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    let first = dialer.link().await?;
    let client = match client::start(first, Ask::New, settings, &mut OsEntropy).await {
        Ok(client) => client,
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
