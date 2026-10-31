//! The client of the DERP road: a connection to the node's server, under a
//! key of this run's, and a link of the resumable layer on it; after each
//! lost link a new one, on the connection while it lives, else on a new
//! one. The ticket's server is first; then, for a server of the fleet, the
//! others of the fleet, where a node whose home went away calls the next
//! one home. The node's key, which the client sends to, is the ticket's; the
//! end-to-end channel above the layer checks the node's identity.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use super::conn::{Conn, Setup};
use super::dial::Dial;
use super::key::{Key, Secret};
use super::link::Link;
use super::servers::{self, Server};
use super::ticket::Ticket;
use super::Say;
use crate::session::client::{self, Outcome};
use crate::session::resume::{self, Next, Note};
use crate::session::secret::NoRandom;
use crate::session::{Ask, Ended, Hearing, OsEntropy, Settings};

/// The links of one client to one node.
pub struct Dialer {
    node: Key,
    servers: Vec<Server>,
    dial: Dial,
    secret: Arc<Secret>,
    say: Say,
    /// The connection, and the place of its server in `servers`.
    conn: Mutex<Option<(usize, Conn)>>,
}

impl Dialer {
    /// The dialer of the node of `ticket`, with a key of this run's.
    pub fn new(ticket: &Ticket, dial: Dial, say: Say) -> Result<Dialer, NoRandom> {
        let secret = Arc::new(Secret::random(&mut OsEntropy)?);
        let servers = servers::for_client(&ticket.server);
        Ok(Dialer { node: ticket.derp, servers, dial, secret, say, conn: Mutex::new(None) })
    }

    /// The servers, in the order that this client tries them.
    pub fn servers(&self) -> &[Server] {
        &self.servers
    }

    /// This client's key on the servers, for this run.
    pub fn key(&self) -> Key {
        self.secret.public()
    }

    /// The server of the connection, while one lives.
    pub async fn server(&self) -> Option<Server> {
        let slot = self.conn.lock().await;
        slot.as_ref().filter(|(_, conn)| conn.why_ended().is_none()).map(|(_, conn)| conn.server().clone())
    }

    /// A new link to the node, which it answered: at the server of the
    /// connection while it lives, then at each other server in turn; else
    /// why none answered.
    pub async fn link(&self) -> Result<Link, String> {
        let mut slot = self.conn.lock().await;
        let first = slot.as_ref().map_or(0, |(at, _)| *at);
        let mut missed = Vec::new();
        for turn in 0..self.servers.len() {
            let at = (first + turn) % self.servers.len();
            let live = slot.as_ref().filter(|(on, conn)| *on == at && conn.why_ended().is_none());
            let conn = match live {
                Some((_, conn)) => conn.clone(),
                None => {
                    if let Some((_, old)) = slot.take() {
                        old.close();
                    }
                    match self.connect(at).await {
                        Ok(conn) => {
                            *slot = Some((at, conn.clone()));
                            conn
                        }
                        Err(why) => {
                            missed.push(why);
                            continue;
                        }
                    }
                }
            };
            let link = match conn.open_link(self.node, &mut OsEntropy) {
                Ok(link) => link,
                Err(why) => {
                    missed.push(why);
                    continue;
                }
            };
            match link.opened().await {
                Ok(()) => return Ok(link),
                Err(why) => missed.push(format!("{}: {why}", conn.server())),
            }
        }
        Err(format!("no link to the node: {}", missed.join("; ")))
    }

    async fn connect(&self, at: usize) -> Result<Conn, String> {
        let server = self.servers[at].clone();
        let io = (self.dial)(&server).await?;
        let setup = Setup { secret: self.secret.clone(), serves: false, say: self.say.clone() };
        Conn::start(server, io, setup).await
    }

    /// End the connection, if there is one.
    pub async fn close(&self) {
        if let Some((_, conn)) = self.conn.lock().await.take() {
            conn.close();
        }
    }
}

/// Carry `app` to the node of `dialer`: the first link and the layer's
/// handshake on it, then a new link after each lost one, until the session
/// ends. `note` hears each step of the session across links.
pub async fn carry<A, N>(dialer: &Dialer, app: A, settings: Settings, note: N) -> Result<Outcome, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    carry_heard(dialer, app, settings, note, Arc::default()).await
}

/// [`carry`], with the session's `hearing`, which a notice of the far end's
/// silence reads.
pub async fn carry_heard<A, N>(
    dialer: &Dialer,
    app: A,
    settings: Settings,
    note: N,
    hearing: Arc<Hearing>,
) -> Result<Outcome, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    let first = dialer.link().await?;
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await.map_err(|e| e.to_string())?;
    let client = client.with_hearing(hearing);
    let connect = |_: &Ended| async move {
        match dialer.link().await {
            Ok(link) => Next::Link(link),
            Err(why) => Next::Retry(why),
        }
    };
    Ok(resume::run(client, app, connect, note, &mut OsEntropy).await)
}
