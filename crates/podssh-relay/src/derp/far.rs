//! The node of the DERP road: a connection to its home server, made again
//! after each loss with the forward opener's jittered backoff, under the
//! node's own key, so that its address stays; and each link that a client
//! opens there served by the resumable layer's far end, with the sessions
//! kept by one keeper across links and connections, as on the iroh road. A
//! new session reaches its target only after its handshake. A node of a list
//! moves home when its home goes away (T-379): after a few failed
//! connections in a row, the first other server of the list that takes one,
//! in the list's order, which a client of the list tries after the ticket's.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use super::conn::{Conn, Setup};
use super::dial::Dial;
use super::key::Secret;
use super::servers::Server;
use super::Say;
use crate::session::keep::Keeper;
use crate::session::record::Role;
use crate::session::{far, Settings};

/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// The failed connections to the home, in a row, after which a node of a
/// list moves: a server that restarts, as a deploy does, costs one or two.
pub const MOVE_AFTER: u32 = 3;

/// What a node hears of a new home: the server. Its key there is the same,
/// so its new ticket differs in the server alone.
pub type Moved = Arc<dyn Fn(&Server) + Send + Sync>;

/// Where a node may move when its home goes away, in the order that it
/// tries them, and what it says of a move.
pub struct Roam {
    pub servers: Vec<Server>,
    pub moved: Moved,
}

impl Roam {
    /// No move: the node calls its home again, for ever.
    pub fn stay() -> Roam {
        Roam { servers: Vec::new(), moved: Arc::new(|_: &Server| {}) }
    }
}

/// A node of the DERP road.
pub struct Node {
    /// The node's key: [`Secret::of_node`], so that its ticket stays.
    pub secret: Arc<Secret>,
    /// Its home.
    pub server: Server,
    pub dial: Dial,
    pub say: Say,
}

/// A connection to the node's home, under its key.
pub async fn connect(node: &Node) -> Result<Conn, String> {
    connect_to(node, &node.server).await
}

/// A connection to `server`, under the node's key.
pub async fn connect_to(node: &Node, server: &Server) -> Result<Conn, String> {
    let io = (node.dial)(server).await?;
    let setup = Setup { secret: node.secret.clone(), serves: true, say: node.say.clone() };
    Conn::start(server.clone(), io, setup).await
}

/// Serve the sessions of each link of `node`, for ever, with a keeper of
/// its own; a new session's target comes from `open`, and the replay
/// buffers of all sessions stay within `budget` bytes.
pub async fn serve<A, O, F>(node: Node, settings: Settings, budget: usize, open: O)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    serve_kept(node, settings, budget, open, keeper).await
}

/// [`serve`] with `keeper`, which another road's far end may share, so that
/// a session resumes on either road.
pub async fn serve_kept<A, O, F>(node: Node, settings: Settings, budget: usize, open: O, keeper: Arc<Keeper<A>>)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    serve_from(node, None, settings, budget, open, keeper).await
}

/// [`serve_kept`], on `first` while it lives: a connection that the caller
/// made already, to say the node's ticket once the node is online.
pub async fn serve_from<A, O, F>(
    node: Node,
    first: Option<Conn>,
    settings: Settings,
    budget: usize,
    open: O,
    keeper: Arc<Keeper<A>>,
) where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    serve_roaming(node, Roam::stay(), first, settings, budget, open, keeper).await
}

/// [`serve_from`], moving home as `roam` says when the home goes away: after
/// [`MOVE_AFTER`] failed connections in a row, the first other server of
/// `roam.servers` that takes a connection is the home, and `roam.moved`
/// hears of it. The node stays there: a home that flaps would move each
/// client again.
pub async fn serve_roaming<A, O, F>(
    mut node: Node,
    roam: Roam,
    first: Option<Conn>,
    settings: Settings,
    budget: usize,
    open: O,
    keeper: Arc<Keeper<A>>,
) where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    // The sweep ends with the keeper, when the node and its sessions end.
    {
        let keeper = Arc::downgrade(&keeper);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                let Some(keeper) = keeper.upgrade() else { return };
                keeper.expire().await;
            }
        });
    }
    let (mut retry, mut failed): (u32, u32) = (0, 0);
    let mut next = first;
    loop {
        let conn = match next.take() {
            Some(conn) => Ok(conn),
            None => connect(&node).await,
        };
        match conn {
            Ok(conn) => {
                (retry, failed) = (0, 0);
                (node.say)(format!("online at the DERP server {} as {}", node.server, conn.key()));
                while let Some(link) = conn.accept().await {
                    let (keeper, open) = (keeper.clone(), open.clone());
                    tokio::spawn(async move {
                        far::serve(link, Role::NODE, settings, &keeper, budget, open).await;
                    });
                }
                let why = conn.why_ended().unwrap_or_else(|| "it closed".to_string());
                (node.say)(format!("the connection to the DERP server {} ended: {why}", node.server));
            }
            Err(why) => {
                failed = failed.saturating_add(1);
                (node.say)(format!("no connection to the DERP server {}: {why}", node.server));
            }
        }
        if failed >= MOVE_AFTER {
            if let Some(conn) = move_home(&mut node, &roam).await {
                (retry, failed) = (0, 0);
                next = Some(conn);
                continue;
            }
        }
        retry = retry.saturating_add(1);
        let wait = crate::open::backoff(retry);
        (node.say)(format!("connecting again in {} ms", wait.as_millis()));
        tokio::time::sleep(wait).await;
    }
}

/// The first server of `roam`, from the top of its list, other than the
/// node's home, that takes a connection: the node's home is then that
/// server, and `roam.moved` hears of it.
async fn move_home(node: &mut Node, roam: &Roam) -> Option<Conn> {
    for server in roam.servers.iter().filter(|server| **server != node.server) {
        match connect_to(node, server).await {
            Ok(conn) => {
                (node.say)(format!("the DERP server {} went away; {server} is the node's home now", node.server));
                node.server = server.clone();
                (roam.moved)(server);
                return Some(conn);
            }
            Err(why) => (node.say)(format!("no connection to the DERP server {server}: {why}")),
        }
    }
    None
}
