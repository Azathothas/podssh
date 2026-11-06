//! The node of the road: a GET at its door for as long as it runs, asked
//! again after each hello, after each lost connection with the forward
//! opener's jittered backoff, and each few minutes, so that no proxy holds
//! a quiet request for ever; and each link that a hello asks for, served by
//! the resumable layer's far end, with the sessions kept by one keeper
//! across links, as on the other roads. A new session reaches its target
//! only after the layer's handshake, and the channel above it.
//!
//! Over HTTP/1.1, where each way of a link holds a connection, the door is
//! closed while a link runs, so that the node holds two connections at
//! most, as the operator's ruling Q44 allows a road that a refused upgrade
//! chose; a second client waits for the first link's end. Over HTTP/2 the
//! door and each link are streams of one connection.
//!
//! With the public servers (T-497), the door is at the first server that
//! answers: a server whose door fails sends it to the next, and after a
//! refresh with no link at a later server it goes back to the first, where
//! a client knocks first. A door that waits keeps a free service of Render
//! awake, as each refresh is a request.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::dial::Proto;
use super::exchange::Http;
use super::flow::{self, Opening};
use super::numbered;
use super::paths::{Ends, LinkId, Mode, Secret, HELLO_MAX};
use super::Say;
use crate::session::far as layer;
use crate::session::keep::Keeper;
use crate::session::record::Role;
use crate::session::Settings;

/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// How long the door's GET waits before it is asked again.
pub const DOOR_REFRESH: Duration = Duration::from_secs(240);
/// A GET of the door that failed after this long met a proxy's bound of a
/// quiet request, not a fault: it is asked again at once.
const QUIET: Duration = Duration::from_secs(20);
/// How long a link's id is kept, so that its hello again opens nothing: a
/// client knocks again when the server's answer does not say that the
/// hello went whole, and piping-server-rust 0.18.0 says "halfway
/// disconnected" to a sender whose receiver took it all.
const SEEN_FOR: Duration = Duration::from_secs(120);

/// A node of the road.
pub struct Node {
    /// The pair's key, which names the door and the links.
    pub secret: Arc<Secret>,
    /// The first server, where the node waits while it answers.
    pub http: Arc<Http>,
    /// The servers after it, in order: the node's door moves to the next
    /// when the one before fails, never to two at once (T-497).
    pub fallbacks: Vec<Arc<Http>>,
    pub say: Say,
}

/// Serve the sessions of each link of `node`, for ever, with `keeper`, which
/// another road's far end may share, so that a session resumes on either
/// road; a new session's target comes from `open`, and the replay buffers of
/// all sessions stay within `budget` bytes.
pub async fn serve_kept<A, O, F>(node: Node, settings: Settings, budget: usize, open: O, keeper: Arc<Keeper<A>>)
where
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
    let servers: Vec<Arc<Http>> = std::iter::once(node.http.clone()).chain(node.fallbacks.iter().cloned()).collect();
    // Each server's links that run: a door goes back to the first server
    // only when none runs at the one that it leaves.
    let running: Vec<Arc<()>> = servers.iter().map(|_| Arc::new(())).collect();
    let mut at = 0;
    (node.say)(format!("waiting for clients at the Piping Server {}", servers[at].server()));
    let mut failed: u32 = 0;
    // Over HTTP/1.1, the one link that may run, which the door waits for.
    let one_link = Arc::new(Semaphore::new(1));
    let mut seen: VecDeque<(Instant, LinkId)> = VecDeque::new();
    loop {
        let http = servers[at].clone();
        let door = http.server().path(&node.secret.door());
        let mut held = match http.proto() {
            Some(Proto::H1) => one_link.clone().acquire_owned().await.ok(),
            _ => None,
        };
        let asked = Instant::now();
        match http.get_all(&door, Some(DOOR_REFRESH), HELLO_MAX).await {
            Ok(hello) => {
                failed = 0;
                match node.secret.read_hello(&hello) {
                    Ok((mode, id)) => {
                        seen.retain(|(at, _)| at.elapsed() < SEEN_FOR);
                        if seen.iter().any(|(_, known)| *known == id) {
                            continue;
                        }
                        seen.push_back((Instant::now(), id));
                        // The door's first GET tells the protocol.
                        if held.is_none() && http.proto() == Some(Proto::H1) {
                            held = one_link.clone().try_acquire_owned().ok();
                        }
                        let (secret, say, live) = (node.secret.clone(), node.say.clone(), running[at].clone());
                        let (keeper, open) = (keeper.clone(), open.clone());
                        tokio::spawn(async move {
                            let _held: (Option<OwnedSemaphorePermit>, Arc<()>) = (held, live);
                            let ends = Ends::node(&secret, &id);
                            let Some(link) = open_link(http, &ends, mode, id, &say).await else { return };
                            layer::serve(link, Role::NODE, settings, &keeper, budget, open).await;
                        });
                    }
                    Err(why) => (node.say)(format!("a hello at the door that is not this pair's: {why}")),
                }
            }
            // The refresh: no client in the last minutes. A door at a later
            // server goes back to the first, which a client tries first.
            Err(why) if why.waited => {
                if at > 0 && Arc::strong_count(&running[at]) == 1 {
                    at = 0;
                    (node.say)(format!("waiting for clients at the Piping Server {} again", servers[at].server()));
                }
            }
            Err(_) if asked.elapsed() >= QUIET => failed = 0,
            // Another receiver holds the door: this pair's node before a
            // restart, which goes away.
            Err(why) if at + 1 < servers.len() && why.status != Some(400) => {
                (node.say)(format!(
                    "the door at {}: {why}; waiting at {} instead",
                    http.server(),
                    servers[at + 1].server()
                ));
                // Its links fail as its door did, and resume at the next.
                http.close().await;
                at += 1;
            }
            Err(why) => {
                failed = failed.saturating_add(1);
                let wait = crate::open::backoff(failed);
                (node.say)(format!("the door at {}: {why}; asking again in {} ms", http.server(), wait.as_millis()));
                tokio::time::sleep(wait).await;
                if why.status != Some(400) {
                    at = 0;
                }
            }
        }
    }
}

/// The link of a hello, in its mode; `None`, with a line, when it did not
/// open.
async fn open_link(http: Arc<Http>, ends: &Ends, mode: Mode, id: LinkId, say: &Say) -> Option<flow::Link> {
    let opened = match mode {
        Mode::Streamed => flow::streamed(http, ends).await,
        Mode::Numbered => numbered::open(http, ends).await,
    };
    match opened {
        Ok(link) => Some(link),
        // The client finds the same and asks for numbered pieces.
        Err(Opening::Held(why)) => {
            say(format!("link {}: {why}", id.short()));
            None
        }
        Err(Opening::Failed(why)) => {
            say(format!("link {} did not open: {why}", id.short()));
            None
        }
    }
}
