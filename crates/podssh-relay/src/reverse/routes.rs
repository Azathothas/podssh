//! A node that offers several TCP services, each under its route (T-089).
//! Each session runs the end-to-end channel, whose operator names a route
//! in its encrypted proof; once its key is let in, the node checks that the
//! key may use that route, and only then dials the route's target. A target
//! with no route is the one that an operator who names none reaches. A
//! roost's targets are each a standard sshd, checked at each dial (T-166).
//! An exit node (T-431) dials a target that the operator names too, by the
//! binary's [`ExitDial`], which decides who may and which address. A grant
//! used once (T-226) that named the route stands for the key's own line.
//! The node's shares (T-433) are routes too, which [`Shared`] reads again
//! for each session, so that one added while the node runs is reached at
//! the next session and one removed is refused; a route of the command line
//! wins over a share of its name.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::DuplexStream;
use tokio::net::TcpStream;

use super::framing::SessionId;
use super::node::{Admit, Handler, Opening, NO_ROOM};
use super::tcp::dial_target;
use crate::e2e::ends::{serve_asked, Node, NO_EXIT};
use crate::e2e::{Ask, Refusal};
use crate::identity::PublicKey;

/// Each direction of the pipe between a session and its channel.
const PIPE: usize = 256 * 1024;

/// One target of the node: its route, or none for the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub name: Option<String>,
    pub host: String,
    pub port: u16,
}

/// Whether a key may use a named route: `Err` is why not, for the node's
/// log.
pub type Grant = dyn Fn(&PublicKey, &str) -> Result<(), String> + Send + Sync;

/// The node's shares now (T-433), each a route by its name: read again for
/// each session that names a route of no other target.
pub type Shared = dyn Fn() -> Vec<Route> + Send + Sync;

/// An exit's dial of the target that the operator `key` named (T-431): the
/// connection, or the refusal, whose words the operator gets.
pub type ExitDial =
    dyn Fn(PublicKey, String, u16) -> Pin<Box<dyn Future<Output = Result<TcpStream, Refusal>> + Send>> + Send + Sync;

/// The routes of a node, who may use each, and the bound on each dial.
#[derive(Clone)]
pub struct Routes {
    pub routes: Arc<Vec<Route>>,
    pub grant: Arc<Grant>,
    pub timeout: Duration,
    /// Each target is a standard sshd, whose version line comes first.
    pub sshd: bool,
    /// The node's egress (T-431): none, and an exit's target is refused.
    pub exit: Option<Arc<ExitDial>>,
    /// The node's shares (T-433): none, and only the routes above.
    pub shared: Option<Arc<Shared>>,
}

impl Routes {
    /// The target of what the operator `key` asked: refused when the node
    /// has no such route or the key may not use it, with the same words for
    /// both, so that an operator learns no route that it may not use; an
    /// exit's target goes to the node's egress, when it lends one.
    pub async fn open(&self, key: &PublicKey, ask: &Ask) -> Result<TcpStream, Refusal> {
        self.open_with(key, ask, || true).await
    }

    /// [`Routes::open`], with `admit` asked once the route and the key's
    /// grant passed, before the dial: `false` refuses with the budget's
    /// words. An exit's target asks it before the exit's own check.
    pub async fn open_with(
        &self,
        key: &PublicKey,
        ask: &Ask,
        admit: impl FnOnce() -> bool,
    ) -> Result<TcpStream, Refusal> {
        let no_room = || Refusal::Other(NO_ROOM.to_string());
        let route = match ask {
            Ask::Exit { host, port } => {
                let Some(exit) = &self.exit else { return Err(Refusal::Other(NO_EXIT.into())) };
                if !admit() {
                    return Err(no_room());
                }
                return exit(*key, host.clone(), *port).await;
            }
            Ask::Route(name) => Some(name.as_str()),
            Ask::Target => None,
        };
        let refused = || match route {
            Some(name) => Refusal::Other(format!("this key may not use the route {name} of the node")),
            // An exit with no TARGET of its own (T-431).
            None if self.routes.is_empty() => {
                Refusal::Other("this node has no target of its own: it is an exit, so name a target through it".into())
            }
            None => Refusal::Other("the node has a target for each route only: name one, as NAME/ROUTE".into()),
        };
        let fixed = self.routes.iter().find(|r| r.name.as_deref() == route).cloned();
        // A share of that name, read now, where the command line has none.
        let target = match (fixed, route, &self.shared) {
            (Some(target), _, _) => target,
            (None, Some(name), Some(shared)) => {
                shared().into_iter().find(|r| r.name.as_deref() == Some(name)).ok_or_else(refused)?
            }
            _ => return Err(refused()),
        };
        // A grant used once named this route already, and its issuer may use
        // it (T-226): the key needs no line of its own.
        if let (Some(name), false) = (route, crate::e2e::ends::granted()) {
            (self.grant)(key, name).map_err(|_| refused())?;
        }
        if !admit() {
            return Err(no_room());
        }
        dial_target(&target.host, target.port, self.timeout, self.sshd).await.map_err(Refusal::NoTarget)
    }
}

/// A handler whose sessions run the channel, and reach the target of the
/// route that each operator named.
pub struct Routed {
    routes: Routes,
    node: Node,
}

impl Routed {
    pub fn new(routes: Routes, node: Node) -> Routed {
        Routed { routes, node }
    }
}

impl Handler for Routed {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let (routes, node) = (self.routes.clone(), self.node.clone());
        // A handover finds the channel by the layer's id of its session (T-668).
        tokio::spawn(crate::e2e::hold::holding(async move {
            serve_asked(theirs, &node, move |key, ask: Ask| async move { routes.open(&key, &ask).await }).await;
        }));
        Box::pin(async move { Ok(ours) })
    }

    /// The client counts against the layer's budget once the channel let
    /// its key in and its route passed, as [`super::E2e`]'s does: a visitor
    /// with no key, or a route refused, never takes the room of a session,
    /// now that each node of the channel serves its shares through routes
    /// (T-433).
    fn open_admitted(&self, _id: SessionId, admit: Admit) -> Opening<DuplexStream> {
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let (routes, node) = (self.routes.clone(), self.node.clone());
        // A handover finds the channel by the layer's id of its session (T-668).
        tokio::spawn(crate::e2e::hold::holding(async move {
            let open = move |key: PublicKey, ask: Ask| async move { routes.open_with(&key, &ask, admit).await };
            serve_asked(theirs, &node, open).await;
        }));
        Box::pin(async move { Ok(ours) })
    }

    /// Each session that the channel lets in gets the seed of its tokens of
    /// one leg, registered in `frames` (T-615).
    fn registers(&self, frames: Option<crate::e2e::legs::Frames>) {
        self.node.leases.attach(frames);
    }

    fn spent(&self, digest: &str) {
        self.node.leases.spent(digest);
    }
}
