//! A node that offers several TCP services, each under its route (T-089).
//! Each session runs the end-to-end channel, whose operator names a route
//! in its encrypted proof; once its key is let in, the node checks that the
//! key may use that route, and only then dials the route's target. A target
//! with no route is the one that an operator who names none reaches.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::ProxyChoice;
use tokio::io::DuplexStream;
use tokio::net::TcpStream;

use super::framing::SessionId;
use super::node::{Handler, Opening};
use crate::e2e::ends::{serve_routed, Node};
use crate::e2e::Refusal;
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

/// The routes of a node, who may use each, and the bound on each dial.
#[derive(Clone)]
pub struct Routes {
    pub routes: Arc<Vec<Route>>,
    pub grant: Arc<Grant>,
    pub timeout: Duration,
}

impl Routes {
    /// The target of `route` for the operator `key`: refused when the node
    /// has no such route or the key may not use it, with the same words for
    /// both, so that an operator learns no route that it may not use.
    pub async fn open(&self, key: &PublicKey, route: Option<&str>) -> Result<TcpStream, Refusal> {
        let refused = || match route {
            Some(name) => Refusal::Other(format!("this key may not use the route {name} of the node")),
            None => Refusal::Other("the node has a target for each route only: name one, as NAME/ROUTE".into()),
        };
        let target = self.routes.iter().find(|r| r.name.as_deref() == route).ok_or_else(refused)?;
        if let Some(name) = route {
            (self.grant)(key, name).map_err(|_| refused())?;
        }
        podssh_ws::dial::dial(&target.host, target.port, &ProxyChoice::FromEnvironment, self.timeout)
            .await
            .map_err(|e| Refusal::NoTarget(e.to_string()))
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
        tokio::spawn(async move {
            serve_routed(theirs, &node, move |key, route| async move { routes.open(&key, route.as_deref()).await })
                .await;
        });
        Box::pin(async move { Ok(ours) })
    }
}
