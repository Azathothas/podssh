//! The two ends of the channel as a session runs them. A node answers each
//! operator, checks its key, and only then reaches its target, so a refused
//! operator costs the target no connection and gets none of its bytes. An
//! operator checks the node's key before it proves its own. What the
//! operator asks ([`Ask`]) is a route, or of an exit node a target of its
//! own (T-431), which a node that is no exit refuses.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

use super::{initiate, respond, Ask, Error, Refusal};
use crate::identity::{Identity, PublicKey};

/// Each direction of the pipe between the channel and the stream under it.
const PIPE: usize = 256 * 1024;
/// The bound on a node's dial of its target, within the operator's wait for
/// the verdict.
pub const TARGET_WAIT: Duration = Duration::from_secs(20);

/// Who may reach a node, for what it asked (T-430, T-431): `Err` is why not,
/// for the node's log; the operator learns only that it is not let in.
pub type Admit = dyn Fn(&PublicKey, &Ask) -> Result<(), String> + Send + Sync;

/// The refusal of an exit's target by a node that is no exit.
pub const NO_EXIT: &str = "this node is no exit: it lends no egress (podssh node --exit)";

/// A node's end: its key, who may come in, and where its lines go.
#[derive(Clone)]
pub struct Node {
    pub identity: Arc<Identity>,
    pub admit: Arc<Admit>,
    pub say: Arc<dyn Fn(String) + Send + Sync>,
}

impl Node {
    /// A node that lets in each operator whose key proves itself: the relay's
    /// connect token decided who reaches it.
    pub fn open_to_all(identity: Arc<Identity>, say: Arc<dyn Fn(String) + Send + Sync>) -> Node {
        Node { identity, admit: Arc::new(|_: &PublicKey, _: &Ask| Ok(())), say }
    }
}

/// Serve one session's channel on `link`, the stream that the layer or the
/// relay carries: the handshake, the operator's key against the node's
/// admission, then the target from `open`, and the bytes between the two. A
/// node served so has no routes and is no exit: an operator that names a
/// route, or an exit's target, is refused.
pub async fn serve_node<L, A, O, F>(link: L, node: &Node, open: O)
where
    L: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
    O: FnOnce() -> F,
    F: Future<Output = Result<A, String>>,
{
    serve_routed(link, node, |_, route: Option<String>| async move {
        match route {
            Some(route) => Err(Refusal::Other(format!("this node has no routes, so none named {route}"))),
            None => open().await.map_err(Refusal::NoTarget),
        }
    })
    .await
}

/// [`serve_node`] for a node with routes (T-089): once the operator's key is
/// let in, `open` gets it and the route that it named, and gives the target
/// of that route, or the refusal: a route that the key may not use is the
/// node's refusal, not its target's. Such a node is no exit (T-431).
pub async fn serve_routed<L, A, O, F>(link: L, node: &Node, open: O)
where
    L: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
    O: FnOnce(PublicKey, Option<String>) -> F,
    F: Future<Output = Result<A, Refusal>>,
{
    serve_asked(link, node, move |key, ask: Ask| async move {
        match ask {
            Ask::Exit { .. } => Err(Refusal::Other(NO_EXIT.into())),
            Ask::Route(route) => open(key, Some(route)).await,
            Ask::Target => open(key, None).await,
        }
    })
    .await
}

/// [`serve_routed`] for each ask, an exit's target too (T-431): `open` gets
/// the operator's key, once the admission let it in for what it asked, and
/// the ask, and gives the target or the refusal.
pub async fn serve_asked<L, A, O, F>(link: L, node: &Node, open: O)
where
    L: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
    O: FnOnce(PublicKey, Ask) -> F,
    F: Future<Output = Result<A, Refusal>>,
{
    let asked = match respond(link, &node.identity).await {
        Ok(asked) => asked,
        Err(e) => {
            (node.say)(format!("a session ended in the channel's handshake: {e}"));
            return;
        }
    };
    let peer = asked.peer();
    let ask = asked.ask().clone();
    let to = ask.to_string();
    if let Err(why) = (node.admit)(&peer, &ask) {
        (node.say)(format!("refused the operator key {peer}: {why}"));
        asked.refuse(Refusal::NotAllowed).await;
        return;
    }
    let target = match tokio::time::timeout(TARGET_WAIT, open(peer, ask)).await {
        Ok(Ok(target)) => target,
        Ok(Err(refusal)) => {
            (node.say)(format!("the operator key {peer} came in{to}; refused: {refusal}"));
            asked.refuse(refusal).await;
            return;
        }
        Err(_) => {
            let why = format!("it did not answer within {} s", TARGET_WAIT.as_secs());
            (node.say)(format!("the operator key {peer} came in{to}; the target could not be reached: {why}"));
            asked.refuse(Refusal::NoTarget(why)).await;
            return;
        }
    };
    (node.say)(format!("the operator key {peer} came in{to}"));
    let channel = match asked.admit().await {
        Ok(channel) => channel,
        Err(e) => {
            (node.say)(format!("the session of {peer} ended before it began: {e}"));
            return;
        }
    };
    if let Err(e) = channel.carry(target).await {
        (node.say)(format!("the session of {peer} ended: {e}"));
    }
}

/// The operator's end of one session: `app` carries the session's bytes in
/// plain, and the stream returned goes to the layer, or to the relay's leg.
/// `check` judges the node's key before this end proves its own; its `Err`
/// refuses the node. The future ends with the session, with the node's key.
pub fn operator<A, C>(
    app: A,
    identity: Arc<Identity>,
    check: C,
) -> (DuplexStream, impl Future<Output = Result<PublicKey, Error>> + Send)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: FnOnce(&PublicKey) -> Result<(), String> + Send + 'static,
{
    operator_to(app, identity, check, None)
}

/// [`operator`] to `route` of the node, when one is named (T-089): the word
/// of a route, or of an exit's target (T-431, [`Ask::word`]).
pub fn operator_to<A, C>(
    app: A,
    identity: Arc<Identity>,
    check: C,
    route: Option<String>,
) -> (DuplexStream, impl Future<Output = Result<PublicKey, Error>> + Send)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: FnOnce(&PublicKey) -> Result<(), String> + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let session = async move {
        let offered = initiate(theirs, &identity).await?;
        let node = offered.peer();
        if let Err(why) = check(&node) {
            offered.reject().await;
            return Err(Error::NodeKey(why));
        }
        offered.accept(route.as_deref()).await?.carry(app).await?;
        Ok(node)
    };
    (ours, session)
}
