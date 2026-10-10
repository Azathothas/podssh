//! The two ends of the channel as a session runs them. A node answers each
//! operator, checks its key, and only then reaches its target, so a refused
//! operator costs the target no connection and gets none of its bytes. An
//! operator checks the node's key before it proves its own.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

use super::{initiate, respond, Error, Refusal};
use crate::identity::{Identity, PublicKey};

/// Each direction of the pipe between the channel and the stream under it.
const PIPE: usize = 256 * 1024;
/// The bound on a node's dial of its target, within the operator's wait for
/// the verdict.
pub const TARGET_WAIT: Duration = Duration::from_secs(20);

/// Who may reach a node: `Err` is why not, for the node's log; the operator
/// learns only that its key is not let in.
pub type Admit = dyn Fn(&PublicKey) -> Result<(), String> + Send + Sync;

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
        Node { identity, admit: Arc::new(|_: &PublicKey| Ok(())), say }
    }
}

/// Serve one session's channel on `link`, the stream that the layer or the
/// relay carries: the handshake, the operator's key against the node's
/// admission, then the target from `open`, and the bytes between the two.
pub async fn serve_node<L, A, O, F>(link: L, node: &Node, open: O)
where
    L: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
    O: FnOnce() -> F,
    F: Future<Output = Result<A, String>>,
{
    let asked = match respond(link, &node.identity).await {
        Ok(asked) => asked,
        Err(e) => {
            (node.say)(format!("a session ended in the channel's handshake: {e}"));
            return;
        }
    };
    let peer = asked.peer();
    if let Err(why) = (node.admit)(&peer) {
        (node.say)(format!("refused the operator key {peer}: {why}"));
        asked.refuse(Refusal::NotAllowed).await;
        return;
    }
    let target = match tokio::time::timeout(TARGET_WAIT, open()).await {
        Ok(Ok(target)) => target,
        Ok(Err(why)) => {
            (node.say)(format!("the operator key {peer} came in; the target could not be reached: {why}"));
            asked.refuse(Refusal::NoTarget(why)).await;
            return;
        }
        Err(_) => {
            let why = format!("it did not answer within {} s", TARGET_WAIT.as_secs());
            (node.say)(format!("the operator key {peer} came in; the target could not be reached: {why}"));
            asked.refuse(Refusal::NoTarget(why)).await;
            return;
        }
    };
    (node.say)(format!("the operator key {peer} came in"));
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
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let session = async move {
        let offered = initiate(theirs, &identity).await?;
        let node = offered.peer();
        if let Err(why) = check(&node) {
            offered.reject().await;
            return Err(Error::NodeKey(why));
        }
        offered.accept().await?.carry(app).await?;
        Ok(node)
    };
    (ours, session)
}
