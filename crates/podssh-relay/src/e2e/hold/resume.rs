//! A session's channel carried on in the binary that took the node's place
//! (T-668): from the keys and the nonces that the binary before it handed
//! over, between a new pipe to the layer and the target's connection that
//! moved with it. The bytes cut short each way go first: those of the
//! operator to the channel's reading, those of the channel's messages to the
//! layer. The channel holds again for a later handover, as each does.

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

use super::super::channel::Start;
use super::super::ends::Node;
use super::{after, again, register, scoped, ChannelState};
use crate::identity::PublicKey;
use crate::session::SessionId;

/// Each direction of the pipe between the layer and a channel, as the
/// node's handlers make it.
const PIPE: usize = 256 * 1024;

/// The channel of the layer's session `id`, from `bytes` (its
/// [`ChannelState`]), carried on above `target` with `node`'s lines and
/// tokens of one leg: the layer's end of its pipe, which the session's slot
/// holds as its target. Bytes that this binary does not read are refused
/// with why, and nothing starts.
pub fn resume<T>(id: SessionId, bytes: &[u8], target: T, node: &Node) -> Result<DuplexStream, String>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = ChannelState::decode(bytes).map_err(|e| e.to_string())?;
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let mut channel = again(theirs, &state)?;
    let peer = PublicKey(state.peer);
    if state.net {
        // The documents of this binary: the one before held the same file.
        if let Some(docs) = super::super::net::installed() {
            channel.set_net(docs, peer);
        }
    }
    let lease = state.lease.map(|(seed, low)| node.leases.restore(seed, low));
    let ChannelState { out_ended, in_ended, unread, to_layer, .. } = state;
    let start = Start { out_ended, in_ended, unread, to_layer };
    let (hold, say) = (register(id), node.say.clone());
    let inner = hold.clone();
    tokio::spawn(scoped(id, hold, async move {
        let carried = channel.carry_held(target, Some(&*inner), start).await;
        after(carried, Some(&*inner), peer, lease, &*say).await;
    }));
    Ok(ours)
}
