//! A node's handler whose sessions run the end-to-end channel (T-088) over
//! the sessions of an inner handler: each session that the relay, or the
//! resumable layer above it, opens answers the channel's handshake, and
//! reaches the inner handler's target only once the operator's key is let
//! in (T-087). Under the layer, a resume carries the same channel on.

use std::sync::Arc;

use tokio::io::DuplexStream;

use super::framing::SessionId;
use super::node::{Handler, Opening};
use crate::e2e::ends::{serve_node, Node};

/// Each direction of the pipe between a session and its channel.
const PIPE: usize = 256 * 1024;

/// A handler whose sessions run the channel over the sessions of `inner`.
pub struct E2e<H: Handler> {
    inner: Arc<H>,
    node: Node,
}

impl<H: Handler> E2e<H> {
    pub fn new(inner: H, node: Node) -> E2e<H> {
        E2e { inner: Arc::new(inner), node }
    }
}

impl<H: Handler> Handler for E2e<H> {
    type Stream = DuplexStream;

    fn open(&self, id: SessionId) -> Opening<DuplexStream> {
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let (inner, node) = (self.inner.clone(), self.node.clone());
        tokio::spawn(async move {
            serve_node(theirs, &node, || inner.open(id)).await;
        });
        Box::pin(async move { Ok(ours) })
    }

    fn queue_bytes(&self) -> usize {
        self.inner.queue_bytes()
    }
}
