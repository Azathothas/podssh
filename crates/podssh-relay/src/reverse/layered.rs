//! The node's far end of the resumable layer (T-153). Each session that the
//! relay opens is one link: the node answers `ready` at once, greets, and
//! the layer's handshake tells a new session from a resume. Only a new
//! session dials the target, after its handshake, so a link that never
//! completes one costs no connection to sshd (T-164); a resume goes on with
//! the target that the session kept.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::DuplexStream;

use super::framing::SessionId as RelayId;
use super::node::{Handler, Opening};
use crate::session::keep::Keeper;
use crate::session::record::Role;
use crate::session::{far, Settings};

/// Each direction of the pipe between the node's session and the layer.
const PIPE: usize = 256 * 1024;
/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// The replay memory of the whole node: the relay lets a node carry 64
/// sessions, and 4 MiB of each would be 256 MiB in a cage (T-153).
pub const NODE_BUDGET: usize = 64 << 20;

/// A handler whose sessions run the resumable layer over the sessions of
/// `inner`, which opens each target.
pub struct Layered<H: Handler> {
    inner: Arc<H>,
    keeper: Arc<Keeper<H::Stream>>,
    settings: Settings,
    budget: usize,
    sweeping: AtomicBool,
}

impl<H: Handler> Layered<H> {
    pub fn new(inner: H, settings: Settings, budget: usize) -> Layered<H> {
        Layered {
            inner: Arc::new(inner),
            keeper: Arc::new(Keeper::new(settings.resume_deadline)),
            settings,
            budget,
            sweeping: AtomicBool::new(false),
        }
    }

    /// The sessions kept, with a link or waiting for one.
    pub fn kept(&self) -> usize {
        self.keeper.kept()
    }

    /// One task forgets the sessions whose deadline passed; started with the
    /// first session, inside the node's runtime.
    fn sweep(&self) {
        if self.sweeping.swap(true, Ordering::SeqCst) {
            return;
        }
        let keeper = Arc::downgrade(&self.keeper);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                let Some(keeper) = keeper.upgrade() else { return };
                keeper.expire().await;
            }
        });
    }
}

impl<H: Handler> Handler for Layered<H> {
    type Stream = DuplexStream;

    fn open(&self, id: RelayId) -> Opening<DuplexStream> {
        self.sweep();
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let (inner, keeper, settings, budget) = (self.inner.clone(), self.keeper.clone(), self.settings, self.budget);
        tokio::spawn(async move {
            far::serve(ours, Role::NODE, settings, &keeper, budget, || inner.open(id)).await;
        });
        Box::pin(async move { Ok(theirs) })
    }
}
