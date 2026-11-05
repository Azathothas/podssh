//! One iroh connection to a node for the sessions of one process (T-666).
//! A second SSH connection of this process to a node of the iroh road, as
//! a copy beside a terminal, opens a new QUIC stream of the connection that
//! the first one made: no new endpoint, relay connection, path or handshake.
//! Each session holds a [`Lease`] of the shared [`Dialer`], and takes its
//! streams in its own [`Lane`], so that a copy's bytes wait for a terminal's
//! and not the other way round; QUIC loses no byte of one stream to the loss
//! of another's. The connection and its endpoint close with the last lease.
//!
//! Sessions share a dialer when they run in one runtime (an endpoint's tasks
//! are its runtime's), with one key of this client, to one node.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use iroh::{EndpointId, PublicKey};
use tokio::sync::OnceCell;

use crate::client::{Dialer, Failure};
use crate::stream::{Lane, Stream};

/// How long the endpoint of the last lease may take to close.
const CLOSE_LIMIT: Duration = Duration::from_secs(3);

/// Which sessions may share a dialer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Key {
    runtime: tokio::runtime::Id,
    client: PublicKey,
    node: EndpointId,
}

/// One node's dialer, made once by the first lease that needs it.
struct Slot {
    key: Key,
    made: OnceCell<Dialer>,
}

/// Each slot of the process, with the leases that hold it.
static SLOTS: Mutex<Vec<(Arc<Slot>, usize)>> = Mutex::new(Vec::new());

fn slots() -> MutexGuard<'static, Vec<(Arc<Slot>, usize)>> {
    SLOTS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A session's hold on the dialer of its node.
pub struct Lease {
    slot: Arc<Slot>,
    lane: Lane,
    /// Whether an earlier lease made the dialer, whose connection this one
    /// then shares.
    joined: bool,
    released: AtomicBool,
}

/// A lease of the dialer of `node` for this client's key `client`: the one
/// that a session of this process made, while its endpoint is open, else one
/// of `make`. Its lane is that of the task that asks ([`Lane::current`]).
pub async fn lease<F, Fut, E>(client: PublicKey, node: EndpointId, make: F) -> Result<Lease, E>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Dialer, E>>,
{
    let key = Key { runtime: tokio::runtime::Handle::current().id(), client, node };
    let mut lease = Lease { slot: take(key), lane: Lane::current(), joined: true, released: AtomicBool::new(false) };
    let mut made_here = false;
    let made = lease.slot.made.get_or_try_init(|| {
        made_here = true;
        make()
    });
    // A failure gives the lease back, as it drops.
    made.await?;
    lease.joined = !made_here;
    Ok(lease)
}

/// The usable slot of `key`, one lease more; else a new one.
fn take(key: Key) -> Arc<Slot> {
    let mut slots = slots();
    let usable = |slot: &Slot| slot.key == key && slot.made.get().is_none_or(|d| !d.endpoint().is_closed());
    if let Some((slot, held)) = slots.iter_mut().find(|(slot, _)| usable(slot)) {
        *held += 1;
        return slot.clone();
    }
    let slot = Arc::new(Slot { key, made: OnceCell::new() });
    slots.push((slot.clone(), 1));
    slot
}

/// One lease fewer of `slot`; the slot, out of the list, when it was the last.
fn give_back(slot: &Arc<Slot>) -> Option<Arc<Slot>> {
    let mut slots = slots();
    let at = slots.iter().position(|(s, _)| Arc::ptr_eq(s, slot))?;
    slots[at].1 -= 1;
    (slots[at].1 == 0).then(|| slots.swap_remove(at).0)
}

/// Close the connection and the endpoint of a slot that no lease holds.
async fn close(slot: &Slot) {
    if let Some(dialer) = slot.made.get() {
        dialer.close().await;
        let _ = tokio::time::timeout(CLOSE_LIMIT, dialer.endpoint().close()).await;
    }
}

impl Lease {
    /// The shared dialer.
    pub fn dialer(&self) -> &Dialer {
        self.slot.made.get().expect("a lease is had once its dialer is made")
    }

    /// The lane of this session's streams.
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// Whether a session of this process made the dialer before this one.
    pub fn joined(&self) -> bool {
        self.joined
    }

    /// How many leases hold this dialer, this one among them.
    pub fn holders(&self) -> usize {
        slots().iter().find(|(s, _)| Arc::ptr_eq(s, &self.slot)).map_or(0, |(_, held)| *held)
    }

    /// A new link of this session, in its lane: a stream of the shared
    /// connection while it lives.
    pub async fn link(&self) -> Result<Stream, Failure> {
        self.dialer().link_as(self.lane).await
    }

    /// Give the lease back; the connection and the endpoint close with the
    /// last. A second call does nothing.
    pub async fn release(&self) {
        if self.released.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(slot) = give_back(&self.slot) {
            close(&slot).await;
        }
    }
}

impl Drop for Lease {
    /// A lease that was never given back, as on an early return: the last
    /// one closes its slot in a task of the runtime, when one runs.
    fn drop(&mut self) {
        if self.released.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(slot) = give_back(&self.slot) else { return };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move { close(&slot).await });
        }
    }
}
