//! A node's channel held for the binary that takes its place (T-668). Each
//! channel's task above the resumable layer registers a [`Hold`] by the
//! layer's id of its session ([`holding`]); a handover asks it, reads what
//! the channel still writes for the layer meanwhile, so that no write of
//! the channel waits on a layer that no longer reads, and takes the
//! channel's state and its target once both directions stopped between two
//! messages. The next binary carries the channel on from that state
//! ([`resume`]), so the operator's end, which never knew, goes on.

mod resume;
pub mod state;

use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Notify};

use super::channel::{Carried, Channel, Held};
use super::legs::Lease;
use super::Error;
use crate::identity::PublicKey;
use crate::session::handover::{Movable, Moved, Moving};
use crate::session::SessionId;
pub use resume::resume;
pub use state::ChannelState;

/// How long a channel has to stop between two messages: its write to the
/// target ends first, which a target that reads nothing holds.
pub const HOLD_LIMIT: Duration = Duration::from_secs(10);

/// What a held channel gives the handover: its state, and its target.
struct Taken {
    state: ChannelState,
    target: Box<dyn Any + Send>,
}

/// The meeting of a channel's task and a handover.
#[derive(Default)]
pub struct Hold {
    asked: AtomicBool,
    wake: Notify,
    reply: Mutex<Option<oneshot::Sender<Taken>>>,
}

impl Hold {
    fn ask(&self, reply: oneshot::Sender<Taken>) {
        *lock(&self.reply) = Some(reply);
        self.asked.store(true, Ordering::SeqCst);
        self.wake.notify_waiters();
    }

    /// Whether a handover asked.
    pub fn is_asked(&self) -> bool {
        self.asked.load(Ordering::SeqCst)
    }

    async fn asked(&self) {
        loop {
            // Asked for before the look, so that a notice between the two
            // is not missed.
            let woken = self.wake.notified();
            if self.is_asked() {
                return;
            }
            woken.await;
        }
    }
}

/// Once `hold` is asked; never with none.
pub async fn held(hold: Option<&Hold>) {
    match hold {
        Some(hold) => hold.asked().await,
        None => std::future::pending().await,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The holds of this process, by the layer's id of their session.
fn holds() -> &'static Mutex<HashMap<SessionId, Arc<Hold>>> {
    static HOLDS: OnceLock<Mutex<HashMap<SessionId, Arc<Hold>>>> = OnceLock::new();
    HOLDS.get_or_init(Mutex::default)
}

/// A new hold of the session `id`, in the place of one before it.
fn register(id: SessionId) -> Arc<Hold> {
    let hold = Arc::new(Hold::default());
    lock(holds()).insert(id, hold.clone());
    hold
}

tokio::task_local! {
    /// The hold of the channel that runs in this task.
    static HOLD: Arc<Hold>;
}

/// The hold of the channel's task that runs now, if one.
pub fn current() -> Option<Arc<Hold>> {
    HOLD.try_with(Arc::clone).ok()
}

/// The hold of a task leaves the registry with the task, and its reply with
/// it, so that a handover that asks a task that ended learns so at once.
struct Gone(SessionId, Arc<Hold>);

impl Drop for Gone {
    fn drop(&mut self) {
        let mut holds = lock(holds());
        if holds.get(&self.0).is_some_and(|hold| Arc::ptr_eq(hold, &self.1)) {
            holds.remove(&self.0);
        }
        drop(holds);
        lock(&self.1.reply).take();
    }
}

/// Run `task`, the channel's task of a session, with `hold`.
async fn scoped<F: std::future::Future<Output = ()>>(id: SessionId, hold: Arc<Hold>, task: F) {
    let _gone = Gone(id, hold.clone());
    HOLD.scope(hold, task).await
}

/// `task`, the channel's task of a session that the layer opens now, with a
/// hold that a handover finds by the layer's id of the session; as it is
/// where no layer opens it. Called where the task is spawned, which is
/// inside the layer's opening of the target.
pub fn holding<F>(task: F) -> impl std::future::Future<Output = ()>
where
    F: std::future::Future<Output = ()>,
{
    let held = crate::session::handover::current().map(|id| (id, register(id)));
    async move {
        match held {
            Some((id, hold)) => scoped(id, hold, task).await,
            None => task.await,
        }
    }
}

/// After `serve_asked`'s carry stopped for a handover: the bytes that the
/// layer had written and the channel not read go with the bytes cut short,
/// and the state and the target to the handover that asked. Nothing is
/// closed: the target is the next binary's.
pub(super) async fn give<L, A>(hold: &Hold, held: Held<L, A>, peer: PublicKey, lease: Option<Lease>)
where
    L: AsyncRead + Unpin,
    A: Send + 'static,
{
    let Held { mut transport, app, sent, received, mut start, keys, net } = held;
    // A channel with no keys of its own (an operator's) cannot move: the
    // handover learns so at once.
    let Some(keys) = keys else {
        lock(&hold.reply).take();
        return;
    };
    drain(&mut transport, &mut start.unread).await;
    let state = ChannelState {
        keys,
        sent,
        received,
        out_ended: start.out_ended,
        in_ended: start.in_ended,
        unread: std::mem::take(&mut start.unread),
        to_layer: Vec::new(),
        peer: peer.0,
        net: net.is_some(),
        lease: lease.map(Lease::hand_over),
    };
    let taken = Taken { state, target: Box::new(app) };
    if let Some(reply) = lock(&hold.reply).take() {
        let _ = reply.send(taken);
    }
}

/// What waits in `pipe` now, read to `out` with no wait.
async fn drain<R: AsyncRead + Unpin>(pipe: &mut R, out: &mut Vec<u8>) {
    let mut buf = vec![0u8; 64 * 1024];
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::ZERO, pipe.read(&mut buf)).await {
        if n == 0 {
            return;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// The layer's side of a session's pipe to its channel: the channel stops
/// between two messages, and moves with its TCP target. One that runs no
/// channel in this process (a pipe that copies a target as it is) does not.
impl Movable for DuplexStream {
    fn move_out(self, id: SessionId) -> Moving {
        Box::pin(async move {
            let hold = lock(holds()).remove(&id).ok_or("no channel above its target can stop in this process")?;
            let (reply, taken) = oneshot::channel();
            hold.ask(reply);
            let (mut pipe, mut to_layer) = (self, Vec::new());
            let mut buf = vec![0u8; 64 * 1024];
            let waited = tokio::time::timeout(HOLD_LIMIT, async {
                tokio::pin!(taken);
                loop {
                    tokio::select! {
                        taken = &mut taken => return taken.ok(),
                        read = pipe.read(&mut buf) => match read {
                            Ok(n) if n > 0 => to_layer.extend_from_slice(&buf[..n]),
                            // The channel ended: its answer, if it gave one.
                            _ => return (&mut taken).await.ok(),
                        },
                    }
                }
            })
            .await;
            let Ok(Some(Taken { mut state, target })) = waited else {
                return Err(format!("its channel did not stop between two messages within {} s", HOLD_LIMIT.as_secs()));
            };
            // What the channel wrote before its answer came.
            drain(&mut pipe, &mut to_layer).await;
            state.to_layer = to_layer;
            let tcp = target.downcast::<TcpStream>().map_err(|_| "its target is no TCP connection".to_string())?;
            let socket = tcp.into_std().map_err(|e| format!("its connection to the target: {e}"))?;
            Ok(Moved { socket, channel: Some(state.encode()) })
        })
    }
}

/// The end of a node's carry of a session's channel: a line for an error,
/// and for a hold, the state to the handover.
pub(super) async fn after<L, A>(
    carried: Result<Carried<L, A>, Error>,
    hold: Option<&Hold>,
    peer: PublicKey,
    lease: Option<Lease>,
    say: &(dyn Fn(String) + Send + Sync),
) where
    L: AsyncRead + AsyncWrite + Unpin,
    A: Send + 'static,
{
    match (carried, hold) {
        (Ok(Carried::Held(held)), Some(hold)) => give(hold, held, peer, lease).await,
        (Ok(_), _) => {}
        (Err(e), _) => say(format!("the session of {peer} ended: {e}")),
    }
}

/// The channel of `held` again, for a carry that goes on in this process.
pub(super) fn again<L: AsyncRead + AsyncWrite + Unpin>(
    transport: L,
    state: &ChannelState,
) -> Result<Channel<L>, String> {
    let transport_state = state::transport_of(&state.keys)?;
    Ok(Channel::restored(transport, transport_state, (state.sent, state.received), state.keys.clone()))
}
