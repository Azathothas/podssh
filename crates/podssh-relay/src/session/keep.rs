//! The sessions that a far end keeps across links (T-153). A session's
//! target and state wait after its link is lost, until the client resumes it
//! on a new link or the deadline passes; then the target is shut and the
//! session forgotten.
//!
//! A resume can come while the far end still runs the old link, which it has
//! not yet seen fail: the old link is told to stop, and the new one goes on
//! from the client's offset once it has. The newest resume wins: the client
//! runs one handshake at a time, so an older resume that still waits is a
//! link that the client left, and it gives way.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::decode::Decoder;
use super::far::Accepted;
use super::link::Link;
use super::pump::{self, Carry, Ended, Watch};
use super::record::Record;
use super::secret::SessionId;
use super::sessions::Sessions;

/// How long a resume waits for the old link of its session to stop.
const STOP_WAIT: Duration = Duration::from_secs(10);
/// How often a resume looks at the session again while it waits: `done` is
/// the signal, and this the fallback for a signal that came before the wait.
const STOP_CHECK: Duration = Duration::from_millis(50);
/// How long a `REFUSE` may take to go out before the link is dropped.
const REFUSE_WAIT: Duration = Duration::from_secs(5);

/// Why a resume did not take its session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotTaken {
    /// The session ended, on its old link, while this one shook hands.
    Ended,
    /// A newer resume came: the client left this link.
    Newer,
    /// The old link did not stop in time.
    Stuck,
}

impl std::fmt::Display for NotTaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NotTaken::Ended => "the session ended on its old link",
            NotTaken::Newer => "a newer link resumed the session",
            NotTaken::Stuck => "the old link of the session did not stop",
        })
    }
}

enum Slot<A> {
    /// A link carries the session; its `watch` stops it, and `done` tells
    /// when it has ended. `state` is the session's, for the count of its
    /// buffer.
    Live { watch: Arc<Watch>, done: Arc<Notify>, state: Arc<Mutex<Link>> },
    /// No link: the target and the state wait until `until`.
    Idle { app: A, carry: Carry, until: Instant },
}

/// The sessions of a far end, with their targets, across links.
pub struct Keeper<A> {
    /// The secrets and the offsets, for the handshake ([`super::far::accept`]).
    pub sessions: Mutex<Sessions>,
    slots: Mutex<HashMap<SessionId, Slot<A>>>,
    /// The newest resume of each session, by its number.
    newest: Mutex<HashMap<SessionId, u64>>,
    resumes: AtomicU64,
    deadline: Duration,
}

impl<A> Keeper<A>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// A keeper whose sessions wait `deadline` after a loss.
    pub fn new(deadline: Duration) -> Keeper<A> {
        Keeper {
            sessions: Mutex::new(Sessions::new()),
            slots: Mutex::new(HashMap::new()),
            newest: Mutex::new(HashMap::new()),
            resumes: AtomicU64::new(0),
            deadline,
        }
    }

    /// The sessions kept, with a link or without.
    pub fn kept(&self) -> usize {
        lock(&self.slots).len()
    }

    /// The bytes that the replay buffers of all sessions hold.
    pub fn replay_bytes(&self) -> usize {
        lock(&self.slots)
            .values()
            .map(|slot| match slot {
                Slot::Idle { carry, .. } => lock(&carry.state).kept(),
                Slot::Live { state, .. } => lock(state).kept(),
            })
            .sum()
    }

    /// Carry a new session's first link, with `app`, its target.
    pub async fn run_new<L>(&self, accepted: Accepted<L>, app: A) -> Ended
    where
        L: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (link, decoder, established, settings) = accepted.into_parts();
        let carry = Carry::new(settings.link(&established));
        lock(&self.sessions).attach(&established.id, carry.state.clone());
        let (watch, done) = (Arc::new(Watch::default()), Arc::new(Notify::new()));
        let live = Slot::Live { watch: watch.clone(), done: done.clone(), state: carry.state.clone() };
        lock(&self.slots).insert(established.id, live);
        self.carry(established.id, app, link, decoder, carry, &watch, &done).await
    }

    /// Carry a resumed session onto `accepted`'s link: its old link stops
    /// first, then the bytes go on from the client's received offset. An
    /// error when the session is no longer kept, or the client asks for
    /// bytes that this side no longer has; the session then ends.
    pub async fn run_resumed<L>(&self, accepted: Accepted<L>) -> Result<Ended, String>
    where
        L: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (mut link, decoder, established, _) = accepted.into_parts();
        let id = established.id;
        let number = self.resumes.fetch_add(1, Ordering::SeqCst) + 1;
        lock(&self.newest).insert(id, number);
        let (watch, done) = (Arc::new(Watch::default()), Arc::new(Notify::new()));
        let (mut app, mut carry) = match self.take(&id, number, &watch, &done).await {
            Ok(taken) => taken,
            // The client hears the session's end, not a lost link.
            Err(NotTaken::Ended) => {
                if let Ok(bytes) = (Record::Close { reason: String::new() }).to_bytes() {
                    let _ = tokio::time::timeout(REFUSE_WAIT, link.write_all(&bytes)).await;
                }
                return Err(NotTaken::Ended.to_string());
            }
            Err(other) => return Err(other.to_string()),
        };
        let mut again = Vec::new();
        let resumed = lock(&carry.state).resume(established.peer_received, &mut again);
        if let Err(not_kept) = resumed {
            if let Ok(bytes) = not_kept.refusal().to_bytes() {
                let _ = tokio::time::timeout(REFUSE_WAIT, link.write_all(&bytes)).await;
            }
            lock(&self.slots).remove(&id);
            self.forget(&id);
            let _ = app.shutdown().await;
            done.notify_waiters();
            return Err(not_kept.to_string());
        }
        // The pump sends the bytes that the client lacks while it reads the
        // client's.
        carry.send_again(again);
        Ok(self.carry(id, app, link, decoder, carry, &watch, &done).await)
    }

    /// The target and the state of a kept session for resume `number`, the
    /// link that held it stopped. The new link's `watch` and `done` take the
    /// slot in the same lock that empties it, so a resume that looks next
    /// finds this link, and stops it.
    async fn take(
        &self,
        id: &SessionId,
        number: u64,
        watch: &Arc<Watch>,
        done: &Arc<Notify>,
    ) -> Result<(A, Carry), NotTaken> {
        let deadline = Instant::now() + STOP_WAIT;
        loop {
            match lock(&self.newest).get(id) {
                Some(newest) if *newest == number => {}
                Some(_) => return Err(NotTaken::Newer),
                None => return Err(NotTaken::Ended),
            }
            let stopping = {
                let mut slots = lock(&self.slots);
                match slots.remove(id) {
                    Some(Slot::Idle { app, carry, .. }) => {
                        let live = Slot::Live { watch: watch.clone(), done: done.clone(), state: carry.state.clone() };
                        slots.insert(*id, live);
                        return Ok((app, carry));
                    }
                    Some(Slot::Live { watch, done, state }) => {
                        watch.stop.notify_one();
                        slots.insert(*id, Slot::Live { watch, done: done.clone(), state });
                        done
                    }
                    None => return Err(NotTaken::Ended),
                }
            };
            if Instant::now() >= deadline {
                return Err(NotTaken::Stuck);
            }
            let _ = tokio::time::timeout(STOP_CHECK, stopping.notified()).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn carry<L>(
        &self,
        id: SessionId,
        mut app: A,
        link: L,
        decoder: Decoder,
        mut carry: Carry,
        watch: &Watch,
        done: &Notify,
    ) -> Ended
    where
        L: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let ended = pump::run(&mut app, link, decoder, &mut carry, watch).await;
        if ended.end.resumable() {
            self.idle(id, app, carry);
        } else {
            lock(&self.slots).remove(&id);
            self.forget(&id);
            // The target learns that the session is over.
            let _ = app.shutdown().await;
        }
        // Each resume that waits looks at the session again.
        done.notify_waiters();
        ended
    }

    /// No client can resume the session from now on.
    fn forget(&self, id: &SessionId) {
        lock(&self.sessions).remove(id);
        lock(&self.newest).remove(id);
    }

    fn idle(&self, id: SessionId, app: A, carry: Carry) {
        let until = Instant::now() + self.deadline;
        lock(&self.slots).insert(id, Slot::Idle { app, carry, until });
    }

    /// Forget each session whose link has been lost for longer than the
    /// deadline: its target is shut, and no client can resume it. The count
    /// forgotten.
    pub async fn expire(&self) -> usize {
        let now = Instant::now();
        let expired: Vec<(SessionId, A)> = {
            let mut slots = lock(&self.slots);
            let ids: Vec<SessionId> = slots
                .iter()
                .filter(|(_, slot)| matches!(slot, Slot::Idle { until, .. } if *until <= now))
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| match slots.remove(&id) {
                    Some(Slot::Idle { app, .. }) => Some((id, app)),
                    _ => None,
                })
                .collect()
        };
        let count = expired.len();
        for (id, mut app) in expired {
            self.forget(&id);
            let _ = app.shutdown().await;
        }
        count
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
