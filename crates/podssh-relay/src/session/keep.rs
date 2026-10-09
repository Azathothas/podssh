//! The sessions that a far end keeps across links (T-153). A session's
//! target and state wait after its link is lost, until the client resumes it
//! on a new link or the deadline passes; then the target is shut and the
//! session forgotten.
//!
//! A resume can come while the far end still runs the old link, which it has
//! not yet seen fail: the old link is told to stop, and the new one goes on
//! from the client's offset once it has.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::decode::Decoder;
use super::far::Accepted;
use super::link::Link;
use super::pump::{self, Carry, Ended};
use super::secret::SessionId;
use super::sessions::Sessions;

/// How long a resume waits for the old link of its session to stop.
const STOP_WAIT: Duration = Duration::from_secs(10);

enum Slot<A> {
    /// A link carries the session; `stop` ends it, and `done` tells when it
    /// has ended. `state` is the session's, for the count of its buffer.
    Live { stop: Arc<Notify>, done: Arc<Notify>, state: Arc<Mutex<Link>> },
    /// No link: the target and the state wait until `until`.
    Idle { app: A, carry: Carry, until: Instant },
}

/// The sessions of a far end, with their targets, across links.
pub struct Keeper<A> {
    /// The secrets and the offsets, for the handshake ([`super::far::accept`]).
    pub sessions: Mutex<Sessions>,
    slots: Mutex<HashMap<SessionId, Slot<A>>>,
    deadline: Duration,
}

impl<A> Keeper<A>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// A keeper whose sessions wait `deadline` after a loss.
    pub fn new(deadline: Duration) -> Keeper<A> {
        Keeper { sessions: Mutex::new(Sessions::new()), slots: Mutex::new(HashMap::new()), deadline }
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
        let (stop, done) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        let live = Slot::Live { stop: stop.clone(), done: done.clone(), state: carry.state.clone() };
        lock(&self.slots).insert(established.id, live);
        self.carry(established.id, app, link, decoder, carry, &stop, &done).await
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
        let (mut app, carry) = self.take(&id).await?;
        let mut again = Vec::new();
        let resumed = lock(&carry.state).resume(established.peer_received, &mut again);
        if let Err(not_kept) = resumed {
            if let Ok(bytes) = not_kept.refusal().to_bytes() {
                let _ = link.write_all(&bytes).await;
            }
            lock(&self.sessions).remove(&id);
            let _ = app.shutdown().await;
            return Err(not_kept.to_string());
        }
        if let Err(e) = link.write_all(&again).await {
            // The new link is already gone: the session waits for the next.
            self.idle(id, app, carry);
            return Err(format!("the new link failed: {e}"));
        }
        let (stop, done) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        let live = Slot::Live { stop: stop.clone(), done: done.clone(), state: carry.state.clone() };
        lock(&self.slots).insert(id, live);
        Ok(self.carry(id, app, link, decoder, carry, &stop, &done).await)
    }

    /// The target and the state of a kept session, its old link stopped.
    async fn take(&self, id: &SessionId) -> Result<(A, Carry), String> {
        let done = {
            let mut slots = lock(&self.slots);
            match slots.remove(id) {
                Some(Slot::Idle { app, carry, .. }) => return Ok((app, carry)),
                Some(Slot::Live { stop, done, state }) => {
                    stop.notify_one();
                    slots.insert(*id, Slot::Live { stop, done: done.clone(), state });
                    done
                }
                None => return Err("the session is no longer kept".into()),
            }
        };
        if tokio::time::timeout(STOP_WAIT, done.notified()).await.is_err() {
            return Err("the old link of the session did not stop".into());
        }
        match lock(&self.slots).remove(id) {
            Some(Slot::Idle { app, carry, .. }) => Ok((app, carry)),
            Some(live) => {
                lock(&self.slots).insert(*id, live);
                Err("another link took the session".into())
            }
            None => Err("the session ended".into()),
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
        stop: &Notify,
        done: &Notify,
    ) -> Ended
    where
        L: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let ended = pump::run(&mut app, link, decoder, &mut carry, Some(stop)).await;
        if ended.end.resumable() {
            self.idle(id, app, carry);
        } else {
            lock(&self.slots).remove(&id);
            lock(&self.sessions).remove(&id);
            // The target learns that the session is over.
            let _ = app.shutdown().await;
        }
        done.notify_one();
        ended
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
            lock(&self.sessions).remove(&id);
            let _ = app.shutdown().await;
        }
        count
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
