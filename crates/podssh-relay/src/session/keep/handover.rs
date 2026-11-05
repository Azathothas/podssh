//! A far end's sessions handed to the binary that takes its place, and
//! taken there (T-668). Each link stops as a resume stops it; each session
//! that waits for its client then gives its layer's state, and its target
//! moves as [`Movable`] moves it. A session that cannot move goes as a
//! closed one, with why: the next binary keeps its id, and its client's
//! resume hears `CLOSE` with those words, never a forgotten session.

use super::*;
use crate::session::handover::{Handed, Kept, LayerState, Movable, Moved};
use crate::session::secret::Secret;

/// How long the links of the sessions have to stop at a handover: a link
/// whose writer is in a record ends that record first.
const STOP_LIMIT: Duration = Duration::from_secs(10);

/// Why a session whose link did not stop goes no further.
const NOT_STOPPED: &str = "the node's upgrade could not move this session: its link did not stop in time";

/// The words of a session whose target did not move.
pub fn not_moved(why: &str) -> String {
    format!("the node's upgrade could not move this session: {why}")
}

fn closed(id: SessionId, secret: Secret, left: Duration, received: u64, reason: String) -> Handed {
    let target = Err(reason.clone());
    Handed { state: LayerState { id, secret, left, kept: Kept::Closed { received, reason } }, target }
}

impl<A> Keeper<A>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + Movable,
{
    /// The sessions that a link carries now.
    fn live(&self) -> usize {
        lock(&self.slots).values().filter(|slot| matches!(slot, Slot::Live { .. })).count()
    }

    /// Each session out of this keeper, for the binary that takes its place:
    /// each link stops at a record boundary, as for a resume, then each
    /// session gives its state and its target. A session whose client was
    /// not let in yet is a visitor's, and goes with nothing. The keeper
    /// holds nothing after.
    pub async fn hand_over(&self) -> Vec<Handed> {
        for slot in lock(&self.slots).values() {
            if let Slot::Live { watch, .. } = slot {
                watch.stop.notify_one();
            }
        }
        let deadline = Instant::now() + STOP_LIMIT;
        while self.live() > 0 && Instant::now() < deadline {
            tokio::time::sleep(STOP_CHECK).await;
        }
        let slots: Vec<(SessionId, Slot<A>)> = lock(&self.slots).drain().collect();
        lock(&self.newest).clear();
        let now = Instant::now();
        let mut out = Vec::with_capacity(slots.len());
        for (id, slot) in slots {
            let (secret, received) = {
                let mut sessions = lock(&self.sessions);
                let secret = sessions.secret(&id).map(|secret| Secret::from_bytes(*secret.bytes()));
                let received = sessions.received(&id).unwrap_or(0);
                sessions.remove(&id);
                (secret, received)
            };
            let Some(secret) = secret else { continue };
            match slot {
                Slot::Idle { app, carry, until, admitted } => {
                    if !admitted.load(Ordering::SeqCst) {
                        continue;
                    }
                    let left = until.saturating_duration_since(now);
                    let (link, parts) = carry.parts();
                    match app.move_out(id).await {
                        Ok(moved) => out.push(Handed {
                            state: LayerState { id, secret, left, kept: Kept::Carried { link, carry: parts } },
                            target: Ok(moved),
                        }),
                        Err(why) => out.push(closed(id, secret, left, link.received, not_moved(&why))),
                    }
                }
                Slot::Closed { until, reason } => {
                    out.push(closed(id, secret, until.saturating_duration_since(now), received, reason));
                }
                // The pump still holds its target: the session goes as one
                // that ended, with why.
                Slot::Live { state, admitted, .. } if admitted.load(Ordering::SeqCst) => {
                    let received = lock(&state).received();
                    out.push(closed(id, secret, self.deadline, received, NOT_STOPPED.to_string()));
                }
                Slot::Live { .. } => {}
            }
        }
        out
    }

    /// The sessions that the binary before this one handed over, each with
    /// its target as `restore` makes it from what moved. Each waits for its
    /// client's resume as after a lost link, for the time that it had left,
    /// this keeper's deadline at most. A session whose target does not come
    /// back waits as a closed one, with why. The words of each session that
    /// does not go on, for the node's lines.
    pub fn take_over<R>(&self, handed: Vec<Handed>, mut restore: R) -> Vec<String>
    where
        R: FnMut(SessionId, Moved) -> Result<A, String>,
    {
        let now = Instant::now();
        let mut said = Vec::new();
        for Handed { state, target } in handed {
            let LayerState { id, secret, left, kept } = state;
            let until = now + left.min(self.deadline);
            let (received, reason) = match (kept, target) {
                (Kept::Carried { link, carry }, Ok(moved)) => {
                    let received = link.received;
                    let restored = Link::from_parts(link).and_then(|link| restore(id, moved).map(|app| (link, app)));
                    match restored {
                        Ok((link, app)) => {
                            let carry = Carry::from_parts(link, carry);
                            {
                                let mut sessions = lock(&self.sessions);
                                sessions.insert(id, secret);
                                sessions.attach(&id, carry.state.clone());
                            }
                            let slot = Slot::Idle { app, carry, until, admitted: admitted_at_once() };
                            lock(&self.slots).insert(id, slot);
                            continue;
                        }
                        Err(why) => (received, not_moved(&why)),
                    }
                }
                (Kept::Carried { link, .. }, Err(why)) => (link.received, not_moved(&why)),
                (Kept::Closed { received, reason }, _) => (received, reason),
            };
            {
                let mut sessions = lock(&self.sessions);
                sessions.insert(id, secret);
                sessions.set_received(&id, received);
            }
            if !reason.is_empty() {
                said.push(format!("the session {} ends at its resume: {reason}", id.short()));
            }
            lock(&self.slots).insert(id, Slot::Closed { until, reason });
        }
        said
    }
}
