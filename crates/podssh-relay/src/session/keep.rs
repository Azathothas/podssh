//! The sessions that a far end keeps across links (T-153). A session's
//! target and state wait after its link is lost, until the client resumes it
//! on a new link or the deadline passes; then the target is shut and the
//! session forgotten.
//!
//! A resume can come while the far end still runs the old link, which it has
//! not yet seen fail: the old link is told to stop, and the new one goes on
//! from the client's offset once it has. The newest resume wins: the client
//! runs one handshake at a time, so an older resume that still waits is a
//! link that the client left, and it gives way. Newest is by the order of
//! the handshakes, which [`super::far::accept`] numbers before it answers,
//! not by the order in which their tasks start (T-270).
//!
//! A session that ended at this side, whose client acknowledged each byte
//! but lost the link before it answered the `CLOSE`, keeps its id alone
//! until the deadline: its target is shut and its buffer goes, and a resume
//! hears the `CLOSE` again (T-586). Each slot is charged against the far
//! end's budget by what it can hold ([`super::budget`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::budget::{Census, Told};
use super::decode::Decoder;
use super::far::{last_word, Accepted};
use super::link::Link;
use super::pump::{self, Carry, End, Ended, Watch};
use super::record::Record;
use super::secret::SessionId;
use super::sessions::Sessions;

/// How long a resume waits for the old link of its session to stop.
const STOP_WAIT: Duration = Duration::from_secs(10);
/// How often a resume looks at the session again while it waits: `done` is
/// the signal, and this the fallback for a signal that came before the wait.
const STOP_CHECK: Duration = Duration::from_millis(50);
/// How long a session whose client was not let in yet waits for a resume:
/// the channel's handshake has as long for each step, and a session kept
/// longer would only hold a visitor's handshake.
pub const UNADMITTED_WAIT: Duration = Duration::from_secs(30);

/// Whether what runs above the layer let a session's client in: the
/// end-to-end channel's admission of its key (T-300). A session counts
/// against the budget once it is admitted, and waits the whole deadline for
/// a resume only then: a visitor with no key, which can reach the layer of a
/// public name, takes nothing from the clients with one.
pub type Admitted = Arc<AtomicBool>;

/// An admission that holds from the start: a road that checks its client
/// before the layer, or has nothing above it that checks.
pub fn admitted_at_once() -> Admitted {
    Arc::new(AtomicBool::new(true))
}

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
    Live { watch: Arc<Watch>, done: Arc<Notify>, state: Arc<Mutex<Link>>, admitted: Admitted },
    /// No link: the target and the state wait until `until`.
    Idle { app: A, carry: Carry, until: Instant, admitted: Admitted },
    /// The session ended at this side and its client had each byte, but its
    /// answer to the `CLOSE` was lost with the link: no target and no
    /// buffer, only the id, whose secret the handshake of a resume proves,
    /// until `until`. The resume then gets the `CLOSE` (T-586).
    Closed { until: Instant },
}

impl<A> Slot<A> {
    /// The bytes of the budget that the slot holds (T-586): `each`, a whole
    /// buffer, while the buffer can still fill; once the target ended, the
    /// buffer can only empty, so the bytes kept for either side, at most
    /// `each`; nothing before the client is let in, or for an id alone. A
    /// link stays charged whole: the bytes that it holds are the pump's.
    fn charge(&self, each: usize) -> usize {
        match self {
            Slot::Live { admitted, .. } | Slot::Idle { admitted, .. } if !admitted.load(Ordering::SeqCst) => 0,
            Slot::Idle { carry, .. } if carry.app_ended() => {
                lock(&carry.state).kept().saturating_add(carry.undelivered()).min(each)
            }
            Slot::Live { .. } | Slot::Idle { .. } => each,
            Slot::Closed { .. } => 0,
        }
    }

    /// When a slot with no link is forgotten.
    fn until(&self) -> Option<Instant> {
        match self {
            Slot::Idle { until, .. } | Slot::Closed { until } => Some(*until),
            Slot::Live { .. } => None,
        }
    }
}

/// Whether a session that `end` left needs nothing more than its id
/// (T-586): this side's `CLOSE` went out after its target's last byte, the
/// client acknowledged each byte, and no byte of the client's waits for the
/// target. A resume could then only carry the `CLOSE` again.
fn closed_but_unanswered(end: &End, carry: &Carry) -> bool {
    matches!(end, End::Closing) && carry.app_ended() && carry.undelivered() == 0 && lock(&carry.state).kept() == 0
}

/// The sessions of a far end, with their targets, across links.
pub struct Keeper<A> {
    /// The secrets and the offsets, for the handshake ([`super::far::accept`]).
    pub sessions: Mutex<Sessions>,
    slots: Mutex<HashMap<SessionId, Slot<A>>>,
    /// The newest resume of each session, by its number.
    newest: Mutex<HashMap<SessionId, u64>>,
    deadline: Duration,
    /// When the budget's lines were last said (T-586).
    told: Mutex<Told>,
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
            deadline,
            told: Mutex::new(Told::default()),
        }
    }

    /// The sessions kept with their target, with a link or waiting for one;
    /// not a session that keeps its id alone, which holds nothing.
    pub fn kept(&self) -> usize {
        lock(&self.slots).values().filter(|slot| !matches!(slot, Slot::Closed { .. })).count()
    }

    /// The sessions that ended and keep their id alone, for a resume that
    /// lost their `CLOSE` (T-586).
    pub fn closed(&self) -> usize {
        lock(&self.slots).values().filter(|slot| matches!(slot, Slot::Closed { .. })).count()
    }

    /// What holds the budget (T-586), a session whose buffer can still fill
    /// charged `each`: the bytes charged, the sessions that a link carries,
    /// those that wait for their client, and when the first of those is
    /// forgotten. One still in its channel's handshake holds a few hundred
    /// bytes, and is not charged.
    pub fn census(&self, each: usize) -> Census {
        let now = Instant::now();
        let mut census = Census::default();
        for slot in lock(&self.slots).values() {
            let charge = slot.charge(each);
            if charge == 0 {
                continue;
            }
            census.held = census.held.saturating_add(charge);
            match slot.until() {
                None => census.live += 1,
                Some(until) => {
                    census.waiting += 1;
                    let left = until.saturating_duration_since(now);
                    census.first_free = Some(census.first_free.map_or(left, |first| first.min(left)));
                }
            }
        }
        census
    }

    /// Let a session's client in, marking `admitted`, when `budget` has room
    /// for one more session of `each` bytes; else `false`. The count and the
    /// mark are under one lock, so that two clients let in at once do not
    /// pass the budget together.
    pub fn admit(&self, admitted: &AtomicBool, each: usize, budget: usize) -> bool {
        let slots = lock(&self.slots);
        let held = slots.values().map(|slot| slot.charge(each)).fold(0, usize::saturating_add);
        if held.saturating_add(each) > budget {
            return false;
        }
        admitted.store(true, Ordering::SeqCst);
        true
    }

    /// When the budget's lines were last said, to say them seldom (T-586).
    pub fn told(&self) -> std::sync::MutexGuard<'_, Told> {
        lock(&self.told)
    }

    /// The bytes that the replay buffers of all sessions hold.
    pub fn replay_bytes(&self) -> usize {
        lock(&self.slots)
            .values()
            .map(|slot| match slot {
                Slot::Idle { carry, .. } => lock(&carry.state).kept(),
                Slot::Live { state, .. } => lock(state).kept(),
                Slot::Closed { .. } => 0,
            })
            .sum()
    }

    /// Carry a new session's first link, with `app`, its target.
    pub async fn run_new<L>(&self, accepted: Accepted<L>, app: A) -> Ended
    where
        L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.run_new_admitted(accepted, app, admitted_at_once()).await
    }

    /// [`Keeper::run_new`] for a session whose client is let in above the
    /// layer later, when `admitted` is set.
    pub async fn run_new_admitted<L>(&self, accepted: Accepted<L>, app: A, admitted: Admitted) -> Ended
    where
        L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (link, decoder, established, settings) = accepted.into_parts();
        let carry = Carry::new(settings.link(&established));
        lock(&self.sessions).attach(&established.id, carry.state.clone());
        let (watch, done) = (Arc::new(Watch::far_end().within(settings.window)), Arc::new(Notify::new()));
        let live = Slot::Live {
            watch: watch.clone(),
            done: done.clone(),
            state: carry.state.clone(),
            admitted: admitted.clone(),
        };
        lock(&self.slots).insert(established.id, live);
        self.carry(established.id, app, link, decoder, carry, &watch, &done, admitted).await
    }

    /// Carry a resumed session onto `accepted`'s link: its old link stops
    /// first, then the bytes go on from the client's received offset. An
    /// error when the session is no longer kept, or the client asks for
    /// bytes that this side no longer has; the session then ends.
    pub async fn run_resumed<L>(&self, accepted: Accepted<L>) -> Result<Ended, String>
    where
        L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let number = accepted.resume();
        let (mut link, decoder, established, settings) = accepted.into_parts();
        let id = established.id;
        // Only raised: an older resume whose task starts late gives way.
        {
            let mut newest = lock(&self.newest);
            let at = newest.entry(id).or_insert(number);
            *at = (*at).max(number);
        }
        let (watch, done) = (Arc::new(Watch::far_end().within(settings.window)), Arc::new(Notify::new()));
        let (mut app, mut carry, admitted) = match self.take(&id, number, &watch, &done).await {
            Ok(taken) => taken,
            // The client hears the session's end, not a lost link.
            Err(NotTaken::Ended) => {
                last_word(&mut link, &Record::Close { reason: String::new() }).await;
                return Err(NotTaken::Ended.to_string());
            }
            Err(other) => return Err(other.to_string()),
        };
        let mut again = Vec::new();
        let resumed = lock(&carry.state).resume(established.peer_received, &mut again);
        if let Err(not_kept) = resumed {
            lock(&self.slots).remove(&id);
            self.forget(&id);
            let _ = app.shutdown().await;
            done.notify_waiters();
            last_word(&mut link, &not_kept.refusal()).await;
            return Err(not_kept.to_string());
        }
        // The pump sends the bytes that the client lacks while it reads the
        // client's.
        carry.send_again(again);
        Ok(self.carry(id, app, link, decoder, carry, &watch, &done, admitted).await)
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
    ) -> Result<(A, Carry, Admitted), NotTaken> {
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
                    Some(Slot::Idle { app, carry, admitted, .. }) => {
                        let (watch, done, state) = (watch.clone(), done.clone(), carry.state.clone());
                        slots.insert(*id, Slot::Live { watch, done, state, admitted: admitted.clone() });
                        return Ok((app, carry, admitted));
                    }
                    Some(Slot::Live { watch, done, state, admitted }) => {
                        watch.stop.notify_one();
                        slots.insert(*id, Slot::Live { watch, done: done.clone(), state, admitted });
                        done
                    }
                    // The id stays until its deadline, for each resume
                    // that lost the `CLOSE` (T-586).
                    Some(closed @ Slot::Closed { .. }) => {
                        slots.insert(*id, closed);
                        return Err(NotTaken::Ended);
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
        admitted: Admitted,
    ) -> Ended
    where
        L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ended = pump::run(&mut app, link, decoder, &mut carry, watch).await;
        if ended.end.resumable() && closed_but_unanswered(&ended.end, &carry) {
            self.keep_id_alone(id, app, admitted).await;
        } else if ended.end.resumable() {
            self.idle(id, app, carry, admitted);
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

    /// How long a session with no link waits for a resume: the deadline, or
    /// less while its client was not let in.
    fn wait(&self, admitted: &Admitted) -> Duration {
        if admitted.load(Ordering::SeqCst) {
            self.deadline
        } else {
            self.deadline.min(UNADMITTED_WAIT)
        }
    }

    /// The session waits for a resume.
    fn idle(&self, id: SessionId, app: A, carry: Carry, admitted: Admitted) {
        let until = Instant::now() + self.wait(&admitted);
        lock(&self.slots).insert(id, Slot::Idle { app, carry, until, admitted });
    }

    /// The session ended, and only its id waits, as long as a lost session
    /// would (T-586): the target is shut, the buffer and the state go, and
    /// the secret and the offset stay for the handshake of a resume, which
    /// then hears the `CLOSE`. The slot comes first, so that a resume that
    /// waits for this link finds it.
    async fn keep_id_alone(&self, id: SessionId, mut app: A, admitted: Admitted) {
        lock(&self.sessions).detach(&id);
        let until = Instant::now() + self.wait(&admitted);
        lock(&self.slots).insert(id, Slot::Closed { until });
        let _ = app.shutdown().await;
    }

    /// Forget each session whose link has been lost for longer than the
    /// deadline, and each id kept alone as long: a target is shut, and no
    /// client can resume it. The count forgotten.
    pub async fn expire(&self) -> usize {
        self.expire_at(Instant::now()).await
    }

    /// [`Keeper::expire`] as at `now`. A test gives a later `now`: a far end
    /// whose clock ran on while its client's stood still, as on a client's
    /// host that slept (T-306).
    pub async fn expire_at(&self, now: Instant) -> usize {
        let expired: Vec<(SessionId, Option<A>)> = {
            let mut slots = lock(&self.slots);
            let ids: Vec<SessionId> = slots
                .iter()
                .filter(|(_, slot)| slot.until().is_some_and(|until| until <= now))
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| match slots.remove(&id) {
                    Some(Slot::Idle { app, .. }) => Some((id, Some(app))),
                    Some(Slot::Closed { .. }) => Some((id, None)),
                    _ => None,
                })
                .collect()
        };
        let count = expired.len();
        for (id, app) in expired {
            self.forget(&id);
            if let Some(mut app) = app {
                let _ = app.shutdown().await;
            }
        }
        count
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
