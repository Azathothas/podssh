//! A person at the node (T-638, GitHub #136): a gate after a node's door,
//! for a node that asks for one (`podssh node --ask`). Each key that the
//! door, or a grant, lets through waits for a person's yes: one question for
//! each key at a time, which each session of that key that comes meanwhile
//! waits for. A yes covers the key while one of its sessions is open, and
//! [`Times::cover`] after its last; a no, or no answer within
//! [`Times::question`], stands [`Times::stands`], in which the key is
//! refused with no question.
//!
//! The gate comes after the door, never before it: a key that the door
//! refuses raises no question, so that whoever reaches the node with a key
//! of its own cannot put questions to its person, and a yes widens no door.
//! A no that stands is read before the door ([`Gate::standing`]), so that it
//! spends no grant. Who answers, and where, is the binary's ([`Asker`]):
//! this crate has no terminal. The covers live in the process, so a node
//! that starts again asks again.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use super::Ask;
use crate::identity::PublicKey;

/// The times of a gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Times {
    /// How long a question waits for its answer: no answer is a no.
    pub question: Duration,
    /// How long a yes covers its key after the key's last session ended.
    pub cover: Duration,
    /// How long a no stands, in which the key is refused with no question.
    pub stands: Duration,
}

impl Times {
    /// 100 s for an answer, a cover of 120 s and a no that stands 15 s, as
    /// GitHub #136 proposed them: chosen, not measured.
    pub const DEFAULT: Times =
        Times { question: Duration::from_secs(100), cover: Duration::from_secs(120), stands: Duration::from_secs(15) };
}

/// What a node asks its person: the key that the channel proved, what it
/// asks, whether a grant let it through the door, and how long the answer
/// may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub key: PublicKey,
    pub ask: Ask,
    pub granted: bool,
    pub limit: Duration,
}

/// An answer on its way: `Ok` is a yes; `Err` is a no, in the words of the
/// node's line.
pub type Answer = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

/// Who answers a question: the binary's, a person at its terminal. The gate
/// drops an answer that did not come within the question's limit, so its
/// future must leave nothing behind when it is dropped.
pub type Asker = dyn Fn(Question) -> Answer + Send + Sync;

/// How the gate let a key in, for the node's line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By {
    /// A yes to the question of this key, which this session waited for.
    Answer,
    /// The cover of an earlier yes.
    Cover,
}

impl fmt::Display for By {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            By::Answer => "a yes of the node's person",
            By::Cover => "the cover of a yes of the node's person",
        })
    }
}

/// The answer that a question gave, which each waiting session reads.
type Said = Option<Result<(), String>>;

/// What the gate knows of one key.
enum Slot {
    /// A question is out: each session of the key waits for its answer.
    Asking(watch::Receiver<Said>),
    /// A yes: the sessions open, and the end of the cover once none is.
    Covered { open: usize, until: Instant },
    /// A no, which stands until then.
    Refused { until: Instant, why: String },
}

impl Slot {
    /// Whether the slot still says something at `now`.
    fn live(&self, now: Instant) -> bool {
        match self {
            Slot::Asking(_) => true,
            Slot::Covered { open, until } => *open > 0 || *until > now,
            Slot::Refused { until, .. } => *until > now,
        }
    }
}

/// What one look at a key's slot gives.
enum Step {
    /// A cover holds: in, with no question.
    In,
    /// A no stands: why.
    Refused(String),
    /// Another session's question is out: its answer.
    Wait(watch::Receiver<Said>),
    /// No word on the key: this session asks.
    Ask(watch::Sender<Said>),
}

/// A node's gate of its person.
pub struct Gate {
    asker: Arc<Asker>,
    times: Times,
    slots: Mutex<HashMap<PublicKey, Slot>>,
}

/// One session that the gate let in: while one lives, its key's cover
/// holds; once the last one goes, the cover runs [`Times::cover`] more.
pub struct Pass {
    gate: Arc<Gate>,
    key: PublicKey,
}

impl Drop for Pass {
    fn drop(&mut self) {
        let end = Instant::now() + self.gate.times.cover;
        if let Some(Slot::Covered { open, until }) = self.gate.slots().get_mut(&self.key) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                *until = end;
            }
        }
    }
}

/// A question that is out. Dropped before its answer (the session that asked
/// ended), it takes the slot back, and each session that waited looks again,
/// so that the next one asks anew.
struct Outstanding {
    gate: Arc<Gate>,
    key: PublicKey,
    tell: watch::Sender<Said>,
    answered: bool,
}

impl Drop for Outstanding {
    fn drop(&mut self) {
        if !self.answered {
            let mut slots = self.gate.slots();
            if let Some(Slot::Asking(_)) = slots.get(&self.key) {
                slots.remove(&self.key);
            }
        }
        // The sender goes after this, and wakes each session that waited.
    }
}

impl Gate {
    /// A gate whose questions `asker` answers, with the times of GitHub #136.
    pub fn new(asker: Arc<Asker>) -> Arc<Gate> {
        Gate::with_times(asker, Times::DEFAULT)
    }

    /// A gate with other times, for the tests.
    pub fn with_times(asker: Arc<Asker>, times: Times) -> Arc<Gate> {
        Arc::new(Gate { asker, times, slots: Mutex::new(HashMap::new()) })
    }

    pub fn times(&self) -> Times {
        self.times
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<PublicKey, Slot>> {
        // Each change under the lock is one step, so a panic leaves the map whole.
        self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A no that stands for `key` now, in the words of the node's line: the
    /// session is refused with no question, and before the door, so that it
    /// spends no grant.
    pub fn standing(&self, key: &PublicKey) -> Option<String> {
        let now = Instant::now();
        match self.slots().get(key) {
            Some(Slot::Refused { until, why }) if *until > now => Some(stands(why, *until - now)),
            _ => None,
        }
    }

    /// Let `key` cross, which the door (or a grant, `granted`) let through
    /// for `ask`: a cover, else the one question of the key, which each
    /// session of the key that comes meanwhile waits for. The pass holds
    /// the cover while the session lives; `Err` is why not, for the node's
    /// line.
    pub async fn cross(self: &Arc<Self>, key: PublicKey, ask: &Ask, granted: bool) -> Result<(Pass, By), String> {
        loop {
            match self.look(key) {
                Step::In => return Ok((self.pass(key), By::Cover)),
                Step::Refused(why) => return Err(why),
                Step::Ask(tell) => {
                    let out = Outstanding { gate: self.clone(), key, tell, answered: false };
                    return self.put(out, ask, granted).await;
                }
                Step::Wait(mut answer) => {
                    // An error is a question that ended with no answer: look again.
                    let _ = answer.changed().await;
                    let said: Said = (*answer.borrow()).clone();
                    match said {
                        Some(Ok(())) if self.join(key) => return Ok((self.pass(key), By::Answer)),
                        Some(Err(why)) => return Err(self.refusal(&why)),
                        _ => {}
                    }
                }
            }
        }
    }

    /// One look at the slot of `key`, under the lock.
    fn look(&self, key: PublicKey) -> Step {
        let now = Instant::now();
        let mut slots = self.slots();
        // A word whose time passed goes, so the map holds what counts alone.
        slots.retain(|_, slot| slot.live(now));
        match slots.entry(key) {
            Entry::Vacant(place) => {
                let (tell, answer) = watch::channel(None);
                place.insert(Slot::Asking(answer));
                Step::Ask(tell)
            }
            Entry::Occupied(mut place) => match place.get_mut() {
                Slot::Covered { open, .. } => {
                    *open += 1;
                    Step::In
                }
                Slot::Refused { until, why } => Step::Refused(stands(why, until.saturating_duration_since(now))),
                Slot::Asking(answer) => Step::Wait(answer.clone()),
            },
        }
    }

    /// A session of `key` that waited for its question's yes, counted in the
    /// key's cover; `false` when the cover went meanwhile.
    fn join(&self, key: PublicKey) -> bool {
        match self.slots().get_mut(&key) {
            Some(Slot::Covered { open, .. }) => {
                *open += 1;
                true
            }
            _ => false,
        }
    }

    fn pass(self: &Arc<Self>, key: PublicKey) -> Pass {
        Pass { gate: self.clone(), key }
    }

    /// Ask the node's person, once, of the key of `out`: the answer goes to
    /// each session of the key that waits, and the key's slot keeps it.
    async fn put(self: &Arc<Self>, mut out: Outstanding, ask: &Ask, granted: bool) -> Result<(Pass, By), String> {
        let limit = self.times.question;
        let question = Question { key: out.key, ask: ask.clone(), granted, limit };
        let said = match tokio::time::timeout(limit, (self.asker)(question)).await {
            Ok(said) => said,
            Err(_) => Err(format!("no answer came within {} s, which is a no", limit.as_secs())),
        };
        let now = Instant::now();
        let slot = match &said {
            Ok(()) => Slot::Covered { open: 1, until: now + self.times.cover },
            Err(why) => Slot::Refused { until: now + self.times.stands, why: why.clone() },
        };
        self.slots().insert(out.key, slot);
        out.answered = true;
        let _ = out.tell.send_replace(Some(said.clone()));
        match said {
            Ok(()) => Ok((self.pass(out.key), By::Answer)),
            Err(why) => Err(self.refusal(&why)),
        }
    }

    /// The words of a no that this session's question got.
    fn refusal(&self, why: &str) -> String {
        format!("{why}; the no stands {} s, with no question", self.times.stands.as_secs())
    }
}

/// The words of a no that stands, `left` more.
fn stands(why: &str, left: Duration) -> String {
    format!("{why}; that no stands {} s more, with no question", left.as_secs().max(1))
}

#[cfg(test)]
#[path = "person_tests.rs"]
mod tests;
