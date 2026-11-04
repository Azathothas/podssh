//! What a pair's node holds the role to beside the contract (T-615): the
//! tokens of one leg that it registers, each of which one operator's upgrade
//! takes, and its stop token as it rotates it.
//!
//! A token of one leg is kept by its digest alone, which the node sent on
//! its socket; the role takes it for an upgrade of `/v1/connect/<name>` only
//! while the node is joined with room for a session, tells the node which one
//! it took (`spent`) before the session's `open`, and keeps it as spent until
//! its end, so that the node cannot register it again. A pair keeps
//! [`MAX_LEGS`] of each at once, the ones that end first making room; they
//! live in memory, and the node registers its own again on its next socket.
//!
//! A rotation of the stop token is two steps, so that a node that stops
//! between them keeps a token that the role takes: by its stop token, the
//! node names the digest of the one to come, which it drew and kept; the
//! first use of that one makes it the pair's, and ends each before it. The
//! file of `--pairs` keeps both.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use super::{digest, hex, same, Kept, Pair, Pairs};

/// The tokens of one leg, and the spent ones, that a pair keeps: 64 sessions
/// of a node, with a window of 4 each.
pub const MAX_LEGS: usize = 256;
/// The longest life of a token of one leg, whatever its node says: its node
/// registers it again at each new socket and each upgrade of its session.
pub const LEG_LIFE_MS: u64 = 24 * 3600 * 1000;

/// A pair's tokens of one leg and its stop token's rotation.
#[derive(Default)]
pub struct Held {
    legs: Mutex<Legs>,
    stop: Mutex<Stop>,
}

#[derive(Default)]
struct Legs {
    /// Each token that the node registered, by its digest, with its end.
    live: HashMap<[u8; 32], u64>,
    /// Each token that an upgrade took, with its end.
    spent: HashMap<[u8; 32], u64>,
}

#[derive(Default)]
struct Stop {
    /// The stop token since a rotation, in the place of the pair's first.
    current: Option<[u8; 32]>,
    /// The one to come, which its first use makes the pair's.
    next: Option<[u8; 32]>,
}

/// What an upgrade with a token of one leg found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// Taken, once: the node hears of it with the session's `open`.
    Taken,
    /// No node is joined, or it has no room: nothing is taken, as the node
    /// would not hear of it.
    NoNode,
    /// Not a live token of the pair: taken already, ended, or withdrawn.
    Refused,
}

/// 64 hex digits as a digest; `None` for anything else.
pub fn parse_digest(text: &str) -> Option<[u8; 32]> {
    crate::e2e::legs::unhex(text)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The entry of `map` that ends first, which makes room for a newer one.
fn first_to_end(map: &HashMap<[u8; 32], u64>) -> Option<[u8; 32]> {
    map.iter().min_by_key(|(_, end)| **end).map(|(digest, _)| *digest)
}

/// Hold `map` to [`MAX_LEGS`], the entries that end first going.
fn bound(map: &mut HashMap<[u8; 32], u64>) {
    while map.len() > MAX_LEGS {
        let Some(first) = first_to_end(map) else { return };
        map.remove(&first);
    }
}

impl Held {
    /// Whether `got`, a token's digest, is the stop token: the pair's first
    /// (`first`), or the one that a rotation made it; or the one to come,
    /// which this use makes the pair's, ending each before it.
    pub(super) fn takes_stop(&self, first: &[u8; 32], got: &[u8; 32]) -> bool {
        let mut stop = lock(&self.stop);
        if same(&stop.current.unwrap_or(*first), got) {
            return true;
        }
        if stop.next.is_some_and(|next| same(&next, got)) {
            stop.current = stop.next.take();
            return true;
        }
        false
    }

    /// The stop token to come of the pair `name`, as its file keeps it.
    pub(super) fn next_stop(&self, kept: Option<&str>, name: &str) -> Result<(), String> {
        let Some(text) = kept else { return Ok(()) };
        let bad = || format!("pair {name}: the stop token to come is not 64 hex digits");
        let next = parse_digest(text).ok_or_else(bad)?;
        lock(&self.stop).next = Some(next);
        Ok(())
    }
}

impl Pair {
    /// This pair as its file keeps it: the digest of each token, the stop
    /// token's as its node rotated it, the one to come, and its maker (T-630).
    pub(super) fn kept(&self) -> Kept {
        let stop = lock(&self.held.stop);
        Kept {
            name: self.name.clone(),
            expires: self.expires_ms(),
            node: hex(&self.digests[0]),
            connect: hex(&self.digests[1]),
            stop: hex(&stop.current.unwrap_or(self.digests[2])),
            once: self.once,
            spent: self.connect_spent(),
            next_stop: stop.next.map(|next| hex(&next)),
            maker: self.maker.clone(),
        }
    }

    /// A node's frame of a token of one leg: `digest` (hex) registered until
    /// `expires_ms`, held to [`LEG_LIFE_MS`] from `now_ms`, or withdrawn with
    /// an end that passed; one that an upgrade took is never taken again.
    /// `false` for a digest that is not 64 hex digits.
    pub fn register_leg(&self, digest: &str, expires_ms: u64, now_ms: u64) -> bool {
        let Some(digest) = parse_digest(digest) else { return false };
        let mut legs = lock(&self.held.legs);
        legs.live.retain(|_, end| *end > now_ms);
        legs.spent.retain(|_, end| *end > now_ms);
        if expires_ms <= now_ms {
            legs.live.remove(&digest);
        } else if !legs.spent.contains_key(&digest) {
            legs.live.insert(digest, expires_ms.min(now_ms.saturating_add(LEG_LIFE_MS)));
            bound(&mut legs.live);
        }
        true
    }

    /// How many tokens of one leg are live.
    pub fn legs(&self) -> usize {
        lock(&self.held.legs).live.len()
    }
}

impl Pairs {
    /// The pair `name` whose node registered `token` as a token of one leg,
    /// live at `now_ms`, and the token's digest.
    pub fn find_leg(&self, name: &str, token: Option<&str>, now_ms: u64) -> Option<(Arc<Pair>, [u8; 32])> {
        let token = token?;
        let pair = self.map.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned()?;
        if pair.expires_ms() <= now_ms || pair.lock().ended {
            return None;
        }
        let digest = digest(token);
        let live = lock(&pair.held.legs).live.get(&digest).is_some_and(|end| *end > now_ms);
        live.then_some((pair, digest))
    }

    /// Take the token of one leg `digest` of `pair` for an upgrade: only while
    /// its node is joined with room for a session, which hears of it as the
    /// session's `open` comes; once, also for two upgrades at once.
    pub fn spend_leg(&self, pair: &Pair, digest: &[u8; 32], now_ms: u64) -> Leg {
        let state = pair.lock();
        let room = state.node_outbox().is_some() && state.sessions.len() < super::super::MAX_SESSIONS;
        if state.ended || !room {
            return Leg::NoNode;
        }
        let mut legs = lock(&pair.held.legs);
        match legs.live.remove(digest) {
            Some(end) if end > now_ms => {
                legs.spent.insert(*digest, end);
                bound(&mut legs.spent);
                Leg::Taken
            }
            _ => Leg::Refused,
        }
    }

    /// Rotate the stop token of the pair `name`, whose stop token the caller
    /// checked: `next`, a digest, is the one to come, unless it is the stop
    /// token already; the file keeps it. `None` for no such pair, or one
    /// that ended; a file that took no write leaves the rotation as it was,
    /// and says why.
    pub fn rotate(&self, name: &str, next: [u8; 32], now_ms: u64) -> Result<Option<()>, String> {
        let Some(pair) = self.map.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned() else {
            return Ok(None);
        };
        if pair.lock().ended || pair.expires_ms() <= now_ms {
            return Ok(None);
        }
        let before = {
            let mut stop = lock(&pair.held.stop);
            let current = stop.current.unwrap_or(pair.digests[2]);
            std::mem::replace(&mut stop.next, (!same(&current, &next)).then_some(next))
        };
        if let Err(why) = self.save() {
            lock(&pair.held.stop).next = before;
            return Err(why);
        }
        Ok(Some(()))
    }
}
