//! The queue of one socket's data, a line for each session, served a turn
//! each in a round (T-648). A socket carries many sessions, and one queue in
//! the order of arrival put each byte of a session behind each byte that
//! another queued before it: an interactive shell's echo waited for a bulk
//! copy's backlog, not for the network. Here the writer takes one piece of
//! the next line that holds one, so a session waits for one piece of each
//! other session at most. Each line has a room of its own and the socket a
//! room for all, so the memory stays bounded as the one queue's did; a line
//! that holds nothing always takes one piece, so that a session that writes
//! little never waits for the room that the others hold. A piece keeps its
//! room until the writer is done with it ([`Slot`]), and the order of one
//! session's pieces is kept. Both ends of a reverse socket use it: podssh's
//! node (`super::serve`) and the relay role's writer.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;

/// The queue was shut: its socket ends, and nothing more goes on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shut;

/// Why [`Fair::try_push`] took nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// No room now, in the line or in the socket.
    Full,
    Shut,
}

/// The queue, cheap to clone: its senders and its one writer share it.
pub struct Fair<K, T> {
    shared: Arc<Shared<K, T>>,
}

impl<K, T> Clone for Fair<K, T> {
    fn clone(&self) -> Self {
        Fair { shared: self.shared.clone() }
    }
}

struct Shared<K, T> {
    state: Mutex<State<K, T>>,
    /// The writer's wake: a piece came, or the queue was shut.
    filled: Notify,
    /// A sender's wake: room came back, or the queue was shut.
    freed: Notify,
    line_room: usize,
    socket_room: usize,
}

struct State<K, T> {
    lines: HashMap<K, Line<T>>,
    /// The lines that hold a piece, in the order of their next turn.
    turns: VecDeque<K>,
    /// The room taken in each line, the pieces in flight too.
    used: usize,
    shut: bool,
    /// A number for each line made, so that the room of a piece in flight of
    /// a line that was dropped never goes to a line of the same key after it.
    made: u64,
}

struct Line<T> {
    pieces: VecDeque<(T, usize)>,
    /// The room taken by its pieces, queued or in flight.
    used: usize,
    serial: u64,
}

/// One turn: the line's key, its piece, and the piece's room, which goes
/// back when the slot is dropped, once the piece is written or dropped.
pub struct Turn<K: Eq + Hash, T> {
    pub key: K,
    pub piece: T,
    pub slot: Slot<K, T>,
}

/// The room of a piece that the writer took.
pub struct Slot<K: Eq + Hash, T> {
    shared: Arc<Shared<K, T>>,
    key: K,
    serial: u64,
    cost: usize,
}

impl<K: Eq + Hash, T> Drop for Slot<K, T> {
    fn drop(&mut self) {
        let mut state = lock(&self.shared.state);
        state.used = state.used.saturating_sub(self.cost);
        let idle = match state.lines.get_mut(&self.key) {
            Some(line) if line.serial == self.serial => {
                line.used = line.used.saturating_sub(self.cost);
                line.used == 0 && line.pieces.is_empty()
            }
            _ => false,
        };
        // A line with nothing queued and nothing in flight is forgotten: a
        // node that runs for days keeps no line of each session it saw.
        if idle {
            state.lines.remove(&self.key);
        }
        drop(state);
        self.shared.freed.notify_waiters();
    }
}

impl<K: Eq + Hash + Clone, T> Fair<K, T> {
    /// A queue whose lines hold `line_room` each, and all of them
    /// `socket_room`, in the units of each piece's cost.
    pub fn new(line_room: usize, socket_room: usize) -> Fair<K, T> {
        let state = State { lines: HashMap::new(), turns: VecDeque::new(), used: 0, shut: false, made: 0 };
        let (state, filled, freed) = (Mutex::new(state), Notify::new(), Notify::new());
        Fair { shared: Arc::new(Shared { state, filled, freed, line_room, socket_room }) }
    }

    /// Queue `piece` of `cost` in the line of `key`, once there is room for
    /// it; `Err` once the queue is shut, as its socket ended.
    pub async fn push(&self, key: K, piece: T, cost: usize) -> Result<(), Shut> {
        loop {
            // Enabled before the look, so that room given back meanwhile wakes it.
            let freed = self.shared.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            {
                let mut state = lock(&self.shared.state);
                if state.shut {
                    return Err(Shut);
                }
                if self.shared.fits(&state, &key, cost) {
                    self.shared.queue(&mut state, key, piece, cost);
                    return Ok(());
                }
            }
            freed.await;
        }
    }

    /// [`Fair::push`] with no wait: [`Refused::Full`] when there is no room.
    pub fn try_push(&self, key: K, piece: T, cost: usize) -> Result<(), Refused> {
        let mut state = lock(&self.shared.state);
        if state.shut {
            return Err(Refused::Shut);
        }
        if !self.shared.fits(&state, &key, cost) {
            return Err(Refused::Full);
        }
        self.shared.queue(&mut state, key, piece, cost);
        Ok(())
    }

    /// Queue `piece` after what the line of `key` holds, with no room and no
    /// wait: a session's end after its last bytes, which must never wait for
    /// the room that its own bytes hold.
    pub fn push_last(&self, key: K, piece: T) -> Result<(), Shut> {
        let mut state = lock(&self.shared.state);
        if state.shut {
            return Err(Shut);
        }
        self.shared.queue(&mut state, key, piece, 0);
        Ok(())
    }

    /// The next turn: a piece of the line whose turn it is, which then goes
    /// to the end of the round while it holds more; `None` once the queue is
    /// shut and each piece went out. Safe to drop in a `select!`: a turn is
    /// taken and returned in one poll.
    pub async fn next(&self) -> Option<Turn<K, T>> {
        loop {
            let filled = self.shared.filled.notified();
            tokio::pin!(filled);
            filled.as_mut().enable();
            {
                let mut state = lock(&self.shared.state);
                if let Some(turn) = self.turn(&mut state) {
                    return Some(turn);
                }
                if state.shut {
                    return None;
                }
            }
            filled.await;
        }
    }

    fn turn(&self, state: &mut State<K, T>) -> Option<Turn<K, T>> {
        while let Some(key) = state.turns.pop_front() {
            let Some(line) = state.lines.get_mut(&key) else { continue };
            let Some((piece, cost)) = line.pieces.pop_front() else { continue };
            let serial = line.serial;
            if !line.pieces.is_empty() {
                state.turns.push_back(key.clone());
            }
            let slot = Slot { shared: self.shared.clone(), key: key.clone(), serial, cost };
            return Some(Turn { key, piece, slot });
        }
        None
    }

    /// Drop what the line of `key` holds, as its session ended: its room goes
    /// back, and the other lines keep their turns. A piece in flight keeps its
    /// room until it is written.
    pub fn drop_line(&self, key: &K) {
        let mut state = lock(&self.shared.state);
        let Some(line) = state.lines.remove(key) else { return };
        let queued: usize = line.pieces.iter().map(|(_, cost)| cost).sum();
        state.used = state.used.saturating_sub(queued);
        state.turns.retain(|k| k != key);
        drop(state);
        // The pieces go outside the lock.
        drop(line);
        self.shared.freed.notify_waiters();
    }

    /// No piece more: the writer takes what is queued, then hears `None`,
    /// and each sender that waits for room hears [`Shut`].
    pub fn shut(&self) {
        lock(&self.shared.state).shut = true;
        self.shared.filled.notify_waiters();
        self.shared.freed.notify_waiters();
    }

    /// The room taken now, the pieces in flight too.
    pub fn used(&self) -> usize {
        lock(&self.shared.state).used
    }

    /// How many lines hold a piece, or one in flight.
    pub fn lines(&self) -> usize {
        lock(&self.shared.state).lines.len()
    }
}

impl<K: Eq + Hash + Clone, T> Shared<K, T> {
    /// Whether a piece of `cost` fits the line of `key`: an empty line takes
    /// one piece whatever the others hold; else its own room and the
    /// socket's must hold it.
    fn fits(&self, state: &State<K, T>, key: &K, cost: usize) -> bool {
        let line = state.lines.get(key).map_or(0, |line| line.used);
        line == 0 || (line + cost <= self.line_room && state.used + cost <= self.socket_room)
    }

    fn queue(&self, state: &mut State<K, T>, key: K, piece: T, cost: usize) {
        state.made += 1;
        let made = state.made;
        let new = || Line { pieces: VecDeque::new(), used: 0, serial: made };
        let line = state.lines.entry(key.clone()).or_insert_with(new);
        let first = line.pieces.is_empty();
        line.pieces.push_back((piece, cost));
        line.used += cost;
        state.used += cost;
        if first {
            state.turns.push_back(key);
        }
        self.filled.notify_waiters();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
#[path = "fair_tests.rs"]
mod tests;
