//! A key's share of the role's table of pairs (T-630). A role that mints for
//! the keys of a list, or for the net's members, lends each of them a part of
//! its reverse road, and one key that pairs in a loop must not hold each place
//! of the table for the 72 h of a pair. Half the table is a reserve, in equal
//! parts for the keys that the role mints for now; the other half goes to
//! whoever asks first, so that a busy key among idle ones borrows past its own
//! part. A key makes a pair within its reserve while the table has a place,
//! and past it while the places left after this one still hold each other
//! key's unused reserve. A pair keeps its maker's fingerprint, in memory and
//! in the kept file; a pair of a role for anyone, or of a file of before,
//! counts against no key.

use std::collections::HashMap;
use std::sync::Arc;

use super::{NotMade, Pair, Pairs, MAX_PAIRS};

/// Who asks for a pair: the fingerprint of the key that proved itself, and
/// how many keys the role mints for now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asker {
    pub key: String,
    pub keys: usize,
}

/// The places of a table of `room` that each of `keys` keys keeps for itself:
/// half the table in equal parts, one at least; the whole table for a key
/// alone, and for a role that cannot count its keys.
pub fn reserve(room: usize, keys: usize) -> usize {
    match keys {
        0 | 1 => room,
        n => (room / (2 * n)).max(1),
    }
}

impl Pairs {
    /// The same pairs in a table of `room` places in the place of
    /// [`MAX_PAIRS`]: a test's small table.
    pub fn with_room(mut self, room: usize) -> Pairs {
        self.room = Some(room.max(1));
        self
    }

    /// The places of the table.
    pub fn room(&self) -> usize {
        self.room.unwrap_or(MAX_PAIRS)
    }
}

/// Whether `asker` may make one more pair in `map`, a table of `room` places
/// with one free at least: within its reserve, always; past it, while the
/// places left after this one still hold each other key's unused reserve. A
/// refusal holds the key's own count and reserve, and nothing of another's.
pub(super) fn check(map: &HashMap<String, Arc<Pair>>, room: usize, asker: &Asker) -> Result<(), NotMade> {
    let share = reserve(room, asker.keys);
    let mut held: HashMap<&str, usize> = HashMap::new();
    for maker in map.values().filter_map(|p| p.maker.as_deref()) {
        *held.entry(maker).or_default() += 1;
    }
    let holds = held.get(asker.key.as_str()).copied().unwrap_or(0);
    if holds < share {
        return Ok(());
    }
    // Each other key's reserve, less what it holds of it. A key that left the
    // list and still holds pairs counts as one of the others: a reserve less
    // for those that stay, never one more.
    let others = asker.keys.saturating_sub(1);
    let used: usize = held.iter().filter(|(key, _)| **key != asker.key.as_str()).map(|(_, n)| (*n).min(share)).sum();
    let owed = (others * share).saturating_sub(used);
    let free = room.saturating_sub(map.len());
    if free > owed {
        Ok(())
    } else {
        Err(NotMade::Share { holds, share })
    }
}
