//! What a node's road keeps of its run for the binary that takes its place
//! (T-679), beside the sessions: what the road needs to make its own
//! connection again as the same, so that each client finds the node where
//! it was. A node's key for this run only (`--ephemeral-key`), which a ticket
//! of the iroh road or the DERP road names; a quick tunnel's name and its
//! credentials, which the clients of its sessions hold. Each part goes with
//! the sessions, in the handover's anonymous memory, never in the
//! environment or a path; the binary after reads them before anything
//! connects, and keeps them for its own next upgrade. A binary that did not
//! start leaves them to this one, whose roads start again with them.

use std::collections::BTreeMap;
use std::sync::Mutex;

use podssh_relay::identity::file::{Key, Place};
use podssh_relay::identity::Identity;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;

/// The part of the node's key for this run only: its seed.
pub const KEY: &str = "key";
/// The part of the quick tunnel: its id, name, account and secret.
pub const QUICK: &str = "quick-tunnel";
/// The version of the bytes of a part that this build writes, and the only
/// one that it reads: a part of another is left, and its road starts anew.
const VERSION: u8 = 1;

/// This run's parts, by name: those that the binary before this one handed
/// over, and those that this one's roads kept since.
static PARTS: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>> = Mutex::new(BTreeMap::new());

fn lock() -> std::sync::MutexGuard<'static, BTreeMap<String, Zeroizing<Vec<u8>>>> {
    PARTS.lock().unwrap_or_else(|e| e.into_inner())
}

/// The parts that the binary before this one handed over, at the start.
#[cfg(unix)]
pub(super) fn taken(parts: Vec<super::state::Part>) {
    let mut kept = lock();
    for part in parts {
        kept.insert(part.name, part.bytes);
    }
}

/// Each part of this run, for the handover.
#[cfg(unix)]
pub(super) fn all() -> Vec<super::state::Part> {
    let kept = lock();
    kept.iter().map(|(name, bytes)| super::state::Part { name: name.clone(), bytes: bytes.clone() }).collect()
}

/// `body` as the part `name` of this run, behind its version.
pub(crate) fn keep(name: &str, body: &[u8]) {
    let mut bytes = Zeroizing::new(Vec::with_capacity(1 + body.len()));
    bytes.push(VERSION);
    bytes.extend_from_slice(body);
    lock().insert(name.to_string(), bytes);
}

/// The body of the part `name` of this run, when it has one of this
/// build's version.
pub(crate) fn part(name: &str) -> Option<Zeroizing<Vec<u8>>> {
    let kept = lock();
    match kept.get(name)?.split_first() {
        Some((&VERSION, body)) => Some(Zeroizing::new(body.to_vec())),
        _ => None,
    }
}

/// The part `name` goes: what it held no longer stands, and the binary
/// after makes its own.
pub(crate) fn forget(name: &str) {
    lock().remove(name);
}

/// The node's key at `place`. A key for this run only is the same for the
/// whole run: across an upgrade in place, and when a binary did not start
/// and the road starts again, as a ticket of the iroh road or the DERP road
/// names it. A key of a file is read as before.
pub(crate) fn node_key(place: &Place) -> Result<Key, Refusal> {
    if !matches!(place, Place::Ephemeral) {
        return crate::channel::load_node_key(place);
    }
    let kept = part(KEY).and_then(|body| <[u8; 32]>::try_from(&body[..]).ok()).map(Zeroizing::new);
    if let Some(seed) = kept {
        return Ok(Key { identity: Identity::from_seed(&seed), path: None, made: false });
    }
    let key = crate::channel::load_node_key(place)?;
    keep(KEY, &key.identity.seed()[..]);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key for this run only stays the run's (T-679): the second load
    /// gives the first's key, as the binary after an upgrade loads it from
    /// the part; a key of a file is no part.
    #[test]
    fn a_key_for_this_run_only_stays_the_run_s() {
        let first = node_key(&Place::Ephemeral).unwrap();
        let again = node_key(&Place::Ephemeral).unwrap();
        assert_eq!(first.identity.public(), again.identity.public(), "a new key in the same run");
        assert!(again.path.is_none());
        let seed = part(KEY).expect("the key is a part of the run");
        assert_eq!(&seed[..], &first.identity.seed()[..]);
    }

    /// A part of another version is left: its road starts anew.
    #[test]
    fn a_part_of_another_version_is_left() {
        keep("test-version", b"body");
        assert_eq!(part("test-version").as_deref().map(|b| &b[..]), Some(&b"body"[..]));
        lock().insert("test-version".into(), Zeroizing::new(vec![VERSION + 1, 1, 2]));
        assert!(part("test-version").is_none());
        forget("test-version");
        assert!(part("test-version").is_none());
    }
}
