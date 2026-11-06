//! The signed lists kept in the cache (T-346): the newest list of each key
//! that this binary trusts, with its signature, so that a binary keeps the
//! other deployments when the default's domain is gone. Each read checks
//! each list again, as the trust and the time may have moved since it was
//! kept, and a list's serial never goes back for its key.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::signed::{self, Checked, Keys, Refused, Signed};
use crate::cache;
use crate::identity::PublicKey;
use crate::relay::{default_relay_host, Relay};

/// The cache file of the lists.
pub const FILE: &str = "relay-deployments.json";
/// The most lists kept, one for each key: with each at its largest, the
/// file stays under the cache's bound on a file.
pub const MAX_KEPT: usize = 4;
/// The most hosts of other deployments that follow the default list: a
/// hopeless run stays short, and each deployment's first host comes first.
pub const MAX_OTHERS: usize = 4;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Lists {
    lists: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    fetched_ms: i64,
    signed: Value,
}

/// What [`take`] did with a list that holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// Kept: the first of its key, or newer than the one kept.
    Kept(Checked),
    /// The list kept already, of the same serial.
    Same(Checked),
}

impl Taken {
    pub fn checked(&self) -> &Checked {
        match self {
            Taken::Kept(c) | Taken::Same(c) => c,
        }
    }
}

/// The cache's directories: `None` is this process's.
pub type Dirs<'a> = Option<&'a [PathBuf]>;

fn load(dirs: Dirs<'_>) -> Lists {
    let text = match dirs {
        Some(dirs) => cache::load_file_from(dirs, FILE),
        None => cache::load_file(FILE),
    };
    text.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// Keep `lists`, the oldest dropped first while the file would pass the
/// cache's bound, which a read refuses whole.
fn store(dirs: Dirs<'_>, lists: &mut Lists) -> Result<PathBuf, String> {
    let mut body = serde_json::to_vec(lists).map_err(|e| e.to_string())?;
    while body.len() as u64 > cache::MAX_FILE && lists.lists.len() > 1 {
        lists.lists.remove(0);
        body = serde_json::to_vec(lists).map_err(|e| e.to_string())?;
    }
    match dirs {
        Some(dirs) => cache::store_file_in_first(dirs, FILE, &body),
        None => cache::store_file(FILE, &body),
    }
}

/// The serial of a kept list of `key` whose signature still verifies, with
/// no clock: a list that ended still holds its serial. A kept list that does
/// not verify is no list, and the next one replaces it.
fn kept_serial(entry: &Entry, key: &PublicKey) -> Option<u64> {
    let kept = Signed::of_value(&entry.signed).ok().filter(|s| s.key == *key)?;
    signed::verified(&kept).ok().map(|doc| doc.serial)
}

/// Check `signed` and keep it, when it holds and is not older than the list
/// kept of its key: what was done, or why not.
pub fn take(signed: &Signed, keys: &Keys, now_ms: i64) -> Result<Taken, Refused> {
    take_in(None, signed, keys, now_ms)
}

/// [`take`] with the cache's directories given (for tests).
pub fn take_in(dirs: Dirs<'_>, signed: &Signed, keys: &Keys, now_ms: i64) -> Result<Taken, Refused> {
    let checked = signed::check(signed, keys, now_ms.div_euclid(1000))?;
    let mut lists = load(dirs);
    let at = lists.lists.iter().position(|e| kept_serial(e, &signed.key).is_some());
    if let Some(i) = at {
        let kept = kept_serial(&lists.lists[i], &signed.key).unwrap_or(0);
        if checked.doc.serial < kept {
            return Err(Refused::Older { serial: checked.doc.serial, kept });
        }
        if checked.doc.serial == kept {
            return Ok(Taken::Same(checked));
        }
        lists.lists.remove(i);
    }
    // One list for each key; the oldest goes first past the bound.
    lists.lists.retain(|e| Signed::of_value(&e.signed).is_ok_and(|s| s.key != signed.key));
    while lists.lists.len() >= MAX_KEPT {
        lists.lists.remove(0);
    }
    lists.lists.push(Entry { fetched_ms: now_ms, signed: signed.to_value() });
    // A list that cannot be kept still holds for this run's caller.
    let _ = store(dirs, &mut lists);
    Ok(Taken::Kept(checked))
}

/// A kept list, as each read sees it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// When it was kept.
    pub fetched_ms: i64,
    /// The list, when it holds now; else why not, with its key when it has one.
    pub held: Result<Checked, (Option<PublicKey>, Refused)>,
}

/// Each list kept, checked again now with `keys`.
pub fn seen(keys: &Keys, now_ms: i64) -> Vec<Seen> {
    seen_in(None, keys, now_ms)
}

/// [`seen`] with the cache's directories given (for tests).
pub fn seen_in(dirs: Dirs<'_>, keys: &Keys, now_ms: i64) -> Vec<Seen> {
    let lists = load(dirs);
    let each = lists.lists.into_iter().map(|entry| {
        let held = match Signed::of_value(&entry.signed) {
            Ok(s) => signed::check(&s, keys, now_ms.div_euclid(1000)).map_err(|why| (Some(s.key), why)),
            Err(why) => Err((None, Refused::Form(why))),
        };
        Seen { fetched_ms: entry.fetched_ms, held }
    });
    each.collect()
}

/// The lists that hold now, in the order kept.
pub fn in_force(keys: &Keys, now_ms: i64) -> Vec<Checked> {
    seen(keys, now_ms).into_iter().filter_map(|s| s.held.ok()).collect()
}

/// Whether `relay` is a host of the default deployment, whose pool needs no
/// signature.
pub fn of_default(relay: &Relay) -> bool {
    relay.host.eq_ignore_ascii_case(default_relay_host()) || super::same_deployment(default_relay_host(), &relay.host)
}

/// The hosts of the other deployments of `lists`, for the default list: the
/// first host of each deployment, then the second of each, and so on, each
/// once, none of the default's own, [`MAX_OTHERS`] at most. None when the
/// run has a token of `PODSSH_RELAY_TOKEN` (`token_given`): that token is
/// the default deployment's, and goes to no other.
pub fn others_of(lists: &[Checked], token_given: bool) -> Vec<Relay> {
    if token_given {
        return Vec::new();
    }
    let deployments: Vec<&signed::Deployment> = lists.iter().flat_map(|c| c.doc.deployments.iter()).collect();
    let mut out: Vec<Relay> = Vec::new();
    for round in 0..signed::MAX_HOSTS {
        for deployment in &deployments {
            let Some(relay) = deployment.hosts.get(round) else { continue };
            if out.len() < MAX_OTHERS && !of_default(relay) && !out.contains(relay) {
                out.push(relay.clone());
            }
        }
    }
    out
}

/// The hosts of other deployments that follow the default list in this
/// process, as [`others_of`] gives them.
pub fn other_hosts(now_ms: i64) -> Vec<Relay> {
    let given = std::env::var(crate::token::TOKEN_ENV).is_ok_and(|v| !v.trim().is_empty());
    others_of(&in_force(&Keys::of_process(), now_ms), given)
}
