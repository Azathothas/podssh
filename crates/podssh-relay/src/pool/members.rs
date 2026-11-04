//! The net's relay members (T-617): a member of the user's net with the role
//! `relay` and its host in the net's document, whose role signs its list of
//! deployments ([`super::signed`]) with the key that the net names for it.
//! A run that opens a session on the default list asks that host's
//! `/relays.json` at most once a day, before its race, and takes the list
//! there only by that member's key, as [`super::kept`] takes each list; so a
//! client that holds the net learns its own role's deployments with no
//! `--relay-host`. The ask is a plain request with no token, and its host
//! joins no list by it: the role's list names where sessions go. The binary
//! reads the net and gives the members ([`set_by_net`]), as it gives the
//! keys, so that no SSH code comes into the library.

use std::future::Future;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use podssh_ws::client::open_tls;
use podssh_ws::{dial, ProxyChoice, Trust};
use serde::{Deserialize, Serialize};

use super::kept::{self, Dirs, Taken};
use super::signed::{Keys, Signed};
use crate::cache;
use crate::identity::KeyName;
use crate::relay::{Relay, RelayList};
use crate::token::relay_name;

/// The cache file of the asks.
pub const FILE: &str = "relay-members.json";
/// A member is asked once a day, whatever it answered: a role that is down
/// costs a run one bounded wait a day, never one at each run.
pub const EVERY_MS: i64 = 24 * 3600 * 1000;
/// The bound on one ask.
pub const STEP: Duration = Duration::from_secs(5);
/// The bound on the asks of one run, which wait before its race.
pub const BUDGET: Duration = Duration::from_secs(8);
/// The most members asked: as many as the cache keeps lists of.
pub const MOST: usize = kept::MAX_KEPT;
/// The most asks that the file keeps, the oldest dropped first.
const MAX_ASKS: usize = 16;

/// A relay member of the net, as the binary gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Its name and the net's, for the words.
    pub name: String,
    pub net: String,
    /// The key that the net names for it, which signs its role's list.
    pub key: KeyName,
    /// Where its role serves `/relays.json`.
    pub host: Relay,
}

/// The members of the net that the binary read.
static BY_NET: RwLock<Vec<Member>> = RwLock::new(Vec::new());

/// The relay members of the net that this host holds, for this process: the
/// first [`MOST`] of them, so that a net of many asks no more.
pub fn set_by_net(mut members: Vec<Member>) {
    members.truncate(MOST);
    *BY_NET.write().unwrap_or_else(|e| e.into_inner()) = members;
}

/// The members that [`set_by_net`] gave.
pub fn of_process() -> Vec<Member> {
    BY_NET.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// One ask of a member, as the cache keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ask {
    /// The host asked, as `host` or `host:port`, and the member's key by its
    /// fingerprint: a new host or a new key is asked anew.
    pub host: String,
    pub key: String,
    pub asked_ms: i64,
    /// The serial of the list that it gave, kept now or kept already.
    #[serde(default)]
    pub serial: Option<u64>,
    /// Why no list was taken. Neither: the run that asked ended first.
    #[serde(default)]
    pub why: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Asks {
    asks: Vec<Ask>,
}

impl Asks {
    fn of(&self, member: &Member) -> Option<&Ask> {
        let (host, key) = (relay_name(&member.host), member.key.fingerprint());
        self.asks.iter().find(|a| a.host == host && a.key == key)
    }

    /// `ask` in the place of the one of its host and key.
    fn put(&mut self, ask: Ask) {
        self.asks.retain(|a| !(a.host == ask.host && a.key == ask.key));
        self.asks.push(ask);
        while self.asks.len() > MAX_ASKS {
            let oldest = self.asks.iter().enumerate().min_by_key(|(_, a)| a.asked_ms).map(|(i, _)| i).unwrap_or(0);
            self.asks.remove(oldest);
        }
    }
}

fn load(dirs: Dirs<'_>) -> Asks {
    let text = match dirs {
        Some(dirs) => cache::load_file_from(dirs, FILE),
        None => cache::load_file(FILE),
    };
    text.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn store(dirs: Dirs<'_>, asks: &Asks) -> Result<PathBuf, String> {
    let body = serde_json::to_vec(asks).map_err(|e| e.to_string())?;
    match dirs {
        Some(dirs) => cache::store_file_in_first(dirs, FILE, &body),
        None => cache::store_file(FILE, &body),
    }
}

/// Whether a member whose last ask is `last` is due at `now_ms`: never
/// asked, or a day ago or more; an ask from ahead of the clock, which went
/// back, is due too, as the role's signer reads its own day.
pub fn due(last: Option<&Ask>, now_ms: i64) -> bool {
    last.is_none_or(|a| !(0..EVERY_MS).contains(&now_ms.saturating_sub(a.asked_ms)))
}

/// The last ask of `member` that the cache keeps.
pub fn last_ask(member: &Member) -> Option<Ask> {
    load(None).of(member).cloned()
}

/// The list of a `/relays.json` body that `member`'s host served, taken by
/// that member's key alone: a list of another key is not the member's,
/// whatever else trusts it. Then the rules of [`kept::take`]: a trusted key
/// (`PODSSH_RELAY_KEYS=none` trusts none), its signature, its life, and a
/// serial that does not go back.
pub fn take_from(dirs: Dirs<'_>, member: &Member, body: &[u8], keys: &Keys, now_ms: i64) -> Result<Taken, String> {
    let signed = match Signed::of_body(body) {
        None => return Err("its /relays.json carries no signed list: podssh relay serve --deployment signs one".into()),
        Some(read) => read?,
    };
    if !member.key.matches(&signed.key) {
        return Err(format!(
            "its list is signed by {}, not by the member's key {}",
            signed.key.fingerprint(),
            member.key.fingerprint()
        ));
    }
    kept::take_in(dirs, &signed, keys, now_ms).map_err(|why| why.to_string())
}

/// `host`'s `/relays.json` within `step`, as the pool's refresh reads the
/// default host's: through the proxy of the environment, TLS checked by the
/// host's own name.
async fn fetch(host: Relay, trust: &Trust, step: Duration) -> Result<Vec<u8>, String> {
    let proxy = ProxyChoice::FromEnvironment;
    let header = if host.port == 443 { host.host.clone() } else { dial::authority(&host.host, host.port) };
    let asked = async {
        let mut tls =
            open_tls(&host.host, host.port, &host.host, trust, &proxy, step).await.map_err(|e| e.to_string())?;
        super::body_of(&mut tls, &header).await
    };
    match tokio::time::timeout(step, asked).await {
        Ok(done) => done,
        Err(_) => Err(format!("no answer within {} s", step.as_secs())),
    }
}

/// Ask each member of this process that is due, before a run's race: how
/// many lists were newly kept. None is asked with `PODSSH_OFFLINE`, with a
/// token of `PODSSH_RELAY_TOKEN` (the default's, which takes no other
/// deployment), or with no cache, which could keep no day between two asks.
pub async fn ask_due(trust: &Trust) -> usize {
    let members = of_process();
    let given = std::env::var(crate::token::TOKEN_ENV).is_ok_and(|v| !v.trim().is_empty());
    if members.is_empty() || crate::open::offline() || given || cache::candidate_dirs().is_empty() {
        return 0;
    }
    let keys = Keys::of_process();
    ask_due_with(None, &members, &keys, super::now_ms(), move |host, step| fetch(host, trust, step)).await
}

/// [`ask_due`] with the cache's directories, the members, the keys, the time
/// and the request given (for tests): one member at a time, within
/// [`BUDGET`]. Each ask is kept before it is made, so that it is once a day
/// whatever its end, and a run that cannot keep it asks nothing.
pub async fn ask_due_with<F, A>(dirs: Dirs<'_>, members: &[Member], keys: &Keys, now_ms: i64, mut ask: F) -> usize
where
    F: FnMut(Relay, Duration) -> A,
    A: Future<Output = Result<Vec<u8>, String>>,
{
    let started = Instant::now();
    let mut kept = 0;
    for member in members {
        let left = BUDGET.saturating_sub(started.elapsed());
        if left.is_zero() {
            break;
        }
        let mut asks = load(dirs);
        if !due(asks.of(member), now_ms) {
            continue;
        }
        let (host, key) = (relay_name(&member.host), member.key.fingerprint());
        asks.put(Ask { host: host.clone(), key: key.clone(), asked_ms: now_ms, serial: None, why: None });
        if store(dirs, &asks).is_err() {
            break;
        }
        let taken = match ask(member.host.clone(), STEP.min(left)).await {
            Ok(body) => take_from(dirs, member, &body, keys, now_ms),
            Err(why) => Err(why),
        };
        kept += usize::from(matches!(taken, Ok(Taken::Kept(_))));
        let (serial, why) = match &taken {
            Ok(t) => (Some(t.checked().doc.serial), None),
            Err(why) => (None, Some(podssh_ws::text::one_line(why))),
        };
        let mut asks = load(dirs);
        asks.put(Ask { host, key, asked_ms: now_ms, serial, why });
        let _ = store(dirs, &asks);
    }
    kept
}

/// `list` with the hosts of the lists that this run's asks kept, after the
/// ones that it had: a list that the user named, or one that took nothing
/// new, as it is.
pub async fn refreshed(list: &RelayList, trust: &Trust) -> RelayList {
    if list.explicit || ask_due(trust).await == 0 {
        return list.clone();
    }
    crate::relay::with_others(list.clone(), kept::other_hosts(super::now_ms()))
}

#[cfg(test)]
#[path = "members_tests.rs"]
mod tests;
