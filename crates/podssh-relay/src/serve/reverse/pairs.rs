//! The pairs of the role's reverse road (T-427): made by `POST /v1/pair`,
//! each with a token for its node, one for its operators and one for its
//! stop, and the contract's life of 72 h at most. A pair keeps the SHA-256 of
//! each token, never the token, so that its file gives nobody a credential;
//! a token is compared by its digest, in constant time. The pairs live in
//! memory and, when the user names a file, in that file of mode 0600, so
//! that a node and its sessions come back after a restart. Its owner, who
//! alone holds the stop token, renews a pair (T-592): 72 h from then, its
//! tokens the same, so that each operator's file keeps working. A pair made
//! with `once` (T-226) takes its connect token at one upgrade alone: a token
//! that leaks after it is worth nothing, also after a restart. Its node
//! registers tokens of one leg, and rotates its stop token ([`legs`], T-615).
//! A key that the role mints for has a share of the table ([`share`], T-630).
//! Its owner halts it and resumes it, in memory alone ([`super::halt`], T-647).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use super::outbox::{Outbox, Writers};
use crate::reverse::framing::SessionId;

/// The contract's longest life of a pair.
pub const LIFETIME_MS: u64 = 72 * 3600 * 1000;
/// The pairs that the role keeps at once; past it, a new pair waits (`429`).
pub const MAX_PAIRS: usize = 4096;
/// How long after a session's close a frame of the node for it is one that
/// was on its way (T-421): dropped, where an id never given closes the
/// node's socket with `1003`. The stand-in's grace.
pub const IN_FLIGHT: Duration = Duration::from_secs(2);

/// Which token a request carries, by its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Node,
    Connect,
    Stop,
}

/// A new pair, with its tokens, for the answer of `/v1/pair` only.
pub struct Made {
    pub name: String,
    pub node: String,
    pub connect: String,
    pub stop: String,
    pub expires_ms: u64,
    /// Its connect token takes one upgrade alone (T-226).
    pub once: bool,
}

impl std::fmt::Debug for Made {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Made").field("name", &self.name).field("tokens", &"<redacted>").finish()
    }
}

/// Why no pair was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotMade {
    /// The name drawn is in use: `409`, which a client answers with a new
    /// request, as the contract's short index says.
    NameInUse,
    /// [`MAX_PAIRS`] are kept: `429`.
    Full,
    /// The key holds `holds` pairs, past its reserve of `share`, and the
    /// places left are the other keys' (T-630): `429`, in words of its own.
    Share { holds: usize, share: usize },
    /// No randomness, or a file that took no write.
    Failed(String),
}

/// One pair and what its sockets share.
pub struct Pair {
    pub name: String,
    /// When it ends, in ms since the epoch: later at each renewal (T-592),
    /// which the timers of its sockets read again ([`Pair::expires_ms`]).
    expires: AtomicU64,
    /// The cap of one session, both ways together: the contract's 64 MiB,
    /// none on a carrier (T-595).
    pub session_bytes: u64,
    digests: [[u8; 32]; 3],
    state: Mutex<State>,
    /// Its connect token takes one upgrade alone (T-226).
    pub once: bool,
    /// The one upgrade of a pair of `once` was taken.
    spent: AtomicBool,
    /// The tokens of one leg that its node registered, and its stop token
    /// as its node rotated it (T-615).
    held: legs::Held,
    /// The fingerprint of the key that made it, for its share (T-630); none
    /// for a role that mints for anyone, and for a pair of before.
    maker: Option<String>,
}

/// The node's socket, while one is joined.
pub struct NodeLink {
    pub serial: u64,
    /// `None` while its upgrade is answered: a second node meets `409`.
    pub outbox: Option<Outbox>,
}

/// What the node answered to an `open`.
#[derive(Debug)]
pub enum Answer {
    Ready,
}

/// One session between an operator and the node.
pub struct Session {
    pub operator: Outbox,
    pub ready: bool,
    /// Told when the node readies the session; dropped when it refuses it.
    pub answer: Option<oneshot::Sender<Answer>>,
    /// Payload both ways, for the contract's cap of 64 MiB a session.
    pub bytes: u64,
}

/// The state of a pair's sockets.
#[derive(Default)]
pub struct State {
    pub node: Option<NodeLink>,
    pub sessions: HashMap<SessionId, Session>,
    /// Sessions closed in the last [`IN_FLIGHT`], with when, and whether a
    /// frame of theirs was said to be dropped.
    pub closed: HashMap<SessionId, (Instant, bool)>,
    /// Stopped or expired: nothing joins it again.
    pub ended: bool,
    /// Its owner keeps its operators out, in memory alone (T-647).
    pub halted: Option<super::halt::Halt>,
}

impl State {
    /// Forget `id`, and keep it for the grace of a frame in flight.
    pub fn forget(&mut self, id: &SessionId) -> Option<Session> {
        let now = Instant::now();
        self.closed.retain(|_, (at, _)| now.duration_since(*at) < IN_FLIGHT);
        let session = self.sessions.remove(id);
        if session.is_some() {
            self.closed.insert(*id, (now, false));
        }
        session
    }

    /// Whether `id` closed within [`IN_FLIGHT`]; `Some(true)` the first time,
    /// for a line that says so once.
    pub fn in_flight(&mut self, id: &SessionId) -> Option<bool> {
        let (at, said) = self.closed.get_mut(id)?;
        if at.elapsed() >= IN_FLIGHT {
            return None;
        }
        Some(!std::mem::replace(said, true))
    }

    /// The node's writer, when a node is joined.
    pub fn node_outbox(&self) -> Option<Outbox> {
        self.node.as_ref().and_then(|n| n.outbox.clone())
    }
}

impl Pair {
    /// The one pair of a carrier's role (T-595), named `name`: it is in no
    /// table, so no request finds it and no token takes it; it never expires,
    /// and its sessions have no cap of bytes, as the relay's limits do not
    /// hold on a stream of the user's.
    pub fn carried(name: &str) -> Pair {
        Pair::new(name.to_string(), u64::MAX, u64::MAX, [[0; 32]; 3])
    }

    fn new(name: String, expires_ms: u64, session_bytes: u64, digests: [[u8; 32]; 3]) -> Pair {
        let (expires, state, held) = (AtomicU64::new(expires_ms), Default::default(), Default::default());
        let (once, spent, maker) = (false, AtomicBool::new(false), None);
        Pair { name, expires, session_bytes, digests, state, once, spent, held, maker }
    }

    /// Take the one upgrade of a pair of `once` (T-226): `true` the first
    /// time alone, also for two upgrades at once; `true` for each upgrade of
    /// another pair.
    pub fn take_connect(&self) -> bool {
        !self.once || self.spent.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    /// Whether the connect token of a pair of `once` was taken.
    pub fn connect_spent(&self) -> bool {
        self.once && self.spent.load(Ordering::SeqCst)
    }

    /// When the pair ends now, in ms since the epoch.
    pub fn expires_ms(&self) -> u64 {
        self.expires.load(Ordering::SeqCst)
    }

    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn takes(&self, role: Role, token: &str) -> bool {
        // The stop token as its node rotated it (T-615).
        if role == Role::Stop {
            return self.held.takes_stop(&self.digests[2], &digest(token));
        }
        let wanted = &self.digests[role as usize];
        same(wanted, &digest(token))
    }
}

/// The pairs of one role.
#[derive(Default)]
pub struct Pairs {
    map: Mutex<HashMap<String, Arc<Pair>>>,
    /// Where they are kept, when the user named a file.
    file: Option<PathBuf>,
    serial: AtomicU64,
    pub writers: Arc<Writers>,
    /// The sockets' own tasks, each until its peer answered the role's
    /// Close: a planned stop ends no socket before that, as a reset can lose
    /// the Close on its way (T-255).
    pub live: Arc<Writers>,
    /// A planned stop closes each socket: none joins meanwhile (T-255).
    stopping: AtomicBool,
    /// The role's mailbox of the pairing by code, whose codes give a pair's
    /// operator's part (T-086): one table for each role.
    pub mailbox: crate::serve::mailbox::table::Table,
    /// The places of the table: [`MAX_PAIRS`], or a test's ([`Pairs::with_room`]).
    room: Option<usize>,
}

impl Pairs {
    /// The pairs kept in `file`, or none; a missing file is a role's first
    /// run. A file that is not private, or not the role's, is refused.
    pub fn open(file: Option<PathBuf>) -> Result<Pairs, String> {
        let pairs = Pairs { file, ..Pairs::default() };
        if let Some(path) = &pairs.file {
            let now = super::super::tokens::now_ms();
            let mut map = pairs.map.lock().unwrap_or_else(|e| e.into_inner());
            for kept in load(path)?.into_iter().filter(|p| p.expires > now) {
                let digests = kept.digests()?;
                let mut pair = Pair::new(kept.name, kept.expires, super::SESSION_BYTES, digests);
                // Its maker's share holds across a restart (T-630).
                (pair.once, pair.spent, pair.maker) = (kept.once, AtomicBool::new(kept.spent), kept.maker);
                // The stop token to come, which its node asked for (T-615).
                pair.held.next_stop(kept.next_stop.as_deref(), &pair.name)?;
                map.insert(pair.name.clone(), Arc::new(pair));
            }
        }
        Ok(pairs)
    }

    /// A new pair, made at `now_ms`, kept in the file when there is one.
    pub fn make(&self, now_ms: u64) -> Result<Made, NotMade> {
        self.make_with(now_ms, false)
    }

    /// [`Pairs::make`], with a connect token that takes one upgrade alone
    /// when `once` (T-226).
    pub fn make_with(&self, now_ms: u64, once: bool) -> Result<Made, NotMade> {
        self.make_for(now_ms, once, None)
    }

    /// [`Pairs::make_with`] for `asker`, a key that proved itself, within its
    /// share of the table (T-630); with none, the pair counts against no key.
    pub fn make_for(&self, now_ms: u64, once: bool, asker: Option<&Asker>) -> Result<Made, NotMade> {
        let made = Made {
            name: format!("p-{}", hex(&random(16).map_err(NotMade::Failed)?)),
            node: base36(64).map_err(NotMade::Failed)?,
            connect: base36(64).map_err(NotMade::Failed)?,
            stop: base36(64).map_err(NotMade::Failed)?,
            expires_ms: now_ms + LIFETIME_MS,
            once,
        };
        {
            let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            map.retain(|_, p| p.expires_ms() > now_ms);
            if map.contains_key(&made.name) {
                return Err(NotMade::NameInUse);
            }
            if map.len() >= self.room() {
                return Err(NotMade::Full);
            }
            if let Some(asker) = asker {
                share::check(&map, self.room(), asker)?;
            }
            let digests = [digest(&made.node), digest(&made.connect), digest(&made.stop)];
            let mut pair = Pair::new(made.name.clone(), made.expires_ms, super::SESSION_BYTES, digests);
            (pair.once, pair.maker) = (once, asker.map(|a| a.key.clone()));
            map.insert(made.name.clone(), Arc::new(pair));
        }
        if let Err(why) = self.save() {
            // A pair that its file did not take is no pair: nobody holds it.
            self.map.lock().unwrap_or_else(|e| e.into_inner()).remove(&made.name);
            return Err(NotMade::Failed(why));
        }
        Ok(made)
    }

    /// The pair `name` whose `role` token is `token`, unless it expired at
    /// `now_ms` or was ended.
    pub fn find(&self, name: &str, role: Role, token: Option<&str>, now_ms: u64) -> Option<Arc<Pair>> {
        let pair = self.map.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned()?;
        if pair.expires_ms() <= now_ms {
            self.end(name, 1001, "pair expired");
            return None;
        }
        let taken = token.is_some_and(|t| pair.takes(role, t)) && !pair.lock().ended;
        // A connect token of `once` that its upgrade took is refused, at the
        // status too, as each failed authentication is (T-226).
        (taken && !(role == Role::Connect && pair.connect_spent())).then_some(pair)
    }

    /// Take the connect token of `pair` for its upgrade (T-226): `false` for
    /// a token of `once` that an upgrade took, and for one whose use the file
    /// could not keep, so that a restart never gives it a second.
    pub fn spend_connect(&self, pair: &Pair) -> bool {
        pair.take_connect() && (!pair.once || self.save().is_ok())
    }

    /// Renew the pair `name` at `now_ms` (T-592): it ends [`LIFETIME_MS`]
    /// after, never earlier than it did, with its tokens; the file keeps it.
    /// The new expiry, or `None` for no such pair, or one that ended; a file
    /// that took no write leaves the old expiry, and says why. The caller
    /// checked the stop token.
    pub fn renew(&self, name: &str, now_ms: u64) -> Result<Option<u64>, String> {
        let Some(pair) = self.map.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned() else {
            return Ok(None);
        };
        if pair.lock().ended || pair.expires_ms() <= now_ms {
            return Ok(None);
        }
        let before = pair.expires.fetch_max(now_ms.saturating_add(LIFETIME_MS), Ordering::SeqCst);
        if let Err(why) = self.save() {
            pair.expires.store(before, Ordering::SeqCst);
            return Err(why);
        }
        Ok(Some(pair.expires_ms()))
    }

    /// End the pair `name` (a stop, or its expiry): each of its sockets gets
    /// `code` and `why` after what waits for it, and its tokens are refused
    /// from now on. Whether a node was joined, and the sessions that it had.
    pub fn end(&self, name: &str, code: u16, why: &str) -> Option<(bool, usize)> {
        let pair = self.map.lock().unwrap_or_else(|e| e.into_inner()).remove(name)?;
        let _ = self.save();
        let mut state = pair.lock();
        state.ended = true;
        let node = state.node.take().and_then(|n| n.outbox);
        let sessions: Vec<Session> = state.sessions.drain().map(|(_, s)| s).collect();
        drop(state);
        for session in &sessions {
            session.operator.close(code, why);
        }
        if let Some(node) = &node {
            node.close(code, why);
        }
        Some((node.is_some(), sessions.len()))
    }

    /// The pair `name`, whose token the caller checked, ended or not.
    pub(super) fn named(&self, name: &str) -> Option<Arc<Pair>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned()
    }

    /// A number for each node's socket, so that the end of one never
    /// detaches the next.
    pub fn serial(&self) -> u64 {
        self.serial.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// How many pairs are kept.
    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn save(&self) -> Result<(), String> {
        let Some(path) = &self.file else { return Ok(()) };
        // Each pair as its file keeps it, its stop token as rotated (T-615).
        let kept: Vec<Kept> = self.map.lock().unwrap_or_else(|e| e.into_inner()).values().map(|p| p.kept()).collect();
        let body = serde_json::to_vec(&File { pairs: kept }).map_err(|e| e.to_string())?;
        write_private(path, &body).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// The file: each pair with the digests of its tokens.
#[derive(Serialize, Deserialize)]
struct File {
    pairs: Vec<Kept>,
}

#[derive(Serialize, Deserialize)]
struct Kept {
    name: String,
    expires: u64,
    node: String,
    connect: String,
    stop: String,
    /// A pair of `once`, and whether its connect token was taken (T-226); a
    /// file of before has neither.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    once: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    spent: bool,
    /// The digest of the stop token to come, which its node asked for and
    /// whose first use makes it the stop token (T-615); a file of before has
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_stop: Option<String>,
    /// The fingerprint of the key that made it (T-630); a file of before, and
    /// a pair of a role for anyone, have none, and count against no key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    maker: Option<String>,
}

impl Kept {
    fn digests(&self) -> Result<[[u8; 32]; 3], String> {
        let one = |text: &str| {
            let pairs = (text.len() == 64 && text.is_ascii()).then(|| {
                (0..32).filter_map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()).collect::<Vec<u8>>()
            });
            let bytes = pairs.and_then(|b| <[u8; 32]>::try_from(b).ok());
            bytes.ok_or_else(|| format!("pair {}: a digest is not 64 hex digits", self.name))
        };
        crate::relay::check_node_name(&self.name)?;
        Ok([one(&self.node)?, one(&self.connect)?, one(&self.stop)?])
    }
}

fn load(path: &Path) -> Result<Vec<Kept>, String> {
    if matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(Vec::new());
    }
    let text = crate::cache::read_private(path)?;
    let file: File =
        serde_json::from_str(&text).map_err(|e| format!("{}: not a file of pairs: {e}", path.display()))?;
    Ok(file.pairs)
}

/// `body` into `path` through a private file beside it and a rename, so
/// that no reader sees half of it, and nobody else may read it at any time.
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "pairs".into());
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let written = (|| {
        let mut file = crate::cache::create_new_private(&tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

// The names and tokens that a pair draws, and their digests.
#[path = "draw.rs"]
mod draw;
use draw::{base36, digest, same};
pub use draw::{hex, random};

// A key's share of the table (T-630).
#[path = "share.rs"]
mod share;
pub use share::{reserve, Asker};

// The planned stop, beside the pairs that it closes (T-255).
#[path = "stop.rs"]
mod stop;
pub use stop::Stopping;

// The tokens of one leg and the stop token's rotation (T-615).
#[path = "legs.rs"]
mod legs;
pub use legs::{parse_digest, Leg, LEG_LIFE_MS, MAX_LEGS};

#[cfg(test)]
#[path = "pairs_tests.rs"]
mod tests;
