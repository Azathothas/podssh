//! The sessions of the HTTP road that the role holds: each one's batches up
//! that wait for its target, the target's bytes that no request has
//! acknowledged, and its limits, which are the forward road's (`docs/relay.md`,
//! "Limits that users see"). One table of the process holds them, by an id
//! that the role draws, and each belongs to the role that opened it: another
//! role of the same process does not find it.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio::time::Instant;

use super::super::Config;

/// The batches up that the role holds for a target that has not taken them.
pub const WINDOW: usize = 8;
/// The target's bytes that the role holds until a request acknowledges
/// them; the target is read no further until one does.
pub const DOWN_WINDOW: usize = 2 << 20;
/// How long a batch waits for room in the window before its `503`.
pub const HOLD: Duration = Duration::from_secs(10);
/// A session with no request for this long ends: its client is gone.
pub const ABSENT: Duration = Duration::from_secs(60);
/// How long an ended session still answers with its end.
pub const KEPT_ENDED: Duration = Duration::from_secs(60);
/// The sessions of one process at once; past them, `503`.
pub const MOST: usize = 256;
/// How often the limits are looked at.
const TICK: Duration = Duration::from_millis(500);

static TABLE: OnceLock<Mutex<HashMap<String, Arc<Session>>>> = OnceLock::new();

fn table() -> MutexGuard<'static, HashMap<String, Arc<Session>>> {
    TABLE.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|p| p.into_inner())
}

/// What a session holds, behind its lock.
pub struct State {
    /// The number of the next batch that the role takes.
    pub next_up: u64,
    /// The batches stored that the target has not taken, in order.
    pub queue: VecDeque<Vec<u8>>,
    /// The batches that the target took: `X-Ack`.
    pub written: u64,
    /// The last batch came: after it, the target's half-close.
    pub fin: bool,
    /// The offset of the first byte of `down`.
    pub base: u64,
    pub down: VecDeque<u8>,
    /// The target's stream ended.
    pub target_ended: bool,
    pub ended: Option<(u16, String)>,
    ended_at: Option<Instant>,
    /// Payload bytes, both ways together.
    pub moved: u64,
    /// The last payload either way, and the last request.
    pub heard: Instant,
    pub asked: Instant,
    /// The newest answer down: an older one ends.
    pub generation: u64,
    tasks: Vec<AbortHandle>,
}

/// One session.
pub struct Session {
    pub id: String,
    /// The digest of the session's key, which a request's key is held to.
    key: [u8; 32],
    pub cfg: Arc<Config>,
    started: Instant,
    state: Mutex<State>,
    /// Woken at each change: a batch stored or written, bytes read or
    /// acknowledged, the end.
    pub changed: Notify,
}

/// Whether the bytes from an offset are there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ready {
    Bytes,
    /// None within the wait, or a newer answer took over.
    Nothing,
    /// The target ended, and each of its bytes is before the offset.
    Done,
    Ended,
}

/// What became of a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// Stored now, or before: the same number is the same batch.
    Taken,
    /// No room within [`HOLD`].
    Full,
    /// Not the next number: the one that is.
    Conflict(u64),
    Ended,
}

impl Session {
    /// A new session of `cfg`, its id and its key drawn: the session, and
    /// the key that its client is given.
    pub fn open(cfg: Arc<Config>) -> Result<(Arc<Session>, String), String> {
        let id: String = random(16)?.iter().map(|b| format!("{b:02x}")).collect();
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random(32)?);
        let now = Instant::now();
        let state = State {
            next_up: 0,
            queue: VecDeque::new(),
            written: 0,
            fin: false,
            base: 0,
            down: VecDeque::new(),
            target_ended: false,
            ended: None,
            ended_at: None,
            moved: 0,
            heard: now,
            asked: now,
            generation: 0,
            tasks: Vec::new(),
        };
        let session = Session { id, key: digest(&key), cfg, started: now, state: Mutex::new(state), changed: Notify::new() };
        Ok((Arc::new(session), key))
    }

    /// `f` with the session's state.
    pub fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut state)
    }

    fn key_is(&self, given: &str) -> bool {
        same(&self.key, &digest(given))
    }

    /// The tasks of its target, which its end stops.
    pub fn set_tasks(&self, tasks: Vec<AbortHandle>) {
        let ended = self.with(|st| {
            st.tasks = tasks;
            st.ended.is_some()
        });
        if ended {
            self.with(|st| std::mem::take(&mut st.tasks)).iter().for_each(AbortHandle::abort);
        }
    }

    /// End the session with the forward road's `code` and `why`, once.
    pub fn end(&self, code: u16, why: impl Into<String>) {
        let why = why.into();
        let stopped = self.with(|st| {
            if st.ended.is_some() {
                return None;
            }
            st.ended = Some((code, why));
            st.ended_at = Some(Instant::now());
            Some(std::mem::take(&mut st.tasks))
        });
        let Some(tasks) = stopped else { return };
        tasks.iter().for_each(AbortHandle::abort);
        self.changed.notify_waiters();
        self.cfg.event(&format!("http close {code}"));
    }

    pub fn ended(&self) -> Option<(u16, String)> {
        self.with(|st| st.ended.clone())
    }

    /// The batches that the target took.
    pub fn acked(&self) -> u64 {
        self.with(|st| st.written)
    }

    /// An answer down begins: the newest, which ends each older one.
    pub fn newest(&self) -> u64 {
        let generation = self.with(|st| {
            st.generation += 1;
            st.generation
        });
        self.changed.notify_waiters();
        generation
    }

    /// The client is there: its bytes down go on.
    pub fn progress(&self) {
        self.with(|st| st.asked = Instant::now());
    }

    /// Each byte before `at` came: they are forgotten, and the target may
    /// send more. `Err` for an offset that the role never sent, or one
    /// before what the client said it had.
    pub fn ack(&self, at: u64) -> Result<(), String> {
        let acked = self.with(|st| {
            let end = st.base + st.down.len() as u64;
            if at < st.base {
                return Err(format!("http: the offset {at} is before {}, which came", st.base));
            }
            if at > end {
                return Err(format!("http: the offset {at} is past {end}, the bytes sent"));
            }
            st.down.drain(..(at - st.base) as usize);
            st.base = at;
            Ok(())
        });
        self.changed.notify_waiters();
        acked
    }

    /// A copy of `most` bytes at most from the offset `from`: none when no
    /// byte is there yet.
    pub fn take_from(&self, from: u64, most: usize) -> Vec<u8> {
        self.with(|st| {
            let end = st.base + st.down.len() as u64;
            if from < st.base || from >= end {
                return Vec::new();
            }
            copy_out(&st.down, (from - st.base) as usize, most)
        })
    }

    /// Wait up to `wait` for a byte from the offset `from`, the target's end,
    /// or the session's; an answer of `generation` gives way to a newer one.
    pub async fn ready(&self, from: u64, wait: Duration, generation: Option<u64>) -> Ready {
        let deadline = Instant::now() + wait;
        loop {
            let notified = self.changed.notified();
            let now = self.with(|st| {
                if st.ended.is_some() {
                    Some(Ready::Ended)
                } else if generation.is_some_and(|g| g != st.generation) {
                    Some(Ready::Nothing)
                } else if st.base + st.down.len() as u64 > from {
                    Some(Ready::Bytes)
                } else if st.target_ended {
                    Some(Ready::Done)
                } else {
                    None
                }
            });
            if let Some(ready) = now {
                return ready;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Ready::Nothing;
            }
        }
    }

    /// The batch `seq`, stored once: a number taken before is the same
    /// batch, and the next one waits up to [`HOLD`] for room in the window.
    pub async fn store(&self, seq: u64, batch: Vec<u8>, fin: bool) -> Stored {
        let deadline = Instant::now() + HOLD;
        let mut batch = Some(batch);
        loop {
            let notified = self.changed.notified();
            let now = self.with(|st| {
                if st.ended.is_some() {
                    return Some(Stored::Ended);
                }
                if seq < st.next_up {
                    return Some(Stored::Taken);
                }
                if seq > st.next_up || st.fin {
                    return Some(Stored::Conflict(st.next_up));
                }
                if st.queue.len() >= WINDOW {
                    return None;
                }
                st.queue.push_back(batch.take().unwrap_or_default());
                st.next_up += 1;
                st.fin = fin;
                Some(Stored::Taken)
            });
            if let Some(stored) = now {
                self.changed.notify_waiters();
                return stored;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Stored::Full;
            }
        }
    }
}

/// `most` bytes at most of `down` from `from`, which is inside it.
fn copy_out(down: &VecDeque<u8>, from: usize, most: usize) -> Vec<u8> {
    let (a, b) = down.as_slices();
    let end = from.saturating_add(most).min(down.len());
    let mut out = Vec::with_capacity(end.saturating_sub(from));
    if from < a.len() {
        out.extend_from_slice(&a[from..end.min(a.len())]);
    }
    if end > a.len() {
        out.extend_from_slice(&b[from.saturating_sub(a.len())..end - a.len()]);
    }
    out
}

/// A session of the table.
pub fn insert(session: Arc<Session>) {
    table().insert(session.id.clone(), session);
}

/// The sessions of the process that have not ended.
pub fn live() -> usize {
    table().values().filter(|s| s.ended().is_none()).count()
}

/// The session `id` of `cfg`'s role, when `key` is its key: a wrong key and
/// an id unknown here are the same to the client. A request found it, so
/// its client is there.
pub fn find(id: &str, key: Option<&str>, cfg: &Arc<Config>) -> Option<Arc<Session>> {
    let session = table().get(id).cloned()?;
    if !Arc::ptr_eq(&session.cfg, cfg) || !key.is_some_and(|k| session.key_is(k)) {
        return None;
    }
    session.progress();
    Some(session)
}

/// What the limits say of a session.
enum Watch {
    Go,
    End(u16, &'static str),
    Forget,
}

/// The session's limits, as the forward road's, and its client's absence;
/// once it ended and said so for [`KEPT_ENDED`], it leaves the table.
pub async fn watch(session: Arc<Session>) {
    let limits = session.cfg.limits.clone();
    let started = session.started;
    loop {
        tokio::time::sleep(TICK).await;
        let seen = session.with(|st| match st.ended_at {
            Some(at) if at.elapsed() >= KEPT_ENDED => Watch::Forget,
            Some(_) => Watch::Go,
            None if st.heard.elapsed() >= limits.idle => Watch::End(1001, "idle timeout"),
            None if started.elapsed() >= limits.session => Watch::End(1001, "session time cap"),
            None if st.moved >= limits.bytes => Watch::End(1009, "session byte cap"),
            None if st.asked.elapsed() >= ABSENT => Watch::End(1001, "client gone"),
            None => Watch::Go,
        });
        match seen {
            Watch::Go => {}
            Watch::End(code, why) => session.end(code, why),
            Watch::Forget => {
                table().remove(&session.id);
                return;
            }
        }
    }
}

/// `n` bytes of the system's randomness.
fn random(n: usize) -> Result<Vec<u8>, String> {
    use rand::TryRng;
    let mut out = vec![0u8; n];
    rand::rngs::SysRng.try_fill_bytes(&mut out).map_err(|e| format!("no randomness for a session: {e}"))?;
    Ok(out)
}

fn digest(key: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(key.as_bytes()));
    out
}

/// Equal in constant time: a digest's first bytes are not given away.
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_takes_both_halves_of_the_ring() {
        let mut down: VecDeque<u8> = VecDeque::with_capacity(8);
        down.extend(b"xxxxabcd");
        down.drain(..4);
        down.extend(b"efgh");
        assert_eq!(copy_out(&down, 0, 100), b"abcdefgh");
        assert_eq!(copy_out(&down, 2, 4), b"cdef");
        assert_eq!(copy_out(&down, 6, 1), b"g");
        assert_eq!(copy_out(&down, 3, 0), b"");
    }

    #[test]
    fn a_key_is_held_to_its_digest_alone() {
        let key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ-_01234";
        assert!(same(&digest(key), &digest(key)));
        assert!(!same(&digest(key), &digest("abcdefghijklmnopqrstuvwxyzABCDEFGHIJ-_01235")));
    }
}
