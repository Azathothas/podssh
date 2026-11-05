//! Tokens of one leg (T-615): a connect token for each leg of a session that
//! podssh's relay role carries, which one upgrade spends, so that a token
//! that a proxy logged from a request's headers is worth nothing after it.
//!
//! A node gives each session that it lets in a seed of 32 random bytes in
//! its verdict, inside the channel, where a podssh of before reads nothing
//! past the verdict's code. The session's tokens come from the seed, one for
//! each leg after the first, which the pair's connect token opens: so no
//! token crosses the wire before its own leg, and none is carried for the
//! next. The node registers the SHA-256 of [`WINDOW`] of them at its role,
//! over its socket, while the socket's `hello` offers it ([`OFFER`]); the
//! role tells the node which one an upgrade took, and the node registers the
//! window after it ([`Leases`]). The operator takes them in order
//! ([`Taker`]), and its legs open with them (`crate::reverse::legs`).

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::session::{Entropy, OsEntropy};

/// The tokens of a session that its node keeps registered at once: one that
/// a leg may have spent with no word to the node, and the next ones.
pub const WINDOW: u64 = 4;
/// How long a registration lives at the role: each token that an upgrade
/// takes, and each new socket of the node, registers the window again.
pub const LIFE_MS: u64 = 24 * 3600 * 1000;
/// The field of a role's `hello` that offers the tokens.
pub const OFFER: &str = "legTokens";
/// What a token's HMAC binds, before the leg's number.
const LABEL: &[u8] = b"podssh leg token, version 1";

/// The node's socket, for the text frames of its registrations: a caller
/// that holds a lock sends them, so the sink never waits.
pub type Frames = Arc<dyn Fn(String) + Send + Sync>;

/// The token of leg `index` (from 1) of the session of `seed`: 64 hex
/// digits, the HMAC-SHA256 of the leg's number under the seed.
pub fn token(seed: &[u8; 32], index: u64) -> Zeroizing<String> {
    // HMAC takes a key of each length, so `new_from_slice` cannot fail.
    let mut mac = match Hmac::<Sha256>::new_from_slice(seed) {
        Ok(mac) => mac,
        Err(_) => <Hmac<Sha256> as KeyInit>::new(&Default::default()),
    };
    mac.update(LABEL);
    mac.update(&index.to_be_bytes());
    let bytes: [u8; 32] = mac.finalize().into_bytes().into();
    Zeroizing::new(hex(&bytes))
}

/// The SHA-256 of a token: what the role keeps, and what its frames name.
pub fn digest(token: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(token.as_bytes()));
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 64 hex digits as 32 bytes; `None` for anything else.
pub fn unhex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Whether the fields of a role's `hello` that podssh's node does not model
/// offer the tokens: `"legTokens": true`, and nothing else (`crate::answer`).
pub fn offered(extra: &serde_json::Map<String, serde_json::Value>) -> bool {
    crate::answer::offers(extra.get(OFFER))
}

/// The node's frame that registers `digest` until `expires_ms`, or, with an
/// end of 0, withdraws it.
pub fn frame(digest: &[u8; 32], expires_ms: u64) -> String {
    serde_json::json!({ "type": "token", "digest": hex(digest), "expires": expires_ms }).to_string()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// A node's tokens of one leg, for each session that it let in with a seed:
/// one for each node, shared by its roads, so that a session that came by
/// another road resumes on the pair's.
#[derive(Default)]
pub struct Leases {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The socket of a role that registers them; none, and no seed is given.
    frames: Option<Frames>,
    serial: u64,
    windows: HashMap<u64, Window>,
    /// Each token registered, by its digest: its session and its leg.
    by_digest: HashMap<[u8; 32], (u64, u64)>,
}

/// A session's seed, and the first leg of its window: the tokens of the legs
/// from `low` to `low + WINDOW - 1` are registered.
struct Window {
    seed: Zeroizing<[u8; 32]>,
    low: u64,
}

impl Window {
    fn digests(&self) -> impl Iterator<Item = ([u8; 32], u64)> + '_ {
        (self.low..self.low + WINDOW).map(|index| (digest(&token(&self.seed, index)), index))
    }
}

/// The seed of one session's tokens, while the session lives: its end
/// withdraws them at the role.
pub struct Lease {
    leases: Arc<Leases>,
    session: u64,
    seed: Zeroizing<[u8; 32]>,
}

impl Lease {
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The seed and the first leg of the window, for the binary that takes
    /// the node's place (T-668): the window leaves this node's leases with
    /// no withdrawal at the role, as the next binary registers it again on
    /// its own socket.
    pub fn hand_over(self) -> ([u8; 32], u64) {
        let mut guard = lock(&self.leases.inner);
        let inner = &mut *guard;
        let low = inner.windows.remove(&self.session).map_or(1, |window| window.low);
        inner.by_digest.retain(|_, (session, _)| *session != self.session);
        drop(guard);
        // Its drop finds no window, and withdraws nothing.
        (*self.seed, low)
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.leases.withdraw(self.session);
    }
}

impl Leases {
    /// The node's socket to a role that registers tokens, or `None` once it
    /// ended: each session's window is registered again on a new one, with
    /// a new end, as a role that restarted holds none.
    pub fn attach(&self, frames: Option<Frames>) {
        let mut inner = lock(&self.inner);
        inner.frames = frames;
        let Some(frames) = inner.frames.clone() else { return };
        let ends = now_ms() + LIFE_MS;
        for window in inner.windows.values() {
            for (digest, _) in window.digests() {
                frames(frame(&digest, ends));
            }
        }
    }

    /// A seed for a session that the node lets in, its window registered
    /// first; `None` with no socket to such a role, or no randomness.
    pub fn issue(self: &Arc<Self>) -> Option<Lease> {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsEntropy.fill(&mut seed[..]).ok()?;
        let mut guard = lock(&self.inner);
        let inner = &mut *guard;
        let frames = inner.frames.clone()?;
        inner.serial += 1;
        let session = inner.serial;
        let window = Window { seed: seed.clone(), low: 1 };
        let ends = now_ms() + LIFE_MS;
        for (digest, index) in window.digests() {
            inner.by_digest.insert(digest, (session, index));
            frames(frame(&digest, ends));
        }
        inner.windows.insert(session, window);
        Some(Lease { leases: self.clone(), session, seed })
    }

    /// The seed and the window of a session that the binary before this one
    /// handed over (T-668): registered now on a socket that registers them,
    /// and on each socket after, as a session's of this binary is.
    pub fn restore(self: &Arc<Self>, seed: [u8; 32], low: u64) -> Lease {
        let mut guard = lock(&self.inner);
        let inner = &mut *guard;
        inner.serial += 1;
        let session = inner.serial;
        let window = Window { seed: Zeroizing::new(seed), low: low.max(1) };
        let ends = now_ms() + LIFE_MS;
        for (digest, index) in window.digests() {
            inner.by_digest.insert(digest, (session, index));
            if let Some(frames) = &inner.frames {
                frames(frame(&digest, ends));
            }
        }
        inner.windows.insert(session, window);
        Lease { leases: self.clone(), session, seed: Zeroizing::new(seed) }
    }

    /// The role took the token of `digest` (hex) for an upgrade: each token
    /// before it is one that no leg takes any more, and goes; the window
    /// after it is registered, with a new end.
    pub fn spent(&self, digest_hex: &str) {
        let Some(spent) = unhex(digest_hex) else { return };
        let mut guard = lock(&self.inner);
        let inner = &mut *guard;
        let Some((session, index)) = inner.by_digest.remove(&spent) else { return };
        let frames = inner.frames.clone();
        let say = |text: String| {
            if let Some(frames) = &frames {
                frames(text);
            }
        };
        let Some(window) = inner.windows.get_mut(&session) else { return };
        for gone in window.low..index {
            let digest = digest(&token(&window.seed, gone));
            inner.by_digest.remove(&digest);
            say(frame(&digest, 0));
        }
        window.low = window.low.max(index + 1);
        let ends = now_ms() + LIFE_MS;
        for (digest, leg) in window.digests() {
            inner.by_digest.insert(digest, (session, leg));
            say(frame(&digest, ends));
        }
    }

    /// The session ended: its tokens go, at the role too.
    fn withdraw(&self, session: u64) {
        let mut guard = lock(&self.inner);
        let inner = &mut *guard;
        let Some(window) = inner.windows.remove(&session) else { return };
        for (digest, _) in window.digests() {
            inner.by_digest.remove(&digest);
            if let Some(frames) = &inner.frames {
                frames(frame(&digest, 0));
            }
        }
    }

    /// How many sessions hold a seed.
    pub fn held(&self) -> usize {
        lock(&self.inner).windows.len()
    }
}

tokio::task_local! {
    /// The operator's tokens of the session that runs in this task.
    static TAKER: Arc<Taker>;
}

/// Run `session`, an operator's session over the relay's legs, with a taker
/// of its tokens of one leg: its channel gives the node's seed, and each leg
/// after the first takes the next token ([`current`]).
pub async fn during<F: Future>(session: F) -> F::Output {
    TAKER.scope(Arc::default(), session).await
}

/// The taker of the session that runs in this task, inside [`during`].
pub fn current() -> Option<Arc<Taker>> {
    TAKER.try_with(Arc::clone).ok()
}

/// An operator's tokens of one leg, from the seed that the node gave.
#[derive(Default)]
pub struct Taker {
    state: Mutex<Taking>,
}

#[derive(Default)]
struct Taking {
    seed: Option<Zeroizing<[u8; 32]>>,
    /// The leg that takes the next token.
    next: u64,
    /// The refusals of a token in a row, since the last one that a leg took.
    refused: u64,
}

/// The token of a leg: the session's own, with its number, or the pair's.
pub enum Pick {
    Leg(u64, Zeroizing<String>),
    Pair,
}

impl Taker {
    /// The seed of the node's verdict; the first one stays, as a session has
    /// one channel.
    pub fn give(&self, seed: [u8; 32]) {
        let mut state = lock(&self.state);
        if state.seed.is_none() {
            (state.seed, state.next) = (Some(Zeroizing::new(seed)), 1);
        }
    }

    /// Whether the node gave a seed.
    pub fn holds(&self) -> bool {
        lock(&self.state).seed.is_some()
    }

    /// The token of the next leg: the session's next one, until twice
    /// [`WINDOW`] refusals in a row, past which the node holds none that
    /// this end could reach; then the pair's.
    pub fn pick(&self) -> Pick {
        let state = lock(&self.state);
        match &state.seed {
            Some(seed) if state.refused < 2 * WINDOW => Pick::Leg(state.next, token(seed, state.next)),
            _ => Pick::Pair,
        }
    }

    /// The role took the token of leg `index`: the next leg takes the next.
    pub fn upgraded(&self, index: u64) {
        let mut state = lock(&self.state);
        if index == state.next {
            (state.next, state.refused) = (index + 1, 0);
        }
    }

    /// The role refused the token of leg `index` (403). Once, it may have
    /// restarted, and the node registers it again: the next leg tries it
    /// again. A second time, a leg spent it with no word to the node, or it
    /// ended: the next leg takes the next one.
    pub fn refused(&self, index: u64) {
        let mut state = lock(&self.state);
        if index == state.next {
            state.refused += 1;
            if state.refused.is_multiple_of(2) {
                state.next += 1;
            }
        }
    }

    /// The token of leg `index`, for a check that the role refuses one
    /// that a leg took.
    pub fn token_at(&self, index: u64) -> Option<Zeroizing<String>> {
        lock(&self.state).seed.as_ref().map(|seed| token(seed, index))
    }
}

#[cfg(test)]
#[path = "legs_tests.rs"]
mod tests;
