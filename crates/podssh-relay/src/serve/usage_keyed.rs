//! The tokens that the relay role minted for keys (T-636), each by its
//! SHA-256, never the token, with its key and its end: 64 live tokens a key
//! at most, the oldest forgotten first. Apart from `usage.rs`, so that it
//! stays within 500 lines.

use std::collections::{HashMap, VecDeque};

use sha2::{Digest, Sha256};

use super::TOKENS_A_KEY;

/// How often the tokens of keys that mint no more are swept.
const SWEEP_MS: u64 = 60_000;

/// A token minted for a key, until its end.
struct Minted {
    key: String,
    ends: u64,
}

/// The tokens minted for keys, by digest, and each key's in the order of
/// their mint.
#[derive(Default)]
pub struct Keyed {
    tokens: HashMap<[u8; 32], Minted>,
    keys: HashMap<String, VecDeque<[u8; 32]>>,
    swept: u64,
}

impl Keyed {
    /// Keep `digest` for `key` until `ends`; false when it is another key's
    /// live token, as two mints in one millisecond make one token.
    pub fn keep(&mut self, digest: [u8; 32], key: &str, ends: u64, now: u64) -> bool {
        if let Some(held) = self.tokens.get(&digest).filter(|m| m.ends > now) {
            return held.key == key;
        }
        self.sweep(now);
        let Keyed { tokens, keys, .. } = self;
        let queue = keys.entry(key.to_string()).or_default();
        // The key's tokens that ended go first, then its oldest past the bound.
        queue.retain(|d| {
            let ours = tokens.get(d).is_some_and(|m| m.key == key);
            let live = ours && tokens.get(d).is_some_and(|m| m.ends > now);
            if ours && !live {
                tokens.remove(d);
            }
            live
        });
        while queue.len() >= TOKENS_A_KEY {
            if let Some(oldest) = queue.pop_front() {
                tokens.remove(&oldest);
            }
        }
        queue.push_back(digest);
        tokens.insert(digest, Minted { key: key.to_string(), ends });
        true
    }

    /// The key of `digest`, while its token lives.
    pub fn key_of(&self, digest: &[u8; 32], now: u64) -> Option<String> {
        self.tokens.get(digest).filter(|m| m.ends > now).map(|m| m.key.clone())
    }

    /// Forget each ended token, once a minute at most: a key that mints no
    /// more holds nothing for ever.
    fn sweep(&mut self, now: u64) {
        if now < self.swept.saturating_add(SWEEP_MS) {
            return;
        }
        self.swept = now;
        self.tokens.retain(|_, m| m.ends > now);
        let tokens = &self.tokens;
        self.keys.retain(|_, queue| {
            queue.retain(|d| tokens.contains_key(d));
            !queue.is_empty()
        });
    }
}

/// A token's SHA-256, by which the table holds it.
pub fn digest(token: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(token.as_bytes()));
    out
}
