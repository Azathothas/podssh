//! A node's stop token, rotated where its relay rotates one (T-615):
//! podssh's relay role, whose `hello` on the node's socket says so. Once a
//! socket of this node heard that, and each day after, the node draws the
//! next token, asks its relay for it by the token now, keeps it in the store
//! in the place of the one before, and makes it the pair's by its first use,
//! so that a stop token that leaked from a log or a copied file ends at the
//! next rotation. A crash between two steps leaves a token that the relay
//! takes: the one before until the new one is kept, the new one after. The
//! renewal of T-592 reads the token now from the same place.
//!
//! A pair of `--pair-file` keeps its token, as its file is the user's and is
//! never rewritten (T-592); so does a pair whose store took no write, which
//! is tried again in an hour. An operator never holds the stop token, so no
//! operator's file changes.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use podssh_relay::pair::rotate::{self, Rotated};
use podssh_relay::pair::{self, Pair, PairError};
use podssh_ws::dial::ProxyChoice;
use podssh_ws::Trust;

use crate::node_expiry::Say;

/// How often a node rotates its stop token.
pub(crate) const EVERY: Duration = Duration::from_secs(24 * 3600);
/// How long after a rotation that did not take the node tries again.
const RETRY: Duration = Duration::from_secs(3600);
/// How often the node looks whether a socket heard its role's offer.
const HEARD_EVERY: Duration = Duration::from_secs(2);

/// The node's own copy of its pair, with the stop token now, which the
/// rotation and the renewal share.
pub(crate) type Held = Arc<Mutex<Pair>>;

pub(crate) fn lock(held: &Held) -> MutexGuard<'_, Pair> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

/// What one rotation gave.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Turned {
    /// The new token is the pair's, and the store keeps it.
    Done,
    /// The store keeps the new token, which the relay takes as the one to
    /// come; its next use makes it the pair's.
    Kept(String),
    /// No rotation this time, and why: the token before stays.
    Again(String),
    /// The relay rotates no stop token.
    NotServed,
    /// The relay refused the stop token: the pair ended.
    Refused,
}

/// The rotation of the node's stop token, until the node ends, which aborts
/// it: at once once a socket heard a role that rotates, then each day. A
/// pair that is not the store's, `stored` false, is said once and kept.
pub(crate) async fn run(label: String, held: Held, stored: bool, say: Say, trust: Trust) {
    while !podssh_relay::reverse::legs::rotates() {
        tokio::time::sleep(HEARD_EVERY).await;
    }
    if !stored {
        say("this pair's stop token is not rotated, as its --pair-file is the user's file, never rewritten".into());
        return;
    }
    loop {
        let wait = match once(&label, &held, &trust).await {
            Turned::Done => {
                say("the pair's stop token is new at its relay, and the store keeps it; the one before it ends".into());
                EVERY
            }
            Turned::Kept(why) => {
                say(format!(
                    "the pair's stop token is new in the store; its relay makes it the pair's at its next use ({why})"
                ));
                RETRY
            }
            Turned::Again(why) => {
                say(format!("the pair's stop token was not rotated ({why}); trying again in an hour"));
                RETRY
            }
            Turned::NotServed => return,
            Turned::Refused => {
                say("the relay refused the pair's stop token (403): it was stopped, or it ended".into());
                return;
            }
        };
        tokio::time::sleep(wait).await;
    }
}

/// One rotation of the stop token of `held`, the pair stored under `label`.
async fn once(label: &str, held: &Held, trust: &Trust) -> Turned {
    let before = {
        let pair = lock(held);
        pair.with_expiry(pair.expires_ms)
    };
    let next = match rotate::draw() {
        Ok(next) => next,
        Err(why) => return Turned::Again(why),
    };
    let proxy = ProxyChoice::FromEnvironment;
    let ctx = crate::pairs::context(&before.relay, trust, &proxy);
    // The one to come, asked by the token now.
    match rotate::rotate(&ctx, &before, &next).await {
        Ok(Rotated::Asked) => {}
        Ok(Rotated::NotServed) => return Turned::NotServed,
        Err(PairError::Forbidden) => return Turned::Refused,
        Err(e) => return Turned::Again(e.to_string()),
    }
    // Kept before its first use: from here the relay takes it as the one to
    // come, and the node holds it.
    if let Err(why) = keep(label, &before.name, &next) {
        return Turned::Again(format!("the store took no write ({why})"));
    }
    let new = {
        let mut pair = lock(held);
        *pair = pair.with_stop(&next);
        pair.with_expiry(pair.expires_ms)
    };
    // Its first use makes it the pair's, and ends the one before.
    match rotate::rotate(&ctx, &new, &next).await {
        Ok(_) => Turned::Done,
        // Another token to come took its place: the one before stays, as the
        // relay may take it still.
        Err(PairError::Forbidden) => {
            let back = keep(label, &before.name, before.stop_token());
            *lock(held) = before.with_expiry(before.expires_ms);
            let kept = back.err().map(|why| format!(", which the store took no write of ({why})")).unwrap_or_default();
            Turned::Again(format!("the relay refused the new token at its first use, so the one before stays{kept}"))
        }
        Err(e) => Turned::Kept(e.to_string()),
    }
}

/// The store's copy of the pair `name` under `label`, with `stop_token`.
fn keep(label: &str, name: &str, stop_token: &str) -> Result<(), String> {
    match pair::load(label) {
        Ok(Some(stored)) if stored.name == name => {
            pair::store(label, &stored.with_stop(stop_token)).map(|_| ()).map_err(|e| e.to_string())
        }
        Ok(_) => Err(format!("the store holds no copy of this pair under {label:?}")),
        Err(e) => Err(e.to_string()),
    }
}
