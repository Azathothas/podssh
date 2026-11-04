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
//! The pair is the one that the node holds now ([`Held`]): at an expiry the
//! node goes on with the next pair (T-395), and the rotation begins again
//! for it, at its own first socket that heard the offer (T-620), so the first
//! pair's token is never used again, and the next one's is rotated too.
//!
//! A pair of `--pair-file` keeps its token, as its file is the user's and is
//! never rewritten (T-592); so does a pair whose store took no write, which
//! is tried again in an hour. An operator never holds the stop token, so no
//! operator's file changes.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use podssh_relay::pair::rotate::{self, Rotated};
use podssh_relay::pair::{self, Pair, PairError};
use podssh_relay::reverse::legs;
use podssh_ws::dial::ProxyChoice;
use podssh_ws::Trust;
use tokio::sync::watch;

use crate::node_expiry::Say;

/// How often a node rotates its stop token.
pub(crate) const EVERY: Duration = Duration::from_secs(24 * 3600);
/// How long after a rotation that did not take the node tries again.
const RETRY: Duration = Duration::from_secs(3600);
/// How often the node looks whether a socket heard its role's offer.
const HEARD_EVERY: Duration = Duration::from_secs(2);

/// The pair that the node holds now, with its stop token as rotated and its
/// end as renewed, which the rotation, the renewal and the hook of the
/// expiry share. The move to the next pair at an expiry replaces it and
/// wakes each task that waits on it (T-620), so that each next turn is the
/// new pair's.
#[derive(Clone)]
pub(crate) struct Held(Arc<Shared>);

struct Shared {
    now: Mutex<Now>,
    /// The count of moves, for the tasks that wait on one.
    moves: watch::Sender<u64>,
    /// One request by the stop token at a time, with its write of the store:
    /// a renewal never sends a token that a rotation ended meanwhile, and
    /// neither write of the store undoes the other's.
    turn: tokio::sync::Mutex<()>,
}

/// The pair, and the count of sockets that had heard a role that rotates
/// when the node began with it: its rotation waits for one more, its own.
struct Now {
    pair: Pair,
    offers: u64,
}

impl Held {
    /// The pair that the node starts with, before its first socket.
    pub(crate) fn of(pair: &Pair) -> Held {
        let now = Now { pair: copy(pair), offers: legs::offers() };
        let shared = Shared { now: Mutex::new(now), moves: watch::channel(0).0, turn: tokio::sync::Mutex::new(()) };
        Held(Arc::new(shared))
    }

    fn now(&self) -> MutexGuard<'_, Now> {
        self.0.now.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A copy of the pair now.
    pub(crate) fn pair(&self) -> Pair {
        copy(&self.now().pair)
    }

    /// The relay's name of the pair now, which no line shows.
    pub(crate) fn name(&self) -> String {
        self.now().pair.name.clone()
    }

    /// When the pair now ends, in ms since the epoch.
    pub(crate) fn end(&self) -> i64 {
        self.now().pair.expires_ms
    }

    /// The next pair in the place of the one now, at its expiry; each task
    /// that waits on the pair wakes, and its rotation waits for a socket of
    /// the next one.
    pub(crate) fn move_to(&self, next: &Pair) {
        *self.now() = Now { pair: copy(next), offers: legs::offers() };
        self.0.moves.send_modify(|moves| *moves += 1);
    }

    /// The moves from now on.
    pub(crate) fn moves(&self) -> watch::Receiver<u64> {
        self.0.moves.subscribe()
    }

    /// Whether a socket heard a role that rotates since the node began with
    /// the pair now.
    fn heard(&self) -> bool {
        legs::offers() > self.now().offers
    }

    /// The pair `name` with `stop` as its stop token, as a copy; `None`, and
    /// nothing changed, once the node holds another pair.
    fn restop(&self, name: &str, stop: &str) -> Option<Pair> {
        let mut now = self.now();
        (now.pair.name == name).then(|| {
            now.pair = now.pair.with_stop(stop);
            copy(&now.pair)
        })
    }

    /// The end of the pair `name` after a renewal: `false`, and nothing
    /// changed, once the node holds another pair.
    pub(crate) fn renewed(&self, name: &str, until: i64) -> bool {
        let mut now = self.now();
        let same = now.pair.name == name;
        if same {
            now.pair = now.pair.with_expiry(until);
        }
        same
    }

    /// The turn of one request by the stop token, until the guard drops.
    pub(crate) async fn turn(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.0.turn.lock().await
    }
}

/// A copy of `pair`, which zeroes its tokens when it is dropped.
fn copy(pair: &Pair) -> Pair {
    pair.with_expiry(pair.expires_ms)
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
    /// The node went on with its next pair meanwhile: the rotation is that
    /// pair's from now on.
    Moved,
}

/// The rotation of the node's stop token, until the node ends, which aborts
/// it: at once once a socket heard a role that rotates, then each day; and
/// so for each next pair that the node goes on with. A pair that is not the
/// store's, `stored` false, is said once and kept: it has no next pair.
pub(crate) async fn run(label: String, held: Held, stored: bool, say: Say, trust: Trust) {
    let mut moves = held.moves();
    if !stored {
        while !held.heard() {
            tokio::time::sleep(HEARD_EVERY).await;
        }
        say("this pair's stop token is not rotated, as its --pair-file is the user's file, never rewritten".into());
        return;
    }
    loop {
        if !offered(&held, &mut moves).await {
            continue;
        }
        // The turns of the pair now, until the node moves to its next one.
        loop {
            let moved = match after(once(&label, &held, &trust).await, &say) {
                After::Wait(wait) => tokio::select! {
                    () = tokio::time::sleep(wait) => false,
                    Ok(()) = moves.changed() => true,
                },
                // The sender lives in `held`, which this task holds: an
                // error never comes, and would end the task.
                After::UntilMoved => match moves.changed().await {
                    Ok(()) => true,
                    Err(_) => return,
                },
                After::Moved => true,
            };
            if moved {
                break;
            }
        }
    }
}

/// What comes after a turn of the pair now.
enum After {
    /// Its next turn, after this long, unless the node moves first.
    Wait(Duration),
    /// No other turn of this pair: the next pair's, at a move.
    UntilMoved,
    /// The node moved already.
    Moved,
}

/// The line of a turn, and what comes after it.
fn after(turned: Turned, say: &Say) -> After {
    match turned {
        Turned::Done => {
            say("the pair's stop token is new at its relay, and the store keeps it; the one before it ends".into());
            After::Wait(EVERY)
        }
        Turned::Kept(why) => {
            say(format!(
                "the pair's stop token is new in the store; its relay makes it the pair's at its next use ({why})"
            ));
            After::Wait(RETRY)
        }
        Turned::Again(why) => {
            say(format!("the pair's stop token was not rotated ({why}); trying again in an hour"));
            After::Wait(RETRY)
        }
        Turned::NotServed => After::UntilMoved,
        Turned::Refused => {
            say("the relay refused the pair's stop token (403): it was stopped, or it ended".into());
            After::UntilMoved
        }
        Turned::Moved => After::Moved,
    }
}

/// Until a socket heard a role that rotates since the node began with the
/// pair now: `true`; `false` when the node moves to its next pair first, whose
/// own socket the wait is then for.
async fn offered(held: &Held, moves: &mut watch::Receiver<u64>) -> bool {
    // Each move before this wait is the pair now.
    moves.mark_unchanged();
    while !held.heard() {
        tokio::select! {
            () = tokio::time::sleep(HEARD_EVERY) => {}
            Ok(()) = moves.changed() => return false,
        }
    }
    true
}

/// One rotation of the stop token of the pair that `held` holds, stored
/// under `label`.
async fn once(label: &str, held: &Held, trust: &Trust) -> Turned {
    let _turn = held.turn().await;
    let before = held.pair();
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
    // The node's copy, unless it went on with its next pair meanwhile.
    let Some(new) = held.restop(&before.name, &next) else { return Turned::Moved };
    // Its first use makes it the pair's, and ends the one before.
    match rotate::rotate(&ctx, &new, &next).await {
        Ok(_) => Turned::Done,
        // Another token to come took its place: the one before stays, as the
        // relay may take it still.
        Err(PairError::Forbidden) => {
            let back = keep(label, &before.name, before.stop_token());
            let _ = held.restop(&before.name, before.stop_token());
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

#[cfg(test)]
#[path = "node_rotate_tests.rs"]
mod tests;
