//! Sessions readied ahead for a node that asks (T-650, GitHub #148), beside
//! the contract. The node's `hello` offers them (`"spares": true`); a node
//! of `--spares N` answers `{"type":"spares","want":N}`, 16 at most, and a
//! node that says nothing gets none: a spare is a session at rest at the
//! node, and with no layer and no channel a connection to its target, which
//! its owner chooses to pay for. The role sends
//! `{"type":"open","id":ID,"spare":true}` for each, with each leg's session
//! counted inside [`MAX_SESSIONS`]. A leg takes a readied one before it opens
//! a session of its own: its operator hears `ready` at once, then the bytes
//! that the node sent on it (a greeting, a banner), and its first byte goes
//! to the node with no `open`; a leg that finds none goes the way of before.
//! A spare that the node has not readied is never taken, as an early `ready`
//! hands the operator a dead session (`crate::reverse::control::ready`).
//!
//! The number kept starts at the node's, rises by one for each leg that
//! found none, and falls to [`FLOOR`] at a [`Spacing::tick`] in which no leg
//! took one. A spare that waited [`Spacing::age`] closes, and another is
//! drawn: the node's resumable layer and its channel give a client 30 s for
//! its handshake from the session's `open`, and a leg must have most of them.
//! A spare that the node refused stops the drawing until the next tick, so
//! that a target that refuses each connection costs a round of opens a
//! minute, not a loop; one that the node closed, as its target ended it, is
//! drawn again at the next look. A spare never takes a leg's place: a leg
//! that finds no room closes one.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::sync::oneshot;

use super::outbox::Outbox;
use super::pairs::{Answer, Pair, Pairs, Session, State, IN_FLIGHT};
use super::{close, new_id, MAX_SESSIONS};
use crate::reverse::control;
use crate::reverse::framing::SessionId;

pub use crate::reverse::spares::{ASK, MOST, OFFER};

/// The number kept after a tick in which no leg took one: the next leg
/// still finds one.
pub const FLOOR: usize = 1;
/// The bytes that the node may send on a spare before a leg takes it, a
/// greeting or a banner; past them, the spare closes.
pub const HELD: usize = 64 * 1024;

/// Why the role closes a spare, as the node's `close` says it.
const AGED: &str = "a spare that no operator took in time";
const UNUSED: &str = "a spare that no operator needs";
const YIELDS: &str = "a spare gives its place to an operator";
const TOO_MUCH: &str = "a spare's bytes past 64 KiB before an operator";

/// A fault of the node's bytes: the code and the reason of the close table's
/// row, as `super::node` closes its socket with them.
type Fault = (u16, &'static str);

/// The times of a role's spares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spacing {
    /// How often a node's socket looks at its spares.
    pub check: Duration,
    /// How often the number kept falls to the floor, where no leg took one.
    pub tick: Duration,
    /// How long a spare waits for a leg before it closes: under the 30 s of
    /// the node's handshakes, with a look's time.
    pub age: Duration,
}

impl Default for Spacing {
    fn default() -> Spacing {
        Spacing { check: Duration::from_secs(5), tick: Duration::from_secs(60), age: Duration::from_secs(15) }
    }
}

/// One spare: when its `open` went, whether the node readied it, and the
/// bytes that the node sent on it since, for the leg that takes it.
struct Spare {
    opened: Instant,
    ready: bool,
    held: Vec<Vec<u8>>,
    bytes: usize,
}

impl Spare {
    fn new() -> Spare {
        Spare { opened: Instant::now(), ready: false, held: Vec::new(), bytes: 0 }
    }
}

/// A node's spares, in its pair's state, for its socket alone.
#[derive(Default)]
pub struct Spares {
    /// The node's number: none asked is 0.
    want: usize,
    /// The number kept now, from [`FLOOR`] to `want`.
    level: usize,
    each: HashMap<SessionId, Spare>,
    /// Since the last tick: whether a leg took one, and whether the node
    /// refused one.
    taken: bool,
    refused: bool,
    /// When the number kept was last looked at.
    ticked: Option<Instant>,
}

impl Spares {
    /// The spares open now, readied or not.
    pub fn len(&self) -> usize {
        self.each.len()
    }

    pub fn is_empty(&self) -> bool {
        self.each.is_empty()
    }

    /// Whether `id` is a spare that no leg took.
    pub fn holds(&self, id: &SessionId) -> bool {
        self.each.contains_key(id)
    }

    /// The youngest readied spare, which has the most of the node's 30 s
    /// left; never one that the node has not readied.
    fn take(&mut self) -> Option<(SessionId, Spare)> {
        let id = self.each.iter().filter(|(_, s)| s.ready).max_by_key(|(_, s)| s.opened).map(|(id, _)| *id)?;
        self.taken = true;
        self.each.remove(&id).map(|spare| (id, spare))
    }
}

impl Pairs {
    /// The same pairs with the times of a test's spares.
    pub fn with_spacing(mut self, spacing: Spacing) -> Pairs {
        let least = Duration::from_millis(1);
        self.spacing = Spacing { check: spacing.check.max(least), ..spacing };
        self
    }

    /// The times of the role's spares.
    pub fn spacing(&self) -> Spacing {
        self.spacing
    }
}

/// A node's `{"type":"spares","want":N}`: N, [`MOST`] at most, kept for its
/// socket and drawn at once; 0 asks for none and closes those kept. The
/// number taken; a frame with no whole number closes the node's socket, as a
/// bad token frame does.
pub(super) fn asked(pair: &Pair, message: &Value) -> Result<usize, Fault> {
    let Some(want) = message.get("want").and_then(Value::as_u64) else {
        return Err((1003, "invalid spares frame"));
    };
    let want = want.min(u64::from(MOST)) as usize;
    let mut guard = pair.lock();
    let state = &mut *guard;
    let node = state.node_outbox();
    let spares = &mut state.spares;
    (spares.want, spares.level, spares.ticked) = (want, want, Some(Instant::now()));
    (spares.taken, spares.refused) = (false, false);
    trim(state, node.as_ref());
    fill(state, node.as_ref());
    Ok(want)
}

/// Admit a leg of `pair` whose writer is `operator`: the youngest readied
/// spare first, its session in the table, and its `ready` and the node's
/// bytes queued for the operator; else a new session `id`, whose `open` the
/// caller sends, `told` when the node answers it. The session's id, the
/// node's writer, and whether a spare was taken; `Err`, the words of the
/// operator's `1011`.
pub(super) fn admit(
    pair: &Pair,
    operator: &Outbox,
    id: SessionId,
    told: oneshot::Sender<Answer>,
) -> Result<(SessionId, Outbox, bool), &'static str> {
    let mut guard = pair.lock();
    let state = &mut *guard;
    // A halt that came after its request's check (T-647).
    if state.halted.is_some() {
        return Err(super::halt::HALTED);
    }
    let node = match state.node_outbox() {
        Some(node) if !state.ended => node,
        _ => return Err("node unavailable"),
    };
    if let Some((taken, spare)) = state.spares.take() {
        // `ready` first, which the operator reads before any byte.
        if let Ok(ready) = control::ready(&taken) {
            operator.text(String::from_utf8_lossy(&ready).into_owned());
        }
        // Within the operator's bound, as they are `HELD` at most.
        for piece in spare.held {
            let _ = operator.binary_or_full(piece);
        }
        let session = Session { operator: operator.clone(), ready: true, answer: None, bytes: spare.bytes as u64 };
        state.sessions.insert(taken, session);
        return Ok((taken, node, true));
    }
    // A leg that found none asks for one more, up to the node's number.
    if state.spares.want > 0 {
        state.spares.level = (state.spares.level + 1).min(state.spares.want);
    }
    // A spare never takes a leg's place: one that is still opening gives it.
    if state.sessions.len() + state.spares.len() >= MAX_SESSIONS {
        if let Some(spare) = state.spares.each.keys().next().copied() {
            retire(state, Some(&node), spare, YIELDS);
        }
    }
    if state.sessions.len() >= MAX_SESSIONS {
        return Err("node unavailable");
    }
    state.sessions.insert(id, Session { operator: operator.clone(), ready: false, answer: Some(told), bytes: 0 });
    Ok((id, node, false))
}

/// The spares that a leg's take or miss left short, drawn after the leg's
/// own frames.
pub(super) fn refill(pair: &Pair) {
    let mut guard = pair.lock();
    let node = guard.node_outbox();
    fill(&mut guard, node.as_ref());
}

/// Draw spares up to the number kept, inside [`MAX_SESSIONS`] with each
/// leg's session counted: none for a halted or ended pair, nor after a
/// refusal until the next tick.
pub(super) fn fill(state: &mut State, node: Option<&Outbox>) {
    let Some(node) = node else { return };
    if state.halted.is_some() || state.ended || state.spares.refused {
        return;
    }
    let room = MAX_SESSIONS.saturating_sub(state.sessions.len() + state.spares.len());
    let short = state.spares.level.saturating_sub(state.spares.len()).min(room);
    for _ in 0..short {
        let Some(id) = new_id() else { return };
        state.spares.each.insert(id, Spare::new());
        node.text(json!({ "type": "open", "id": id.as_str(), "spare": true }).to_string());
    }
}

/// A node socket's look at its spares, each [`Spacing::check`]: those that
/// waited [`Spacing::age`] close; at each [`Spacing::tick`] with no take,
/// the number kept falls to [`FLOOR`] and those past it close, and a refusal
/// is forgiven; then those missing are drawn.
pub(super) fn keep(pair: &Pair, spacing: Spacing) {
    let mut guard = pair.lock();
    let state = &mut *guard;
    if state.spares.want == 0 {
        return;
    }
    let (node, now) = (state.node_outbox(), Instant::now());
    let aged: Vec<SessionId> = state
        .spares
        .each
        .iter()
        .filter(|(_, s)| now.saturating_duration_since(s.opened) >= spacing.age)
        .map(|(id, _)| *id)
        .collect();
    for id in aged {
        retire(state, node.as_ref(), id, AGED);
    }
    let spares = &mut state.spares;
    if spares.ticked.is_none_or(|at| now.saturating_duration_since(at) >= spacing.tick) {
        if !spares.taken {
            spares.level = FLOOR.min(spares.want);
        }
        (spares.taken, spares.refused, spares.ticked) = (false, false, Some(now));
        trim(state, node.as_ref());
    }
    fill(state, node.as_ref());
}

/// Close the spares past the number kept: those still opening first, then
/// the oldest.
fn trim(state: &mut State, node: Option<&Outbox>) {
    let past = state.spares.len().saturating_sub(state.spares.level);
    let mut order: Vec<(bool, Instant, SessionId)> =
        state.spares.each.iter().map(|(id, s)| (s.ready, s.opened, *id)).collect();
    order.sort_unstable();
    for (_, _, id) in order.into_iter().take(past) {
        retire(state, node, id, UNUSED);
    }
}

/// Close each spare of a pair that its owner halted: no leg comes to take
/// one (T-647).
pub(super) fn close_all(state: &mut State, node: Option<&Outbox>, why: &str) {
    let ids: Vec<SessionId> = state.spares.each.keys().copied().collect();
    for id in ids {
        retire(state, node, id, why);
    }
}

/// Close spare `id` from the role's side: the node hears `close` with `why`
/// before the opens that follow it, and a frame of it on its way is dropped,
/// as for a session (T-421). A spare carries no byte of the role's, so its
/// `close` waits behind nothing.
fn retire(state: &mut State, node: Option<&Outbox>, id: SessionId, why: &str) {
    if state.spares.each.remove(&id).is_none() {
        return;
    }
    let now = Instant::now();
    state.closed.retain(|_, (at, _)| now.saturating_duration_since(*at) < IN_FLIGHT);
    state.closed.insert(id, (now, false));
    if let Some(node) = node {
        node.text(close(&id, Some(why)));
    }
}

/// The node's `ready`, `reject` or `close` of spare `id`: `ready` makes it
/// one that a leg may take; a `reject` or a `close` forgets it, uncounted,
/// and a refusal stops the drawing until the next tick.
pub(super) fn answered(state: &mut State, id: &SessionId, kind: &str) {
    if kind == "ready" {
        if let Some(spare) = state.spares.each.get_mut(id) {
            spare.ready = true;
        }
        return;
    }
    state.spares.each.remove(id);
    state.spares.refused |= kind == "reject";
}

/// The node's bytes on spare `id` before a leg took it, held for that leg,
/// [`HELD`] at most, past which the spare closes; before its `ready`, the
/// fault of each session (`1003 data before ready`).
pub(super) fn data(state: &mut State, node: &Outbox, id: &SessionId, payload: &[u8]) -> Result<(), Fault> {
    let Some(spare) = state.spares.each.get_mut(id) else { return Ok(()) };
    if !spare.ready {
        return Err((1003, "data before ready"));
    }
    if payload.is_empty() {
        return Ok(());
    }
    if spare.bytes + payload.len() > HELD {
        retire(state, Some(node), *id, TOO_MUCH);
        return Ok(());
    }
    spare.bytes += payload.len();
    spare.held.push(payload.to_vec());
    Ok(())
}

#[cfg(test)]
#[path = "spares_tests.rs"]
mod tests;
