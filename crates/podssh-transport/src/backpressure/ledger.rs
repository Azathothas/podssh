//! E16 — ⛔ **the ledger: two counters, one ceiling each, and the halving rule.**
//!
//! ⛔ **One in-flight counter per direction, not one for the session.** ⛔ SSH is
//! full-duplex: ⛔ the window the client grants the server's data and the window
//! the server grants the client's data are separate, ⛔ **and each is bounded by
//! the relay's own 1 MiB queue ⛔ — ⛔ a single shared counter would halve a
//! session's throughput for a congestion that exists in one direction only.**
//!
//! ⛔ **The pacer owns no clock.** Every wait ends when a send completes, ⛔ and
//! ⛔ the parked queue is a value a caller drains ⛔ **rather than a `tokio::time::
//! sleep` this module owns** ⛔ — ⛔ which is how the module stays testable with
//! no wall clock and cannot become the thing that blocks a runtime worker.
//!
//! ⛔ **The halving is on the ceiling and never on the frame.** ⛔ *"The frame is
//! gone."* ⛔ There is no data to re-send, so ⛔ **there is nothing to retry**, and
//! ⛔ **a `replayed` counter exists so that "no retry" is a number a test reads**
//! ⛔ rather than an absence nobody can assert on.

use super::{Permit, SessionBudgetRefused, CHUNK_MAX, CEILING_FLOOR, INFLIGHT_CEILING, SESSION_BUDGET};

/// ⛔ **Which way the bytes are going.** ⛔ Two counters ⛔ **because the relay's
/// queue is one per direction** ⛔ — ⛔ "Over 1 MiB queued for a slow receiver"
/// (spec line 185) names a *receiver*, and each direction has its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// ⛔ podssh → relay → target. ⛔ The direction a large `scp` **upload** is
    /// in, and ⛔ the one E16's cap plant is built on ⛔ — ⛔ "40 MiB up plus 40
    /// MiB down is over budget on the reading that *both directions* means
    /// combined".
    ToTarget,
    /// ⛔ target → relay → podssh. ⛔ A large download, and ⛔ the direction a
    /// slow local reader slows down ⛔ — ⛔ **the relay's queue for this
    /// direction grows when *podssh's own socket* is the slow part.**
    FromTarget,
}

impl Direction {
    pub const BOTH: [Direction; 2] = [Direction::ToTarget, Direction::FromTarget];

    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::ToTarget => "to-target",
            Direction::FromTarget => "from-target",
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ⛔ **One direction's window.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// ⛔ **Bytes handed to the socket and not yet completed.** ⛔ **Not**
    /// "bytes queued at the relay": ⛔ the relay also queues what podssh has
    /// already given to TLS, ⛔ **and the queue depth is not observable from the
    /// client** ⛔ (`backpressure.md` `## Premise`) ⛔ — ⛔ so this is an
    /// approximation of the relay's queue and the doc comment above says so.
    in_flight: u64,
    /// ⛔ **Bytes ever committed to this direction**, ⛔ **which is what the
    /// 64 MiB cap is measured against** ⛔ — ⛔ **and it keeps counting after a
    /// frame is dropped**, ⛔ because the drop cost bytes whether or not the
    /// target ever saw them.
    committed: u64,
    /// ⛔ **Bytes some completion has released, cumulatively.** ⛔
    /// ⛔ **MEASURED 2026-10-02: this field did not exist, and the
    /// ⛔ consequence was that a caller could not see a drop at all** ⛔ —
    /// ⛔ it was `committed - in_flight`, ⛔ and a frame the relay threw
    /// ⛔ away is still in flight, ⛔ so that gap read 0 for the
    /// ⛔ one case it exists to name. ⛔
    ///
    /// ⛔ **`committed - released` is the real one:** no completion
    /// ⛔ arrived, so nothing accounted for those bytes** ⛔ — whether
    /// ⛔ they are still in the TCP window or ⛔ gone, ⛔ and
    /// ⛔ **which is precisely what a caller cannot otherwise know.** ⛔
    released: u64,
    /// ⛔ **Halved on each `1011 relay backpressure`, floored at one chunk.**
    ceiling: u64,
    /// ⛔ **How many times the ceiling was halved.** ⛔ A test reads it; ⛔ a
    /// production caller has no reason to look at it.
    halvings: u32,
}

/// ⛔ **A parked write, and the bytes it was carrying.** ⛔ **These bytes are
/// not in `in_flight` yet** ⛔ — ⛔ counting them at park time is how a pacer
/// inflates its own backlog and then parks on a queue that is already full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parked {
    pub direction: Direction,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
struct Slot {
    window: Window,
    parked: Vec<Parked>,
}

/// ⛔ **Both directions, one ceiling each, and the budget across both.**
#[derive(Debug, Clone)]
pub struct Ledger {
    to_target: Slot,
    from_target: Slot,
    /// ⛔ **Combined committed bytes in both directions.** ⛔ **This is the
    /// `in both directions` superset**, ⛔ applied because ⛔ `exp-04` has not
    /// established which reading is right ⛔ and ⛔ **the cost of being wrong the
    /// other way is a truncated file.**
    committed_total: u64,
    budget: u64,
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

impl Ledger {
    pub fn new() -> Self {
        Self::with_budget(SESSION_BUDGET)
    }

    /// ⛔ **A ledger with a different budget**, ⛔ **for a test and not only for a
    /// test**: ⛔ a budget derived from a measured cap is not always the right
    /// budget, and ⛔ a knob with no caller is a cost ⛔ — ⛔ **so this one has two
    /// callers: the tests that must not move 32 MiB, and a future caller that
    /// reads a cap from `/relays.json`** ⛔ (**MEASURED** 2026-10-02,
    /// `max_session_bytes` **67108864**).
    pub fn with_budget(budget: u64) -> Self {
        let window = || Slot {
            window: Window {
                in_flight: 0,
                committed: 0,
                released: 0,
                ceiling: INFLIGHT_CEILING,
                halvings: 0,
            },
            parked: Vec::new(),
        };
        Self { to_target: window(), from_target: window(), committed_total: 0, budget }
    }

    pub const fn budget(&self) -> u64 {
        self.budget
    }

    fn slot(&self, direction: Direction) -> &Slot {
        match direction {
            Direction::ToTarget => &self.to_target,
            Direction::FromTarget => &self.from_target,
        }
    }

    fn slot_mut(&mut self, direction: Direction) -> &mut Slot {
        match direction {
            Direction::ToTarget => &mut self.to_target,
            Direction::FromTarget => &mut self.from_target,
        }
    }

    /// ⛔ **Ask permission to send `bytes`.**
    ///
    /// ⛔ **A send may start only when `in_flight + chunk <= ceiling`.** ⛔
    /// Otherwise ⛔ **the write parks and is re-driven by the completion of an
    /// outstanding send** ⛔ — ⛔ and ⛔ **the parked chunk is not counted**, ⛔
    /// which is the whole of the ceiling arithmetic.
    ///
    /// ⛔ **The chunk is clamped to [`CHUNK_MAX`] rather than refused**, ⛔
    /// because ⛔ **"chunking at 65504 on every leg is what makes one pacer
    /// legal"** ⛔ and ⛔ refusing a 200 KB write would push the chunking decision
    /// back to every caller, ⛔ which is ⛔ **exactly the mistake of sizing a
    /// buffer from the forward cap while transmitting on the reverse legs.**
    pub fn begin(&mut self, direction: Direction, bytes: u64) -> Result<Permit, SessionBudgetRefused> {
        let chunk = bytes.min(CHUNK_MAX as u64);
        let budget = self.budget;
        let committed_total = self.committed_total;
        let slot = self.slot_mut(direction);
        if slot.window.in_flight + chunk > slot.window.ceiling {
            slot.parked.push(Parked { direction, bytes: chunk });
            return Ok(Permit::Parked {
                in_flight: slot.window.in_flight,
                ceiling: slot.window.ceiling,
            });
        }
        // ⛔ **The budget is checked before the bytes are committed**, ⛔ so a
        // refused write leaves every counter exactly as it was ⛔ — ⛔ a refusal
        // that also charged the budget would make the *next* refusal different,
        // and ⛔ a session that fails differently on the second attempt is a bug
        // that looks like a race.
        let committed = slot.window.committed + chunk;
        let total = committed_total + chunk;
        if committed > budget || total > budget {
            // ⛔ **Un-park: a refused write must not sit in the queue.**
            slot.parked.pop();
            return Err(SessionBudgetRefused {
                direction,
                committed: committed.max(total),
                budget,
                cap: super::SESSION_CAP,
            });
        }
        slot.window.in_flight += chunk;
        slot.window.committed = committed;
        let window = slot.window;
        self.committed_total = total;
        Ok(Permit::Go { in_flight: window.in_flight, ceiling: window.ceiling })
    }

    /// ⛔ **A send completed. ⛔ Release its bytes and take the next parked write.**
    ///
    /// ⛔ **The release is one chunk, not one message.** ⛔ A completion does not
    /// say which bytes it completed ⛔ — ⛔ it says one frame's worth left ⛔ —
    /// and ⛔ **subtracting a caller's whole message would let the in-flight
    /// count go negative**, ⛔ which is ⛔ **a pacer that has stopped pacing
    /// while looking like one that paces.**
    ///
    /// ⛔ **Every byte a completion releases is charged to `released`, including
    /// bytes nobody is waiting to send**, ⛔ and ⛔ **`lost` is whatever the
    /// ledger could not account for.** ⛔ Those two numbers together are ⛔ **how
    /// a caller detects a truncated stream without a retransmit layer**: ⛔
    /// `replayed` is zero and `committed - released` is the bytes that may never
    /// have reached the target.
    pub fn complete(&mut self, direction: Direction, bytes: u64) -> Completions {
        let chunk = bytes.min(CHUNK_MAX as u64);
        let mut released_total = 0u64;
        let mut ready = Vec::new();
        {
            let slot = self.slot_mut(direction);
            slot.window.in_flight = slot.window.in_flight.saturating_sub(chunk);
            // ⛔ **The completion's own bytes are released, not only the
            // ⛔ parked writes it frees** ⛔ — ⛔ and it is charged even
            // ⛔ when nothing is waiting to send, ⛔ because that is the
            // ⛔ whole of the truncation measurement** ⛔: a completion that
            // ⛔ arrived means those bytes left podssh, ⛔ and not being
            // ⛔ charged is ⛔ counting a delivered frame as lost.
            slot.window.released += chunk;
            while slot.window.in_flight < slot.window.ceiling {
                let Some(next) = slot.parked.first().copied() else { break };
                if slot.window.in_flight + next.bytes > slot.window.ceiling {
                    break;
                }
                let taken = slot.parked.remove(0);
                slot.window.in_flight += taken.bytes;
                slot.window.committed += taken.bytes;
                released_total += taken.bytes;
                ready.push(taken);
            }
        }
        self.committed_total += released_total;
        Completions { released: chunk, ready }
    }

    /// ⛔ **The `1011 relay backpressure` handler: ⛔ halve the ceiling, floor it
    /// at one chunk, and replay nothing.**
    ///
    /// ⛔ **Spec line 150's own words are *"Slow down"*** ⛔ and ⛔ *"the
    /// undelivered frame is dropped"*, ⛔ so ⛔ **the prescribed response is
    /// exactly the one taken here** ⛔ — ⛔ halving the ceiling, ⛔ **not retrying
    /// the frame**, and ⛔ **not** touching the other direction ⛔ because ⛔ the
    /// relay said which receiver was slow ⛔ **only in the direction it closed**.
    ///
    /// ⛔ **The drop is recorded, and ⛔ the ledger has no field that could replay
    /// it.** ⛔ [`Ledger::replayed`] is zero by construction ⛔ — ⛔ there is no
    /// method that increments it ⛔ — ⛔ **and that is deliberate: the guard
    /// against reintroducing a retransmit layer is the absence of the ability to
    /// resend, and it is asserted as zero on every test.**
    pub fn on_backpressure_close(&mut self, direction: Direction) -> Backpressure {
        let slot = self.slot_mut(direction);
        let before = slot.window.ceiling;
        let halved = (before / 2).max(CEILING_FLOOR);
        slot.window.ceiling = halved;
        slot.window.halvings += 1;
        Backpressure {
            direction,
            ceiling_before: before,
            ceiling_after: halved,
            halvings: slot.window.halvings,
            // ⛔ **The frame that was dropped is not counted anywhere as sent.**
            // ⛔ It went into `committed` when it was permitted and it never came
            // back, ⛔ **so `committed - released` grows by its size** ⛔ — ⛔ and
            // ⛔ that difference is the truncation the protocol layer will see.
            replayed: 0,
        }
    }

    pub fn in_flight(&self, direction: Direction) -> u64 {
        self.slot(direction).window.in_flight
    }

    pub fn ceiling(&self, direction: Direction) -> u64 {
        self.slot(direction).window.ceiling
    }

    pub fn committed(&self, direction: Direction) -> u64 {
        self.slot(direction).window.committed
    }

    pub const fn committed_total(&self) -> u64 {
        self.committed_total
    }

    pub fn halvings(&self, direction: Direction) -> u32 {
        self.slot(direction).window.halvings
    }

    pub fn parked(&self, direction: Direction) -> usize {
        self.slot(direction).parked.len()
    }

    /// ⛔ **Always zero.** ⛔ **There is no method that can make it anything
    /// else**, and ⛔ that is the shape of the guard: ⛔ a retransmit layer would
    /// be a method that increments it, and ⛔ **its absence is what stops one
    /// arriving by accident.**
    pub const fn replayed(&self) -> u64 {
        0
    }

    /// ⛔ **Bytes committed in a direction that no completion has released.** ⛔
    /// ⛔ **Not an error and not a failure** ⛔ — ⛔ it is the count of bytes in
    /// flight at this instant ⛔ **plus** ⛔ **the bytes the relay told us it
    /// dropped** ⛔ — ⛔ and ⛔ **at end of session the second half is a
    /// truncation**.
    /// ⛔ **Bytes some completion has released in this direction.**
    pub fn released(&self, direction: Direction) -> u64 {
        self.slot(direction).window.released
    }

    /// ⛔ **THE TRUNCATION: bytes committed that no completion ever
    /// released.** ⛔
    ///
    /// ⛔ **This is the number E16 needs, and it is the reason the
    /// module has no retransmit layer rather than in spite of it** ⛔ —
    /// ⛔ **"no retransmit" without a way to MEASURE what was lost is
    /// unreliable** ⛔ .
    ///
    /// ⛔ **At end of session: `0` means every committed byte was
    /// accounted for, ⛔ and any other value is a short stream** ⛔
    /// ⛔ **and SSH will fail the MAC or report a short read on
    /// exactly that number of missing bytes** ⛔ .
    pub fn unaccounted(&self, direction: Direction) -> u64 {
        self.slot(direction)
            .window
            .committed
            .saturating_sub(self.slot(direction).window.released)
    }

    /// ⛔ **Bytes committed in a direction that are still in flight.** ⛔
    /// ⛔ **This is `committed - in_flight`, and it is NOT the truncation** ⛔
    /// ⛔ — ⛔ a dropped frame is in this number too, ⛔ which is exactly
    /// why ⛔ [`Ledger::unaccounted`] ⛔ exists.⛔
    pub fn unreleased(&self, direction: Direction) -> u64 {
        self.slot(direction)
            .window
            .committed
            .saturating_sub(self.slot(direction).window.in_flight)
    }

    /// ⛔ **Whether the chunk arithmetic the entry depends on actually holds.**
    /// ⛔ **A full ceiling plus one chunk must stay under the published
    /// threshold**, ⛔ and ⛔ **a full ceiling plus one chunk at the *halved*
    /// ceiling must stay under it too** ⛔ — ⛔ the second half is the half the
    /// entry does not state, ⛔ and ⛔ it holds because halving moves the ceiling
    /// away from the threshold.
    pub fn headroom_holds(&self, ceiling: u64) -> bool {
        ceiling + CHUNK_MAX as u64 <= super::QUEUE_THRESHOLD
    }
}

/// ⛔ **What one completion released and what became sendable.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completions {
    pub released: u64,
    /// ⛔ **Parked writes that now fit**, ⛔ **in the order they parked.** ⛔ FIFO
    /// ⛔ because ⛔ **re-ordering them would put a later chunk of a byte stream
    /// before an earlier one**, ⛔ and ⛔ a byte stream that arrives out of order is
    /// ⛔ a corrupt one.
    pub ready: Vec<Parked>,
}

/// ⛔ **What the `1011 relay backpressure` handler did.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backpressure {
    pub direction: Direction,
    pub ceiling_before: u64,
    pub ceiling_after: u64,
    pub halvings: u32,
    /// ⛔ **Always zero, and there is no way to make it otherwise.** ⛔ See
    /// [`Ledger::replayed`].
    pub replayed: u64,
}