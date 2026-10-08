//! E16 — ⛔ **the pacer: one in-flight ceiling, both directions, halved on
//! `1011 relay backpressure` and never retried.**
//!
//! ⛔ **The forward path is NOT lossless under backpressure and that is the
//! relay's own statement, not an inference.** **READ**, live spec line 185,
//! verified on 2026-10-02 with `sed -n '150p'` against the pinned 211-line copy
//! (sha256 `a82bf7c9…c2430`):
//!
//! ```text
//! | 1011 | relay backpressure | either | Over 1 MiB queued for a slow
//! receiver. Slow down; the undelivered frame is dropped. |
//! ```
//!
//! ⛔ **The `either` is the load-bearing word.** The drop can land on podssh's
//! socket whichever way the session was established, and ⛔ **any file transfer
//! over it must handle a dropped frame.** ⛔ **The frame is dropped, not
//! buffered and not retried** ⛔ — and ⛔ **a dropped frame is survivable only
//! because SSH detects a truncated stream**: a MAC failure on the packets that
//! follow, or a short read when the channel closes. ⛔ **That is why E16's
//! Decision builds no retransmit layer**, and ⛔ **`why_a_dropped_frame_is_survivable`
//! is a method rather than a comment, so the claim is a value the protocol layer
//! reads and the tests assert.**
//!
//! ⛔ **The numbers, and where each came from:**
//!
//! | bound | value | source |
//! | --- | --- | --- |
//! | chunk, all legs | **65504** | ⛔ `INFERRED` from three caps: +32 id = 65536 ≤ 65568 wire (line 147), ≤ 65536 operator payload (line 149), ≤ 262144 forward |
//! | in-flight ceiling | **524288** | half the 1 MiB threshold on line 185, so a full ceiling plus one chunk stays under it |
//! | warn before | **33554432** | half the 64 MiB session cap (line 148), the same shape of rule as E20's "warn before, do not only react after" |
//!
//! ⛔ **The ceiling is a client-side approximation of a relay-side queue.** ⛔ It
//! is right on average and wrong in the instant ⛔ — ⛔ the relay also queues what
//! podssh already handed to TLS ⛔ — and ⛔ **a wrong-but-survivable ceiling is
//! strictly better than a dropped frame.** ⛔ The alternative is to trust the
//! frames and let the relay decide, which loses the frame.
//!
//! ⛔ **It owns no timer of its own.** ⛔ Every wait is driven by a send
//! completion, ⛔ **so it cannot become the thing that blocks a runtime worker.**

mod ledger;

pub use ledger::{Direction, Ledger, Parked};

/// ⛔ **The chunk size on every leg, and ⛔ *why this number and not 262144*.**
///
/// ⛔ **The binding constraint is the operator payload cap on spec line 184**, ⛔
/// **not** the forward cap ⛔ — ⛔ **"podssh never sizes a buffer from the forward
/// cap while transmitting on the reverse legs"**, ⛔ **and that is the same
/// conflation correction #6 recorded for `dropssh`.** ⛔ **65504 + 32 = 65536**
/// leaves the node wire frame at 65536, ⛔ under the 65568 of line 147, and
/// ⛔ **the chunk is smaller than every cap on purpose** ⛔ — ⛔ one number on
/// every leg is what makes **one pacer legal**.
pub const CHUNK_MAX: usize = 65_504;

/// ⛔ **READ**, spec line 185: *"Over 1 MiB queued for a slow receiver."**
pub const QUEUE_THRESHOLD: u64 = 1_048_576;

/// ⛔ **Half of it, and the reason for the half is arithmetic and testable.**
///
/// ⛔ **A full ceiling plus one chunk must still sit under the threshold**, or the
/// pacer would trip the very condition it exists to avoid ⛔ — ⛔ and
/// [`Ledger::headroom_holds`] asserts `524288 + 65504 <= 1048576` on every run.
pub const INFLIGHT_CEILING: u64 = QUEUE_THRESHOLD / 2;

/// ⛔ **READ**, spec line 183: *"One session exceeded 64 MiB in both directions."*
pub const SESSION_CAP: u64 = 67_108_864;

/// ⛔ **Half the session cap, and the refusal happens at the *budget*, not at the
/// cap.** ⛔ A transfer over the cap is ⛔ **"refused before it starts"**, ⛔ with
/// an error naming the cap ⛔ — ⛔ **never a truncated stream.** ⚠ **`65536` is
/// ⛔ `INFERRED`** ⛔ — ⛔ "both directions" may mean combined or per-direction,
/// ⛔ and [`Ledger::begin`] ⛔ **applies the safe superset (combined)** ⛔ because
/// ⛔ the cost of being wrong the other way is a truncated file ⛔
/// (`exp-04-session-byte-accounting.md`).
pub const SESSION_BUDGET: u64 = SESSION_CAP / 2;

/// ⛔ **One `1011` halves the ceiling, and this is the floor it cannot go below.**
/// ⛔ **One chunk** ⛔ — ⛔ halving to zero would deadlock the session, and ⛔ a
/// floor at one chunk is the same reasoning E16's `## Decision` gives for
/// choosing halving over a fixed slow-down.
pub const CEILING_FLOOR: u64 = CHUNK_MAX as u64;

/// ⛔ **The consequence of a dropped frame, and ⛔ **why it is survivable**.
///
/// ⛔ **The relay did not re-order and did not corrupt: it dropped one frame and
/// said so.** ⛔ The stream podssh hands to SSH is therefore ⛔ **short**, and ⛔
/// **SSH already knows what a short stream is** ⛔ — ⛔ a MAC failure on the
/// packets that follow, or a short read when the channel closes with fewer bytes
/// than the message needed. ⛔ **podssh does not repair it, and must not**: a
/// retransmit layer here would sit *below* the layer that already knows what
/// integrity means, ⛔ and ⛔ **the relay acknowledges nothing about what it lost**,
/// ⛔ **so a retransmit could not even learn what to resend without guessing.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDrop {
    /// ⛔ The relay dropped the frame and told us, on spec line 185.
    DroppedByRelay { frame_bytes: u64 },
    /// ⛔ **A drop podssh did not learn about.** ⛔ **This is the case that
    /// makes the check non-optional**, and it is `UNKNOWN` in size ⛔ — ⛔ the
    /// relay publishes no `queue_depth` and no `buffered_bytes`
    /// ⛔ (`backpressure.md` `## Premise`), ⛔ **so podssh cannot observe the queue
    /// depth at all** ⛔ and ⛔ a close with no reason is the only signal it gets.
    Unannounced { frame_bytes: u64 },
}

impl FrameDrop {
    pub const fn frame_bytes(&self) -> u64 {
        match self {
            FrameDrop::DroppedByRelay { frame_bytes } | FrameDrop::Unannounced { frame_bytes } => {
                *frame_bytes
            }
        }
    }

    /// ⛔ **Whether the relay named it.** ⛔ A named drop is knowable; an
    /// unannounced one is the one that reaches the protocol layer as a
    /// truncation.
    pub const fn announced(&self) -> bool {
        matches!(self, FrameDrop::DroppedByRelay { .. })
    }
}

impl std::fmt::Display for FrameDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameDrop::DroppedByRelay { frame_bytes } => write!(
                f,
                "the relay dropped a {frame_bytes}-byte frame (spec line 185, \
                 `1011 relay backpressure`); the stream is short by {frame_bytes} bytes and \
                 SSH will fail the MAC or report a short read. podssh does not retransmit: \
                 the relay acknowledged nothing, so a resend would be a guess"
            ),
            FrameDrop::Unannounced { frame_bytes } => write!(
                f,
                "a {frame_bytes}-byte frame is unaccounted for; the relay published no queue \
                 depth, so the only signal podssh got was the socket ending. Treat the \
                 stream as truncated: SSH will fail the MAC or report a short read"
            ),
        }
    }
}

/// ⛔ **The refusal that happens before a transfer starts.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBudgetRefused {
    pub direction: Direction,
    pub committed: u64,
    pub budget: u64,
    pub cap: u64,
}

impl std::fmt::Display for SessionBudgetRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refusing to start")?;
        write!(f, ": the {} direction already carries {} bytes and this write would take ", self.direction, self.committed)?;
        write!(f, "it past the {} byte budget. ", self.budget)?;
        write!(f, "⛔ The relay's cap is {} bytes per session (spec line 183) and podssh ", self.cap)?;
        write!(f, "halves it, because \"in both directions\" may mean combined and the cost of ")?;
        write!(f, "being wrong is a truncated file. Open a new session (spec line 183: ")?;
        write!(f, "`1009 session byte cap`) rather than discovering the cap as a close half-way through")
    }
}

impl std::error::Error for SessionBudgetRefused {}

/// ⛔ **The three outcomes a `begin` can have.** ⛔ **`Ok(None)` is the
/// interesting arm**: ⛔ the write may proceed, ⛔ **but it may not be sent yet**
/// ⛔ — ⛔ the ceiling is full and the write is parked for a completion to
/// release it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permit {
    /// ⛔ Go, with the bytes this write added to the in-flight count.
    Go { in_flight: u64, ceiling: u64 },
    /// ⛔ **Parked, and the caller's chunk is not counted.** ⛔ It counts when a
    /// completion releases room ⛔ — ⛔ **counting it at park time is how a
    /// pacer inflates its own backlog.**
    Parked { in_flight: u64, ceiling: u64 },
}

impl Permit {
    pub const fn may_send(&self) -> bool {
        matches!(self, Permit::Go { .. })
    }

    pub const fn in_flight(&self) -> u64 {
        match self {
            Permit::Go { in_flight, .. } | Permit::Parked { in_flight, .. } => *in_flight,
        }
    }

    pub const fn ceiling(&self) -> u64 {
        match self {
            Permit::Go { ceiling, .. } | Permit::Parked { ceiling, .. } => *ceiling,
        }
    }
}