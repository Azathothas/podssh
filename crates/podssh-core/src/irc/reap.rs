//! Keeping the session alive, and **not fighting a reaper that always wins**.
//!
//! ## The three numbers, and why only one of them is a reaper
//!
//! **Spec line 233, and the clause that matters is in the parentheses:**
//! *"idle sessions (180000 ms of payload inactivity; **transport keepalives do
//! not reset this**)"*. That parenthetical is the whole of this module. The
//! relay counts **payload** bytes, so an idle connection kept alive by
//! keepalives alone is reaped anyway at 180 s, and a podssh that answered
//! every server `PING` with a `PONG` would still be reaped.
//!
//! **A `PONG` is one IRC message on the wire**, so a client that thinks
//! "I answered the ping, I am alive" has measured the wrong thing: the relay
//! sees one message's worth of payload every few minutes and calls the session
//! idle.
//!
//! ## What podssh sends, and why it is not chatter
//!
//! **A `PRIVMSG` to a channel the user is in**, on a timer, whose text
//! is a **heartbeat the receiving client recognises and does not display**.
//! It is payload, it is invisible, and it doubles as proof the link works
//! in both directions. **It is a `PRIVMSG` and not a `PONG`** because a
//! `PONG` answers one message and this has to keep arriving on its own.
//!
//! **The other half: podssh must also receive.** The reaper is symmetric
//! and a session nobody speaks into is reaped the same way, so the user
//! typing anything is itself the payload that resets it — which means an
//! **idle pair of users** is the case that needs the heartbeat, and a busy
//! one does not. The plan is therefore computed from **both** directions.
//!
//! **No clock is read here.** [`PayloadPlan::due`] takes `now_ms` from the
//! caller, because a module that read a clock would make its own behaviour
//! untestable and this repository's rule is that a check is a plant plus a
//! control.

use crate::irc::limits::IDLE_REAPER_MS;

/// **How often podssh writes a heartbeat.** **A third of the reaper
/// window**, and the choice of a third is arithmetic rather than taste:
///
/// * **One skipped heartbeat must not kill the session.** A missed beat is
///   120 s of payload silence, still inside 180 s, so a single dropped timer
///   tick — a busy machine, a stalled read — is survivable.
/// * **A third of the window is inside the window with room to spare**: the
///   worst case with one missed beat is 120 s of payload silence, and 60 s of
///   headroom remain. **Two missed beats is 180 s and the session is
///   gone**, so the margin is one beat and not two and the test says so.
/// * **A fourth would be 45 s** and a heartbeat every 45 s is visible on a
///   shared channel's scrollback to any user who has not installed the
///   recogniser, which is a cost this design does not need to pay.
pub const HEARTBEAT_PERIOD_MS: u64 = IDLE_REAPER_MS / 3;

/// **The text podssh sends.** **It carries a version and a nonce, and
/// the nonce is the point**: a heartbeat with a fixed text is one a user can
/// silence by muting, and one that survives a reconnect is indistinguishable
/// from a stale one queued in a server's buffer. The nonce is **not a secret
/// and not a credential** — it is a counter, and a counter is what makes
/// "the same heartbeat twice" detectable.
pub const HEARTBEAT_PREFIX: &str = "\u{200b}podssh";

/// Build one heartbeat's text.
pub fn heartbeat_text(generation: u64) -> String {
    format!("{HEARTBEAT_PREFIX}/{generation}")
}

/// **Is this a heartbeat, and what generation was it?** **The zero-width
/// space is required and not decoration.** The character is stripped by most
/// IRC loggers and by every terminal that renders it, so a heartbeat that a
/// user somehow saw would appear as a blank line rather than as a word they
/// might reply to. A prefix without it is text a user could quote.
pub fn parse_heartbeat(text: &str) -> Option<u64> {
    let rest = text.strip_prefix(HEARTBEAT_PREFIX)?;
    let rest = rest.strip_prefix('/')?;
    rest.parse().ok()
}

/// What the client should send to keep the session's payload counter alive.
///
/// **Two booleans, not one interval**, because the reaper counts payload in
/// both directions and a client that only tracked its own writes would keep a
/// link alive that the far end had stopped using and then discover it on the
/// next message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PayloadPlan {
    /// Send a heartbeat because the client has been quiet.
    pub send_heartbeat: bool,
    /// **A frame arrived since the last heartbeat**, so the session's
    /// payload counter was just reset and no heartbeat was needed. **The
    /// caller's word and never a derivation**, because a frame arriving is
    /// a fact and "and it has been at least a period" is a different one.
    pub received_since_last_beat: bool,
    /// **Neither end has sent anything for a whole period**, which is the
    /// state the relay's reaper is about to act on. Distinct from
    /// `send_heartbeat: false`, which may simply mean the user is typing.
    pub both_ends_quiet: bool,
}

/// **Decide, from two timestamps and a delivery, what to do now.**
///
/// **`since_send_ms` and `since_recv_ms` are supplied by the caller**
/// because this repository's own rule is that a check with no failure test is
/// not a check: a module that read a clock could only be tested by sleeping,
/// and a test that sleeps is a test that is skipped on a loaded CI machine and
/// passes because it ran no assertions.
pub fn payload_plan_for(
    _now_ms: u64,
    since_send_ms: u64,
    since_recv_ms: u64,
    received_since_last_beat: bool,
    period_ms: u64,
) -> PayloadPlan {
    let quiet_send = since_send_ms >= period_ms;
    let quiet_recv = since_recv_ms >= period_ms;
    // **Send when the client's own side is quiet, not when both are.** If
    // podssh waited for both to be quiet, a link where one user types
    // steadily would never be heartbeated from the other end, and the reaper
    // would still reap it as soon as *that* user stopped.
    //
    // **AND `received_since_last_beat` IS THE CALLER'S WORD, NOT A
    // DERIVATION.** A first version computed it as
    // `received_since_last_beat || !quiet_recv`, and **that is inverted**:
    // `!quiet_recv` means *nothing has arrived since the period*, which is
    // the opposite of what the field says. MEASURED 2026-10-02: with
    // `since_recv_ms = 0` and no delivery the plan claimed a reception had
    // happened, and a caller that trusts it logs a link as live while both
    // ends are silent.
    //
    // **The flag the caller sets means "a frame arrived"** and a timestamp
    // means "and it has been at least this long". Both are facts about the
    // stream, and neither can be inferred from the other.
    PayloadPlan {
        send_heartbeat: quiet_send,
        received_since_last_beat,
        // **"Both ends have been silent for a whole period"**, which is the
        // state in which the session is closest to being reaped and the one
        // a caller wants to log rather than infer from two other fields.
        both_ends_quiet: quiet_send && quiet_recv,
    }
}

/// **The policy, as a value**, so a caller holds one number rather than
/// recomputing the period from the reaper's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapPolicy {
    pub heartbeat_period_ms: u64,
}

impl Default for ReapPolicy {
    fn default() -> Self {
        ReapPolicy { heartbeat_period_ms: HEARTBEAT_PERIOD_MS }
    }
}

impl ReapPolicy {
    /// A policy built from a **measured** reaper window, rather than from
    /// the constant. `/relays.json` publishes `idle_timeout_ms` and
    /// **the honest thing is to use what the peer says**, because a relay
    /// that moved its window from 180 s to 300 s would make podssh's hardcoded
    /// third far more aggressive than it needs to be and a heartbeat every
    /// 100 s is visible in a channel's scrollback.
    ///
    /// **A window of zero is refused**, because dividing by it is a panic
    /// and a relay reporting `0` is a relay whose answer has not been read.
    pub fn from_reaper_ms(reaper_ms: u64) -> Result<Self, String> {
        if reaper_ms == 0 {
            return Err("the relay reports idle_timeout_ms = 0".into());
        }
        Ok(ReapPolicy { heartbeat_period_ms: reaper_ms / 3 })
    }

    pub fn plan(
        &self,
        now_ms: u64,
        since_send_ms: u64,
        since_recv_ms: u64,
        received_since_last_beat: bool,
    ) -> PayloadPlan {
        payload_plan_for(now_ms, since_send_ms, since_recv_ms, received_since_last_beat, self.heartbeat_period_ms)
    }
}
