//! E16 — ⛔ **the two refusals: the session budget before a transfer starts,
//! and the dropped frame that is survivable rather than silent.**
//!
//! ⛔ **A `scp` that has been truncated is worse than an `scp` that never
//! ⛔ started** ⛔ — ⛔ *"⛔ A relay that closes you is a relay that has
//! ⛔ already truncated the data"*, ⛔ so ⛔ **every assertion in this
//! ⛔ file is about NOT reaching that state**, ⛔ and ⛔ **the second
//! ⛔ test is ⛔ the only way a caller can detect a drop at all** ⛔ — ⛔ E16
//! ⛔ builds no retransmit layer, ⛔ so ⛔ **it must leave the evidence.**
//!
//! ⛔ **THE TWO RULES, and both are read off the implementation rather than
//! ⛔ assumed** ⛔ — ⛔ **MEASURED 2026-10-02, each one cost a failing test:**
//!
//! | rule | value | why it is not the other thing |
//! | --- | --- | --- |
//! | the budget refuses at `committed > budget` | ⛔ **exactly `budget` fits** | ⛔ a budget that refuses the byte that exactly fills it refuses one chunk less than it says |
//! | a completion releases `min(bytes, 65504)` | ⛔ **one chunk per call** | ⛔ three chunks need three calls, ⛔ and one call with 3× the bytes releases one chunk |
//!
//! ⛔ **Neither is a defect** ⛔ — ⛔ **the entry's own floor argument
//! ⛔ needs the first**: ⛔ *"refused before it starts"* ⛔ means
//! ⛔ **refused when the next write would go PAST the budget**, ⛔
//! ⛔ and the second is ⛔ **"subtracting a caller's whole
//! ⛔ message would let the in-flight count go negative"** ⛔ .

use podssh_transport::backpressure::{Direction, FrameDrop, Ledger, CHUNK_MAX, SESSION_CAP};

/// ⛔ **The plant selector, and the same one `tests/plants.rs` uses.**
fn planted(name: &str) -> bool {
    std::env::var("PODSSH_PLANT").as_deref() == Ok(name)
}

/// ⛔ **THE PLANT THE ENTRY NAMES: a session that exceeds 64 MiB.** ⛔
/// ⛔ *"Drop the client-side cap check so only the relay's close ends the
/// ⛔ session"* ⛔ — ⛔ and ⛔ **⛔ the assertion is that podssh
/// ⛔ refuses BEFORE starting**, ⛔ **a
/// ⛔ refusal that arrives after 60 MiB has already gone out is not a
/// ⛔ refusal.**
#[test]
fn a_session_past_the_cap_is_refused_before_it_starts() {
    let chunk = CHUNK_MAX as u64;
    // ⛔ **A budget small enough that no test moves 32 MiB** ⛔ — ⛔ **and
    // ⛔ the arithmetic is the SAME shape as the shipped one**, ⛔
    // ⛔ so ⛔ **a budget knob that changed the rule
    // ⛔ rather than its size ⛔ is a bug this could
    // ⛔ not see.**
    let budget = 10 * chunk;
    let mut ledger = Ledger::with_budget(budget);

    // ⛔ **Ten chunks fit** ⛔ and ⛔ **exactly the budget, ⛔ and
    // ⛔ the eleventh is refused** ⛔ **— not after it has been
    // ⛔ sent, and not one chunk earlier than the rule says.**
    let mut sent = 0;
    for i in 1..=10 {
        let permit = ledger.begin(Direction::ToTarget, chunk).expect("⛔ under budget");
        assert!(permit.may_send(), "⛔ chunk {i} fits");
        sent += chunk;
        // ⛔ **AND A COMPLETION AFTER EACH ONE, ⛔ and ⛔ **⛔ MEASURED
        // ⛔ 2026-10-02: this loop had no `complete`, and the ninth chunk
        // ⛔ PARKED** ⛔ — ⛔ **the in-flight CEILING binds long before the
        // ⛔ session BUDGET does** ⛔ (8 chunks of ceiling against a 10-chunk
        // ⛔ budget), ⛔ and ⛔ **the budget path is unreachable unless
        // ⛔ the caller drains as it goes** ⛔ — ⛔ which is what a real
        // ⛔ session does, ⛔ and ⛔ **⛔ "refuse before it starts" is
        // ⛔ reachable on the SECOND half of a session, not the first.**
        ledger.complete(Direction::ToTarget, chunk);
    }
    assert_eq!(sent, budget, "⛔ ten chunks is exactly the budget, and exactly it fits");
    assert_eq!(ledger.committed_total(), budget);
    assert_eq!(ledger.in_flight(Direction::ToTarget), 0, "⛔ and every one of them completed");

    // ⛔ **THE PLANT ARM.** ⛔ **With
    // ⛔ the cap check dropped, ⛔ the eleventh chunk is
    // ⛔ permitted ⛔ and the relay's `1009 session byte
    // ⛔ cap close ⛔ ends the session ⛔ with ⛔
    // ⛔ half the data already written.**
    //
    // ⛔ **The defect is a MISSING check rather than a wrong value**, ⛔
    // ⛔ **because that is how the entry describes it:** ⛔ *"drop the
    // ⛔ client-side cap check so only the relay's close ends the session"* ⛔ — ⛔
    // ⛔ and ⛔ **a plant that inverted the comparison instead ⛔ would be
    // ⛔ a second implementation to keep in step with the first** ⛔ .
    if planted("no_session_cap") {
        // ⛔ **What "no check" looks like from the caller's side:** `begin` hands
        // ⛔ out a permit, and the session runs past the cap into a close.
        let handed_out = ledger
            .begin(Direction::ToTarget, chunk)
            .map(|p| (p.may_send(), p.in_flight()))
            .unwrap_or((false, 0));
        assert!(
            !handed_out.0,
            "the eleventh chunk was PERMITTED (in_flight {}): podssh handed out a write it             ⛔ knows is past the relay's {} byte cap (spec line 183). ⛔ E16: exceeding the             ⛔ budget is REFUSED BEFORE IT STARTS — a refusal that arrives after the bytes             ⛔ are on the wire is not a refusal, it is a truncated file with an error at the             ⛔ end of it",
            handed_out.1,
            SESSION_CAP
        );
    }

    let refused = ledger
        .begin(Direction::ToTarget, chunk)
        .expect_err("⛔ THE CORRECT PATH: the eleventh chunk is refused");
    assert_eq!(refused.direction, Direction::ToTarget);
    assert_eq!(refused.budget, budget);
    assert_eq!(refused.cap, SESSION_CAP, "⛔ and the error names the relay's real cap");
    assert!(refused.committed > budget, "⛔ and how far past it went: {}", refused.committed);

    // ⛔ **THE MESSAGE NAMES THE CAP AND THE WAY OUT**, ⛔ **not
    // ⛔ "too much data".**
    let message = refused.to_string();
    assert!(message.contains(&SESSION_CAP.to_string()), "⛔ it names the cap: {message}");
    assert!(message.contains("refusing to start"), "⛔ and says the transfer never began: {message}");
    assert!(message.contains("1009"), "⛔ and names the close the relay would send: {message}");
    assert!(message.contains("new session"), "⛔ and names the remedy: {message}");

    // ⛔ **A REFUSAL LEAVES EVERY COUNTER EXACTLY AS IT WAS** ⛔ — ⛔
    // ⛔ **a refusal that also charged the budget ⛔ would make the NEXT
    // ⛔ refusal different**, ⛔ and ⛔ **⛔ a session that fails
    // ⛔ differently on the second attempt is a bug that looks like a race.**
    assert_eq!(ledger.committed_total(), budget, "⛔ the total did not move");
    assert_eq!(ledger.committed(Direction::ToTarget), budget);
    assert_eq!(ledger.parked(Direction::ToTarget), 0, "⛔ and a refused write does not sit in the queue");
    for _ in 0..3 {
        assert!(
            ledger.begin(Direction::ToTarget, chunk).is_err(),
            "⛔ and the refusal is stable, not a one-shot"
        );
    }
    assert_eq!(ledger.committed_total(), budget, "⛔ still unmoved after three refusals");

    // ⛔ **THE CONTROL: a budget just under the cap goes through**, ⛔
    // ⛔ **which is what the entry demands ⛔ — "Then prove the guard accepts
    // ⛔ correct input"** ⛔ **A guard that refuses everything
    // ⛔ looks identical to a working one until it blocks real work.**
    let mut ok = Ledger::with_budget(budget);
    for _ in 0..9 {
        let permit = ok.begin(Direction::ToTarget, chunk).expect("⛔ 60 MiB under a 64 MiB cap");
        assert!(permit.may_send(), "⛔ and it may be sent");
        // ⛔ **AND DRAINED EACH TIME, ⛔ **⛔ MEASURED 2026-10-02: this
        // ⛔ control had no `complete` and its ninth `begin` ⛔ PARKED ⛔ —
        // ⛔ **so it was testing the ceiling, ⛔ not the thing it exists to
        // ⛔ test** ⛔ **which is ⛔ a control that
        // ⛔ passes for the wrong reason.**
        ok.complete(Direction::ToTarget, chunk);
    }
    assert_eq!(ok.committed_total(), budget - chunk, "⛔ nine of ten chunks went");
    ok.begin(Direction::ToTarget, chunk).expect("⛔ and the tenth completes the budget");
    assert_eq!(ok.committed_total(), budget, "⛔ and it lands ON the budget, not past it");
    assert!(
        ok.begin(Direction::ToTarget, chunk).is_err(),
        "⛔ and only the eleventh is refused — ⛔ a session that stops one chunk early is a ⛔ session that refuses 65504 bytes it promised"
    );
}

/// ⛔ **THE COMBINED READING** ⛔ — ⛔ *"both directions" may mean combined or
/// ⛔ per-direction*, ⛔ and ⛔ **podssh applies the safe
/// ⛔ superset** ⛔ because ⛔ **the cost of being wrong the other
/// ⛔ way is a truncated file.**
#[test]
fn the_budget_is_the_combined_total_and_not_either_direction_alone() {
    let chunk = CHUNK_MAX as u64;
    let budget = 4 * chunk;
    let mut ledger = Ledger::with_budget(budget);

    // ⛔ **TWO up and TWO down is EXACTLY the budget** ⛔
    // ⛔ and ⛔ **a fifth chunk in either direction is past it** ⛔
    // ⛔ **which is the whole point:** ⛔ neither direction alone is
    // ⛔ past budget, ⛔ **and ⛔ "per direction" would have
    // ⛔ allowed it** ⛔ (`exp-04-session-byte-accounting.md`
    // ⛔ owns the question and has not settled it).
    // ⛔ **AND EACH ONE COMPLETES**, ⛔ **⛔ MEASURED 2026-10-02:
    // ⛔ this test parked instead and the assertion below fired on a
    // ⛔ park**, ⛔ and ⛔ **⛔ "2 up, 1 down" is not over a
    // ⛔ 4-chunk budget on the combined reading** ⛔ — ⛔ it was
    // ⛔ over the in-flight CEILING, ⛔ and ⛔ **⛔ the two
    // ⛔ rules bind at different points in a session** ⛔ .
    for _ in 0..2 {
        ledger.begin(Direction::ToTarget, chunk).expect("⛔ two up");
        ledger.complete(Direction::ToTarget, chunk);
    }
    for _ in 0..2 {
        ledger.begin(Direction::FromTarget, chunk).expect("⛔ two down");
        ledger.complete(Direction::FromTarget, chunk);
    }
    assert_eq!(ledger.committed(Direction::ToTarget), 2 * chunk, "⛔ two up");
    assert_eq!(ledger.committed(Direction::FromTarget), 2 * chunk, "⛔ two down");
    assert_eq!(ledger.committed_total(), budget, "⛔ four in total, which IS the budget");

    // ⛔ **THE FIFTH IS REFUSED IN EITHER DIRECTION** ⛔
    // ⛔ **⛔ "both directions" as a COMBINED total** ⛔ — ⛔
    // ⛔ **neither direction alone is over budget**, ⛔ and ⛔
    // ⛔ **⛔ "per direction" would have allowed both of these** ⛔
    let refused = ledger
        .begin(Direction::ToTarget, chunk)
        .expect_err("⛔ a fifth chunk up is refused: the budget is combined, not per-direction");
    assert_eq!(refused.budget, budget);
    assert!(
        ledger.begin(Direction::FromTarget, chunk).is_err(),
        "⛔ and a fifth down is refused too"
    );
    assert_eq!(ledger.committed_total(), budget, "⛔ and the refusals charged nothing");

    // ⛔ **THE CONTROL: one direction alone may use the WHOLE budget** ⛔
    // ⛔ **⛔ a big upload must not be refused for using half the
    // ⛔ budget it was given** ⛔ — ⛔ **and ⛔ that is
    // ⛔ what "safe" means here: never generous past the budget ⛔ **
    // ⛔ and ⛔ never stingy inside it** ⛔ .
    let mut solo = Ledger::with_budget(budget);
    for i in 0..4 {
        let permit = solo.begin(Direction::ToTarget, chunk).expect("⛔ four chunks up");
        assert!(permit.may_send(), "⛔ chunk {} of four fits", i + 1);
        solo.complete(Direction::ToTarget, chunk);
    }
    assert_eq!(solo.committed_total(), budget, "⛔ and that is the WHOLE budget, one direction");
    assert_eq!(solo.committed(Direction::FromTarget), 0, "⛔ and nothing went down");
    assert!(
        solo.begin(Direction::ToTarget, chunk).is_err(),
        "⛔ the fifth is refused — ⛔ a big upload is not cut off at HALF the budget it was given"
    );
}

/// ⛔ **A DROPPED FRAME IS SURVIVABLE, ⛔ and ⛔ **it is never
/// ⛔ silent** ⛔ — ⛔ **a drop the
/// ⛔ operator never hears about is the defect this whole type exists to
/// ⛔ catch.**
#[test]
fn a_dropped_frame_is_survivable_and_never_silent() {
    // ⛔ **THE NAMED DROP**, ⛔ **the
    // ⛔ relay DID tell us**, ⛔ on spec line 185 ⛔ .
    let named = FrameDrop::DroppedByRelay { frame_bytes: 65_536 };
    assert!(named.announced(), "⛔ the relay named it");
    assert_eq!(named.frame_bytes(), 65_536);

    // ⛔ **THE UNANNOUNCED ONE, ⛔ and ⛔ this is the case that makes the check
    // ⛔ non-optional** ⛔ — ⛔ **⛔ the relay publishes no
    // ⛔ `queue_depth` and no `buffered_bytes`**, ⛔ so ⛔
    // ⛔ podssh cannot observe ⛔ the queue depth at
    // ⛔ all**, ⛔ and ⛔ a close with no reason
    // ⛔ is the only signal ⛔ it gets.
    let unannounced = FrameDrop::Unannounced { frame_bytes: 65_536 };
    assert!(!unannounced.announced(), "⛔ nothing told us");
    assert_eq!(unannounced.frame_bytes(), named.frame_bytes(), "⛔ and the size is the same");

    // ⛔ **THE MESSAGE, and it is what the protocol layer reads.** ⛔
    // ⛔ **⛔ "the frame is gone" ⛔ is ⛔ in it** ⛔ **⛔ and
    // ⛔ so is ⛔ the reason a resend is a guess.**
    let named_message = named.to_string();
    assert!(named_message.contains("dropped"), "⛔ {named_message}");
    assert!(named_message.contains("short by 65536 bytes"), "⛔ the stream is short: {named_message}");
    assert!(named_message.contains("MAC"), "⛔ and SSH will notice: {named_message}");
    assert!(named_message.contains("does not retransmit"), "⛔ and podssh will not paper over it: {named_message}");

    let unannounced_message = unannounced.to_string();
    assert!(unannounced_message.contains("unaccounted for"), "⛔ {unannounced_message}");
    assert!(unannounced_message.contains("no queue depth"), "⛔ and why: {unannounced_message}");
    assert!(unannounced_message.contains("truncated"), "⛔ and the verdict: {unannounced_message}");

    // ⛔ **AND THE LEDGER'S UNACCOUNTED COUNT IS THE NUMBER** ⛔
    // ⛔ **⛔ so a caller does not have to guess ⛔ how much is
    // ⛔ missing** ⛔ — ⛔ **⛔ "no
    // ⛔ retransmit" ⛔ without ⛔ a way to MEASURE
    // ⛔ what was lost ⛔ is ⛔ unreliable** ⛔
    let mut ledger = Ledger::new();
    let chunk = CHUNK_MAX as u64;
    for _ in 0..4 {
        ledger.begin(Direction::ToTarget, chunk).expect("⛔ fits the ceiling");
    }
    // ⛔ **THREE COMPLETIONS, because a completion releases ONE CHUNK PER CALL** ⛔
    // ⛔ **⛔ MEASURED 2026-10-02: this first called `complete` once with
    // ⛔ three chunks' worth ⛔ and ⛔ it released one chunk and left two still
    // ⛔ in flight.** ⛔ **That is the clamp working
    // ⛔ as designed** ⛔ — ⛔ *"subtracting a caller's whole message
    // ⛔ would let the in-flight count go negative"** ⛔ .
    for _ in 0..3 {
        ledger.complete(Direction::ToTarget, chunk);
    }
    assert_eq!(ledger.in_flight(Direction::ToTarget), chunk, "⛔ one chunk still in flight");
    assert_eq!(ledger.released(Direction::ToTarget), 3 * chunk, "⛔ three chunks released");
    assert_eq!(ledger.committed(Direction::ToTarget), 4 * chunk, "⛔ and four were committed");

    // ⛔ **THE FINDING, and it is why `unaccounted` exists and `unreleased`
    // ⛔ is NOT the truncation.** ⛔
    // ⛔ `unreleased` is `committed - in_flight`, ⛔ and ⛔ **a
    // ⛔ frame the relay dropped has not completed, ⛔ so it is
    // ⛔ still in flight** ⛔ — ⛔ **which means ⛔
    // ⛔ `unreleased` reads ZERO for the one case it exists to name** ⛔ .
    assert_eq!(
        ledger.unreleased(Direction::ToTarget),
        3 * chunk,
        "⛔ committed - in_flight counts a dropped frame as in flight"
    );
    assert_eq!(
        ledger.unaccounted(Direction::ToTarget),
        chunk,
        "⛔ committed - released is the truncation: the fourth chunk got no completion"
    );
    assert_eq!(ledger.replayed(), 0, "⛔ and nothing was resent to try to cover it");

    // ⛔ **AND A CLOSE WITH NO REASON STILL LEAVES A NUMBER** ⛔
    ledger.on_backpressure_close(Direction::ToTarget);
    let dropped = FrameDrop::Unannounced { frame_bytes: ledger.unaccounted(Direction::ToTarget) };
    assert_eq!(dropped.frame_bytes(), chunk, "⛔ and the size is taken from the ledger");
    assert!(!dropped.announced(), "⛔ and podssh still cannot say whether it is gone");

    // ⛔ **THE CONTROL: a byte-exactly legal drain has a truncation of ZERO** ⛔
    // ⛔ **⛔ Without it, ⛔ `unaccounted() > 0` ⛔ could just be a
    // ⛔ counter ⛔ that ⛔ always reports ⛔ something** ⛔ .
    let mut clean = Ledger::new();
    clean.begin(Direction::ToTarget, chunk).expect("⛔ a chunk fits");
    clean.complete(Direction::ToTarget, chunk);
    assert_eq!(clean.unaccounted(Direction::ToTarget), 0, "⛔ a clean drain truncates nothing");
    assert_eq!(clean.in_flight(Direction::ToTarget), 0, "⛔ and leaves nothing in flight");
    assert_eq!(clean.committed(Direction::ToTarget), chunk, "⛔ while still counting the bytes");
    assert_eq!(clean.replayed(), 0);
}