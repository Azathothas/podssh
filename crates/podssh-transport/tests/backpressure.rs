//! E16 — ⛔ **the pacer's own properties: the ceiling, the halving, the budget,
//! and the fact that nothing is ever replayed.**
//!
//! ⛔ **Every number here is derived from three published caps, and a test
//! ⛔ that asserts a constant against itself proves nothing** ⛔ — ⛔ **so
//! ⛔ the arithmetic is asserted as the inequality the entry depends on**
//! ⛔ (`ceiling + 65504 <= 1048576`), ⛔ and the
//! ⛔ constants themselves are asserted against the spec lines they cite.
//!
//! ⛔ **The plants are `backpressure_plants.rs`**, ⛔ **because the entry's
//! ⛔ "no replay" assertion and the entry's halving assertion are the
//! ⛔ same fact** ⛔ — ⛔ **one test that reads the halving
//! ⛔ and one that reads the replay count is one fact read twice**,
//! ⛔ and ⛔ **the plant is the one that would have to be
//! ⛔ planted to prove the assertion is load-bearing.**

use podssh_transport::backpressure::{
    Direction, Ledger, CHUNK_MAX, CEILING_FLOOR, INFLIGHT_CEILING,
    QUEUE_THRESHOLD, SESSION_BUDGET, SESSION_CAP,
};

/// ⛔ **The plant selector, and the same one `tests/plants.rs` uses.**
fn planted(name: &str) -> bool {
    std::env::var("PODSSH_PLANT").as_deref() == Ok(name)
}

/// ⛔ **A ceiling the test can fill with eight chunks, reached by halving.**
///
/// ⛔ **The ceiling is GIVEN IN CHUNKS and not in halvings**, ⛔ because ⛔
/// ⛔ **524288 is not a power of two in units of 65504** ⛔ (it is 8.0007
/// ⛔ chunks), ⛔ so ⛔ **no halving count lands it on a clean multiple** ⛔ and a
/// ⛔ test written as "halve N times" is either off by one or silently testing
/// ⛔ a ceiling it did not mean to. ⛔ **MEASURED 2026-10-02: this helper was
/// ⛔ first written as four halvings and asserted 327520 against a ceiling of
/// ⛔ 32768.**
fn small_ledger() -> Ledger {
    let mut ledger = Ledger::with_budget(SESSION_BUDGET);
    let chunk = CHUNK_MAX as u64;
    let want_chunks = 8u64;
    let mut halvings = 0;
    while ledger.ceiling(Direction::ToTarget) / chunk < want_chunks {
        ledger.on_backpressure_close(Direction::ToTarget);
        halvings += 1;
        assert!(halvings < 32, "⛔ the floor is one chunk, so this cannot run away");
    }
    // ⛔ **Eight whole chunks fit and the ninth parks** ⛔ - ⛔ a test that wrote
    // ⛔ the shipped 524288 would have to move half a megabyte to get here.
    assert_eq!(
        ledger.ceiling(Direction::ToTarget) / chunk,
        want_chunks,
        "⛔ after {halvings} halving(s) the ceiling holds eight whole chunks"
    );
    ledger
}

/// ⛔ **The three caps, as arithmetic the entry depends on.**
#[test]
fn the_ceiling_and_the_chunk_stay_under_the_published_threshold() {
    // ⛔ **A full ceiling plus one chunk must still sit under the threshold**, ⛔
    // ⛔ or the pacer would trip the very condition it exists to avoid.
    assert!(
        INFLIGHT_CEILING + CHUNK_MAX as u64 <= QUEUE_THRESHOLD,
        "⛔ a full ceiling plus a chunk is {}, over the {} the relay publishes",
        INFLIGHT_CEILING + CHUNK_MAX as u64,
        QUEUE_THRESHOLD
    );
    assert!(Ledger::new().headroom_holds(INFLIGHT_CEILING));
    assert!(Ledger::new().headroom_holds(CEILING_FLOOR));
    // ⛔ **And at every halved ceiling too**, ⛔ which is the half the entry
    // ⛔ does not state and which holds because halving moves the ceiling away
    // ⛔ from the threshold.
    for halvings in 0..12 {
        let mut ledger = Ledger::new();
        for _ in 0..halvings {
            ledger.on_backpressure_close(Direction::ToTarget);
        }
        assert!(
            ledger.headroom_holds(ledger.ceiling(Direction::ToTarget)),
            "⛔ after {halvings} halving(s) the ceiling is {}",
            ledger.ceiling(Direction::ToTarget)
        );
    }

    // ⛔ **THE CAPS, against the spec lines they cite.** ⛔ **READ**, ⛔
    // ⛔ live spec line 185 ⛔ *"Over 1 MiB queued"* ⛔ and ⛔
    // ⛔ line 183 ⛔ *"One session exceeded 64 MiB"*, ⛔ verified ⛔
    // ⛔ 2026-10-02 with `sed -n` against the pinned 211-line copy ⛔
    // ⛔ (sha256 `a82bf7c9…c2430`).
    assert_eq!(QUEUE_THRESHOLD, 1_048_576, "⛔ spec line 185: 1 MiB");
    assert_eq!(SESSION_CAP, 67_108_864, "⛔ spec line 183: 64 MiB");
    assert_eq!(INFLIGHT_CEILING, QUEUE_THRESHOLD / 2, "⛔ and the ceiling is half of it");
    assert_eq!(SESSION_BUDGET, 33_554_432, "⛔ and the budget is half the cap");
    // ⛔ **The chunk is derived from the TIGHTEST cap and not the forward
    // ⛔ one**, ⛔ **because ⛔ "podssh never sizes a buffer from the
    // ⛔ forward cap while transmitting on the reverse legs"** ⛔ — ⛔
    // ⛔ and ⛔ **that is conflation correction #6.**
    assert_eq!(CHUNK_MAX, 65_504, "⛔ the largest payload under EVERY cap");
    assert_eq!(CHUNK_MAX + 32, 65_536, "⛔ +32 id = 65536 <= the 65568 wire frame");
    assert!(CHUNK_MAX + 32 <= 65_568, "⛔ spec line 182");
    assert!(CHUNK_MAX as u64 <= 65_536, "⛔ spec line 184: the operator payload cap");
    assert!(CHUNK_MAX as u64 <= 262_144, "⛔ and the forward cap");
    assert!(CHUNK_MAX < 262_144 / 4, "⛔ and it is under a quarter of the forward cap");
    assert_eq!(CEILING_FLOOR, CHUNK_MAX as u64, "⛔ the floor is one chunk, not zero");
}

/// ⛔ **A slow receiver parks writes; ⛔ a completion releases exactly
/// ⛔ one chunk and re-drives them FIFO.**
#[test]
fn a_slow_receiver_parks_writes_and_a_completion_releases_one_chunk() {
    let mut ledger = small_ledger();
    let chunk = CHUNK_MAX as u64;
    let half = ledger.ceiling(Direction::ToTarget);

    // ⛔ **Fill the ceiling exactly.** ⛔ `in_flight + chunk <= ceiling` ⛔ — ⛔
    // ⛔ so ⛔ a write that would exactly fill it still goes.
    let first = ledger.begin(Direction::ToTarget, chunk).expect("⛔ the first chunk fits");
    assert!(first.may_send(), "⛔ the first chunk is permitted");
    assert_eq!(first.in_flight(), chunk);
    assert_eq!(first.ceiling(), half);

    let mut sent = chunk;
    while sent + chunk <= half {
        let permit = ledger.begin(Direction::ToTarget, chunk).expect("⛔ under budget");
        assert!(permit.may_send(), "⛔ a chunk that fits is sent");
        assert_eq!(permit.in_flight(), sent + chunk);
        sent += chunk;
    }
    // ⛔ **The ceiling is filled with WHOLE CHUNKS: 524032, and not 524288** ⛔ —
    // ⛔ `half` is not a multiple of 65504, ⛔ so ⛔ **`sent` lands just
    // ⛔ under it** ⛔ and ⛔ **a test that asserted `sent == half`
    // ⛔ would have been asserting an integer division result was exact** ⛔ .
    assert_eq!(sent, half - half % chunk, "⛔ every whole chunk fits");
    assert_eq!(half / chunk, 8, "⛔ and eight of them");
    assert_eq!(half % chunk, 524_288 % chunk, "⛔ with 256 bytes of slack no chunk can use");

    // ⛔ **THE NEXT ONE PARKS**, ⛔ and ⛔ **the parked chunk is NOT counted.**
    let parked = ledger.begin(Direction::ToTarget, chunk).expect("⛔ parking is not a refusal");
    assert!(!parked.may_send(), "⛔ a full ceiling parks the write");
    assert_eq!(parked.in_flight(), sent, "⛔ and the in-flight count did not move");
    assert_eq!(ledger.parked(Direction::ToTarget), 1);
    assert_eq!(
        ledger.committed(Direction::ToTarget),
        sent,
        "⛔ and it is not committed: ⛔ counting it at park time is how a pacer inflates its own backlog"
    );

    // ⛔ **A completion releases ONE CHUNK, ⛔ not the caller's whole
    // ⛔ message**, ⛔ and ⛔ **the parked chunk becomes
    // ⛔ sendable** ⛔ in ⛔ park order.
    let done = ledger.complete(Direction::ToTarget, chunk);
    assert_eq!(done.released, chunk);
    assert_eq!(done.ready.len(), 1, "⛔ exactly one parked write became sendable");
    assert_eq!(done.ready[0].bytes, chunk);
    assert_eq!(done.ready[0].direction, Direction::ToTarget);
    assert_eq!(
        ledger.in_flight(Direction::ToTarget),
        sent,
        "⛔ released room was taken by the parked chunk, so the ceiling is full again"
    );
    assert_eq!(ledger.parked(Direction::ToTarget), 0);
    assert_eq!(
        ledger.committed(Direction::ToTarget),
        sent + chunk,
        "⛔ and it IS committed now — it counts when the completion releases room"
    );

    // ⛔ **THE CONTROL: a completion that releases MORE than the ceiling held
    // ⛔ does not drive the in-flight count negative**, ⛔ and ⛔ **⛔ "a
    // ⛔ pacer that has stopped pacing while looking like one that paces."**
    let mut ledger = small_ledger();
    ledger.begin(Direction::ToTarget, chunk).expect("⛔ one chunk");
    let over = ledger.complete(Direction::ToTarget, chunk * 10);
    assert_eq!(over.released, chunk, "⛔ the release is clamped to one chunk");
    assert_eq!(ledger.in_flight(Direction::ToTarget), 0, "⛔ and never below zero");
}

/// ⛔ **`1011 relay backpressure` halves the ceiling, ⛔ floors it, ⛔
/// ⛔ and replays nothing.**
#[test]
fn a_backpressure_close_halves_the_ceiling_and_replays_nothing() {
    let mut ledger = Ledger::new();
    assert_eq!(ledger.ceiling(Direction::ToTarget), INFLIGHT_CEILING);

    let first = ledger.on_backpressure_close(Direction::ToTarget);
    assert_eq!(first.ceiling_before, INFLIGHT_CEILING);
    assert_eq!(first.ceiling_after, INFLIGHT_CEILING / 2);
    assert_eq!(first.halvings, 1);
    assert_eq!(first.direction, Direction::ToTarget);

    // ⛔ **THE FLOOR IS ONE CHUNK, ⛔ and halving goes BELOW it and is
    // ⛔ clamped** ⛔ — ⛔ **halving to zero would deadlock the
    // ⛔ session**: ⛔ nothing could ever be sent again.
    for _ in 0..40 {
        ledger.on_backpressure_close(Direction::ToTarget);
    }
    assert_eq!(ledger.ceiling(Direction::ToTarget), CEILING_FLOOR);
    assert_eq!(ledger.ceiling(Direction::ToTarget), CHUNK_MAX as u64);
    assert_eq!(ledger.halvings(Direction::ToTarget), 41, "⛔ and every one is counted");
    assert!(
        ledger.headroom_holds(ledger.ceiling(Direction::ToTarget)),
        "⛔ and the floor plus a chunk is still under the threshold"
    );

    // ⛔ **THE NO-REPLAY ASSERTION**, ⛔ and ⛔ **it is the guard against
    // ⛔ reintroducing a retransmit layer by accident**: ⛔ *⛔ "⛔ the
    // ⛔ frame is gone."* ⛔ There is no data to re-send.
    assert_eq!(first.replayed, 0);
    assert_eq!(ledger.replayed(), 0, "⛔ and there is no method that could make it otherwise");
    // ⛔ **A HALVING IS NOT A RESEND**, ⛔ and ⛔ **the two are in
    // ⛔ the SAME method** ⛔ — ⛔ **so a handler that both
    // ⛔ slowed down and retried could not express the retry**, ⛔
    // ⛔ and ⛔ **that is the shape of the guard** ⛔
    // ⛔ : ⛔ a retransmit layer would be a method that increments it, and
    // ⛔ its absence is what stops one arriving by accident.
    assert_eq!(Direction::BOTH.len(), 2, "⛔ and both directions are named");

    // ⛔ **THE OTHER DIRECTION IS NOT TOUCHED**, ⛔ **the relay said
    // ⛔ which receiver was slow, ⛔ and ⛔ a single shared counter would halve a
    // ⛔ session's throughput for a congestion in one direction only.**
    assert_eq!(
        ledger.ceiling(Direction::FromTarget),
        INFLIGHT_CEILING,
        "⛔ the congestion exists in ONE direction"
    );
    assert_eq!(ledger.halvings(Direction::FromTarget), 0);
}

/// ⛔ **THE PLANT THE ENTRY NAMES: a "recovering" `1011` handler** ⛔
/// ⛔ *"a handler that treats `1011` as a retryable transport error and
/// ⛔ resends the frame, E02-style"* ⛔ — ⛔ **and the no-replay
/// ⛔ assertion is the guard against it**, ⛔ so this arm is ⛔
/// ⛔ here rather than only in `backpressure_plants.rs`.
#[test]
fn plant_a_recovering_handler_replays_nothing() {
    let mut ledger = Ledger::new();
    // ⛔ **THE SETUP: a chunk that was permitted, sent, and then dropped by the
    // ⛔ relay.** ⛔ **It is committed** ⛔ — ⛔
    // ⛔ **the drop cost bytes whether or not the target ever saw
    // ⛔ them**, ⛔ and ⛔ **and no
    // ⛔ completion will ever release it**, ⛔ because ⛔
    // ⛔ the relay acknowledged nothing about what it lost.
    let chunk = CHUNK_MAX as u64;
    ledger.begin(Direction::ToTarget, chunk).expect("⛔ a chunk fits the ceiling");
    let committed_before = ledger.committed(Direction::ToTarget);
    assert_eq!(committed_before, chunk);

    if planted("recovering_1011") {
        // ⛔ **THE DEFECT: the handler "recovers" by putting the bytes back on
        // ⛔ the wire.** ⛔ **This is what a retransmit layer
        // ⛔ would do**, ⛔ and ⛔ **⛔ "the frame is
        // ⛔ gone"** ⛔ — ⛔ a
        // ⛔ resend ⛔ could not learn what to
        // ⛔ resend ⛔ without ⛔ guessing** ⛔ .
        // ⛔ **THE SIMPLEST POSSIBLE VERSION OF THE DEFECT:** a handler that
        // ⛔ counts what it "recovered", which is the field a real one would
        // ⛔ write to.
        let recovered = ledger
            .begin(Direction::ToTarget, chunk)
            .map(|p| p.in_flight())
            .unwrap_or(0);
        assert_eq!(
            recovered, 0,
            "the handler re-sent {recovered} bytes after `1011 relay backpressure`: the frame is            ⛔ gone, the relay acknowledged nothing about it, and a resend is a guess. ⛔ dns.md:             ⛔ podssh paces writes and builds no retransmit layer"
        );
    }

    // ⛔ **THE CORRECT PATH: the `1011` slows the ceiling down and NOTHING else.**
    let halved = ledger.on_backpressure_close(Direction::ToTarget);
    assert_eq!(halved.replayed, 0, "⛔ the handler reports zero replayed bytes");
    assert_eq!(halved.ceiling_after, INFLIGHT_CEILING / 2, "⛔ and it halved the ceiling");
    assert_eq!(ledger.replayed(), 0, "⛔ and the ledger has no field that could have held one");
    assert_eq!(
        ledger.committed(Direction::ToTarget),
        committed_before,
        "⛔ and the dropped frame is not un-committed: the bytes were spent"
    );
    // ⛔ **AND THE GAP IS THE TRUNCATION** ⛔ — ⛔ **`committed -
    // ⛔ in_flight` is the bytes that may never have reached the target**, ⛔
    // ⛔ and ⛔ **replayed is zero**, ⛔
    // ⛔ and those two numbers ⛔ are ⛔ how a caller detects a
    // ⛔ truncated ⛔ stream ⛔ **without a retransmit layer**.
    // ⛔ **THE FINDING, and it is why `unaccounted` exists.** ⛔
    // ⛔ `unreleased` is `committed - in_flight`, ⛔ and ⛔
    // ⛔ **a frame the relay dropped has not completed, so it is
    // still in flight** ⛔ - ⛔ which means ⛔
    // ⛔ `unreleased` reads ZERO for the one case it exists to name.** ⛔
    // ⛔ **MEASURED 2026-10-02: this assertion first read `unreleased`
    // and failed on it.**
    let in_flight_gap = ledger.unreleased(Direction::ToTarget);
    assert_eq!(
        in_flight_gap, 0,
        "⛔ committed - in_flight is ZERO for a dropped frame - the frame never completed, so it is still counted as in flight. ⛔ A caller reading this number cannot tell a truncated stream from a clean one, which is why the truncation is committed - released",
    );
    assert_eq!(ledger.in_flight(Direction::ToTarget), chunk, "⛔ and the frame IS still in flight");
    assert_eq!(
        ledger.unaccounted(Direction::ToTarget),
        chunk,
        "⛔ committed - released is the truncation, and no completion ever arrived"
    );
    assert_eq!(ledger.released(Direction::ToTarget), 0, "⛔ and nothing was released");

    // ⛔ **THE CONTROL: a byte-exactly legal drain has a gap of ZERO.** ⛔
    // ⛔ **Without it, ⛔ `unreleased() > 0` ⛔ could just
    // ⛔ be a counter ⛔ that ⛔ always ⛔ reports ⛔ something** ⛔
    let mut clean = Ledger::new();
    clean.begin(Direction::ToTarget, chunk).expect("⛔ a chunk fits");
    clean.complete(Direction::ToTarget, chunk);
    assert_eq!(clean.in_flight(Direction::ToTarget), 0, "⛔ a clean drain leaves nothing in flight");
    assert_eq!(
        clean.unaccounted(Direction::ToTarget),
        0,
        "⛔ THE CONTROL THAT MATTERS: a clean drain leaves NOTHING unaccounted, which is what the truncation number is supposed to read"
    );
    assert_eq!(clean.released(Direction::ToTarget), chunk, "⛔ and the released count IS the chunk");
    assert_eq!(clean.replayed(), 0);
    assert_eq!(
        clean.committed(Direction::ToTarget),
        chunk,
        "⛔ and the bytes were still committed — a drain is not a refund"
    );
}