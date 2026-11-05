//! A drain's end (T-670): its first clean round trip, timed from an adjust
//! that went out once the drain held its channel, and not while another
//! channel that carries bulk still has its bytes in flight, which would
//! queue in front of the timed one.

use std::time::{Duration, Instant};

use super::{target::FLOOR, Keys, Pace, DRAIN_MAX};

const KIB: u64 = 1024;
const A: u32 = 2;
const B: u32 = 3;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Two channels that carry bulk on `pace`, each opened with 512 KiB of
/// window, of which 64 KiB came; then a drain from `t0`.
fn two_downloads(mut pace: Pace, t0: Instant) -> Pace {
    for channel in [A, B] {
        let chan = pace.chan(channel);
        let _ = chan.received(64 * KIB, t0);
        chan.busy = true;
    }
    pace.start_drain(t0);
    pace
}

/// An adjust of `channel` at `at` with a held window, and the message after
/// it at `then` that carries the first byte that only it allowed: the next
/// past what the window before it still allowed.
fn round_trip(pace: &mut Pace, channel: u32, at: Instant, then: Instant) {
    assert_eq!(pace.target(channel, at), FLOOR, "a drain holds each window");
    let left = pace.chan(channel).outstanding();
    pace.adjusted(channel, at);
    pace.received(channel, 1024, at);
    pace.received(channel, usize::try_from(left).expect("a few KiB"), then);
}

/// A rate of 10 MB/s was measured, at which the 896 KiB in flight would
/// come in 92 ms: no round trip came, so the drain holds, to its bound.
#[test]
fn a_drain_lasts_until_a_clean_round_trip_not_a_guess() {
    static KEYS: Keys = Keys::new();
    let t0 = Instant::now();
    let mut pace = Pace::default().with_keys(&KEYS);
    assert!(!pace.path.count(t0, 0));
    assert!(!pace.path.count(t0 + ms(100), 1_000_000));
    // The next message, apart from the last, ends the interval at it.
    assert!(pace.path.count(t0 + ms(150), 0));
    let at = t0 + ms(200);
    let pace = two_downloads(pace, at);
    assert!(pace.draining(at + ms(5_000)), "a guess from the rate ended it at 292 ms");
    assert!(!pace.draining(at + DRAIN_MAX));
}

/// Each step within 100 ms of the first message that the path counts, so
/// that no interval of the rate ends and each channel stays one that
/// carries bulk.
#[test]
fn a_drain_waits_for_each_channel_that_carries_bulk() {
    static KEYS: Keys = Keys::new();
    let t0 = Instant::now();
    let mut pace = two_downloads(Pace::default().with_keys(&KEYS), t0);
    assert!(!pace.others_drained(A), "B has 448 KiB in flight");

    // A's bytes came but for a held window: its round trip crosses B's.
    let _ = pace.chan(A).received(440 * KIB, t0 + ms(5));
    round_trip(&mut pace, A, t0 + ms(10), t0 + ms(60));
    assert!(pace.draining(t0 + ms(60)), "B's bytes were in front of A's");

    // B's bytes came too, but for a held window: A's next one is clean.
    let _ = pace.chan(B).received(448 * KIB - u64::from(FLOOR), t0 + ms(65));
    assert!(pace.others_drained(A));
    round_trip(&mut pace, A, t0 + ms(70), t0 + ms(95));
    assert!(!pace.draining(t0 + ms(95)), "a clean round trip ends the drain");
}

/// A channel that carries no bulk has room in its window, not bytes.
#[test]
fn a_channel_that_carries_no_bulk_holds_no_drain() {
    static KEYS: Keys = Keys::new();
    let t0 = Instant::now();
    let mut pace = two_downloads(Pace::default().with_keys(&KEYS), t0);
    pace.chan(B).busy = false;
    assert!(pace.others_drained(A));
    let _ = pace.chan(A).received(440 * KIB, t0 + ms(5));
    round_trip(&mut pace, A, t0 + ms(10), t0 + ms(60));
    assert!(!pace.draining(t0 + ms(60)));
}
