//! What a connection measures of its path (T-661): the windowed filters,
//! the rate's samples, and a round trip from a window adjust.

use std::time::{Duration, Instant};

use super::*;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A sample's round trip and the bytes behind its byte.
fn rtt(sample: Option<Sample>) -> Option<(Duration, u64)> {
    sample.map(|s| (s.took, s.behind))
}

#[test]
fn the_largest_rate_of_the_last_spans_is_kept_then_forgotten() {
    let t0 = Instant::now();
    let mut rate = Best::new(RATE_SPAN, true);
    rate.add(t0, 100u64);
    rate.add(t0 + ms(1000), 300);
    rate.add(t0 + ms(2000), 200);
    assert_eq!(rate.best(), Some(300));
    // A new span keeps the last one's best beside its own.
    rate.add(t0 + RATE_SPAN + ms(1), 50);
    assert_eq!(rate.best(), Some(300));
    // Two spans on, the old best is gone.
    rate.add(t0 + RATE_SPAN * 2 + ms(2), 60);
    assert_eq!(rate.best(), Some(60));
    // With no sample for two spans, a rate is no longer fresh.
    let last = t0 + RATE_SPAN * 2 + ms(2);
    assert_eq!(rate.fresh(last + RATE_SPAN), Some(60));
    assert_eq!(rate.fresh(last + RATE_SPAN * 2), None);
}

#[test]
fn the_least_round_trip_is_kept_and_stands_with_no_new_sample() {
    let t0 = Instant::now();
    let mut rtt = Best::new(RTT_SPAN, false);
    assert_eq!(rtt.best(), None);
    rtt.add(t0, ms(80));
    rtt.add(t0 + ms(10), ms(60));
    rtt.add(t0 + ms(20), ms(90));
    assert_eq!(rtt.best(), Some(ms(60)));
    // With no sample since, the last least round trip stands.
    assert_eq!(rtt.best(), Some(ms(60)));
    // A path whose delay grew: its new least, after two spans.
    rtt.add(t0 + RTT_SPAN + ms(30), ms(150));
    rtt.add(t0 + RTT_SPAN * 2 + ms(40), ms(140));
    assert_eq!(rtt.best(), Some(ms(140)));
}

#[test]
fn a_rate_is_the_bytes_of_an_interval_over_its_length() {
    let t0 = Instant::now();
    let mut path = Path::default();
    assert_eq!(path.rate(t0), None);
    // The first message opens the interval; its bytes came at its start.
    assert!(!path.count(t0, 50_000));
    assert!(!path.count(t0 + ms(50), 50_000));
    assert!(!path.count(t0 + ms(100), 50_000));
    // The next message, apart from the one before, ends the interval at
    // that one, and opens the next with its bytes: 100 kB in 100 ms.
    assert!(path.count(t0 + ms(150), 50_000));
    assert_eq!(path.rate(t0 + ms(150)), Some(1_000_000));
}

#[test]
fn an_interval_lasts_a_round_trip_where_that_is_longer() {
    let t0 = Instant::now();
    let mut path = Path::default();
    assert_eq!(path.interval(), INTERVAL);
    path.round_trip(t0, ms(300));
    assert_eq!(path.interval(), ms(300));
    assert!(!path.count(t0, 1));
    assert!(!path.count(t0 + ms(200), 30_000));
    assert!(!path.count(t0 + ms(300), 30_000));
    assert!(path.count(t0 + ms(400), 30_000));
    assert_eq!(path.rate(t0 + ms(400)), Some(200_000));
}

#[test]
fn a_channel_is_busy_for_an_interval_of_bulk() {
    let t0 = Instant::now();
    let mut chan = Chan::new(512 * 1024);
    assert!(!chan.close_interval(), "no byte yet");
    let _ = chan.received(BUSY - 1, t0);
    assert!(!chan.close_interval(), "a terminal's output");
    let _ = chan.received(BUSY / 2, t0 + ms(10));
    let _ = chan.received(BUSY / 2, t0 + ms(20));
    assert!(chan.close_interval(), "bulk");
    assert!(chan.busy);
    assert!(!chan.close_interval(), "each interval counts afresh");
}

#[test]
fn sharing_is_one_channel_at_least() {
    let mut path = Path::default();
    assert_eq!(path.sharing(), 1);
    path.set_sharing(0);
    assert_eq!(path.sharing(), 1);
    path.set_sharing(3);
    assert_eq!(path.sharing(), 3);
}

/// A server that used its whole window waits for the adjust: the first byte
/// past the old window comes a round trip after it.
#[test]
fn a_round_trip_is_an_adjust_to_the_first_byte_that_only_it_allowed() {
    let t0 = Instant::now();
    let mut chan = Chan::new(64 * 1024);
    chan.target = 16 * 1024;
    // 40 KiB, then 24 KiB: the window is spent, and russh adjusts it to the
    // smaller target of a key that waits.
    assert_eq!(chan.received(40 * 1024, t0), None);
    chan.adjusted = Some(t0 + ms(5));
    assert_eq!(chan.received(24 * 1024, t0 + ms(5)), None);
    // The next bytes were sent once the adjust arrived.
    assert_eq!(rtt(chan.received(8 * 1024, t0 + ms(85))), Some((ms(80), 8 * 1024)));
    // Each probe once.
    assert_eq!(chan.received(8 * 1024, t0 + ms(86)), None);
    assert_eq!(chan.outstanding(), 0);
}

/// An adjust that went out while the server still had window: the bytes
/// before the old window's end are no sample; the first one past it is, a
/// round trip or more after the adjust.
#[test]
fn bytes_that_the_old_window_allowed_are_no_sample() {
    let t0 = Instant::now();
    let mut chan = Chan::new(64 * 1024);
    chan.target = 128 * 1024;
    chan.adjusted = Some(t0);
    // After 32 KiB, russh adjusts to a larger target: 32 KiB of the old
    // window are left.
    assert_eq!(chan.received(32 * 1024, t0), None);
    assert_eq!(chan.received(16 * 1024, t0 + ms(20)), None);
    assert_eq!(chan.received(16 * 1024, t0 + ms(40)), None);
    assert_eq!(rtt(chan.received(16 * 1024, t0 + ms(90))), Some((ms(90), 16 * 1024)));
}

/// Each adjust is timed, in the order of its bytes, while the probes of
/// earlier adjusts still wait; a message that carries a probe's byte past
/// it (a later adjust let the server send on) still times it.
#[test]
fn each_adjust_is_timed_in_the_order_of_its_bytes() {
    let t0 = Instant::now();
    const K: u64 = 1024;
    let mut chan = Chan::new(64 * 1024);
    chan.target = 64 * 1024;
    // 16 KiB left of 64: an adjust to 64 KiB past 48, its probe at 64 KiB.
    chan.adjusted = Some(t0);
    assert_eq!(chan.received(48 * K, t0), None);
    // The target grows to 256 KiB: an adjust, its probe at 112 KiB.
    chan.target = 256 * 1024;
    chan.adjusted = Some(t0 + ms(10));
    assert_eq!(chan.received(8 * K, t0 + ms(10)), None);
    assert_eq!(chan.received(8 * K, t0 + ms(60)), None);
    assert_eq!(rtt(chan.received(8 * K, t0 + ms(80))), Some((ms(80), 8 * K)));
    assert_eq!(chan.outstanding(), 240 * K);
    // 120 KiB more: they carry the byte at 112 KiB, and leave less than half
    // of 256, so russh adjusts again, its probe at 312 KiB.
    chan.adjusted = Some(t0 + ms(90));
    assert_eq!(rtt(chan.received(120 * K, t0 + ms(90))), Some((ms(80), 192 * K - 112 * K)));
    assert_eq!(chan.received(120 * K, t0 + ms(120)), None);
    assert_eq!(rtt(chan.received(8 * K, t0 + ms(160))), Some((ms(70), 8 * K)));
}

/// Messages of 8 KiB on a path of about 125 kB/s, one each 66 ms, at these
/// times: what each `count` answered, and the rate after the last.
fn flow(times: &[u64]) -> (Vec<bool>, Option<u64>) {
    let t0 = Instant::now();
    let mut path = Path::default();
    let closed = times.iter().map(|&t| path.count(t0 + ms(t), 8_192)).collect();
    (closed, path.rate(t0 + ms(*times.last().unwrap_or(&0))))
}

/// A loss holds the message of 264 ms and the one behind it until 364 ms,
/// when both come at once (T-673): the burst joins the interval of the
/// stall, which reads the path's rate. Ended at the burst's first message,
/// the stall read 70 kB/s and the burst 199 kB/s, kept as the best.
#[test]
fn a_burst_after_a_stall_joins_the_interval_before_it() {
    let (closed, rate) = flow(&[0, 66, 132, 198, 364, 364, 396, 462, 528]);
    assert_eq!(closed, [false, false, false, true, false, false, false, true, false]);
    // 16 KiB in 132 ms, then 32 KiB in 264 ms.
    assert_eq!(rate, Some(124_121));
}

/// The first message and two that a loss held came at once: all three at
/// the interval's start, so none is in its rate.
#[test]
fn the_messages_that_come_with_the_first_open_the_interval_too() {
    let (closed, rate) = flow(&[0, 0, 0, 66, 132, 198]);
    assert_eq!(closed, [false, false, false, false, false, true]);
    assert_eq!(rate, Some(124_121), "counted, the two read 248 kB/s");
}

/// A burst at 233 ms, then a message 31 ms after it, sooner than the path
/// carries one: it was on its way during the stall, so it opens the next
/// interval with the burst, by the rate that the burst's interval read.
/// Counted in the next interval, it read 151 kB/s.
#[test]
fn a_message_on_its_way_during_a_stall_opens_the_next_interval() {
    let (closed, rate) = flow(&[0, 66, 233, 233, 264, 330, 396, 462]);
    assert_eq!(closed, [false, false, false, false, true, false, false, true]);
    // 24 KiB in 233 ms, then 16 KiB in 132 ms.
    assert_eq!(rate, Some(124_121));
}

/// On a fast path each message comes with the one before: a burst longer
/// than an interval ends it anyway, each interval, at the path's rate.
#[test]
fn a_burst_longer_than_an_interval_ends_it_anyway() {
    let t0 = Instant::now();
    let mut path = Path::default();
    let mut closed = 0;
    for step in 0..3_000u64 {
        // 10 kB each 100 µs: 100 MB/s.
        closed += u32::from(path.count(t0 + Duration::from_micros(step * 100), 10_000));
    }
    assert!(closed >= 2, "{closed} intervals ended");
    let rate = path.rate(t0 + ms(300)).expect("a rate");
    assert!((99_000_000..=101_000_000).contains(&rate), "{rate}");
}
