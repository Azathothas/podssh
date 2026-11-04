//! The target of a channel's window (T-661), from its inputs.

use std::time::Duration;

use super::*;

const KIB: u32 = 1024;
const MIB: u32 = 1024 * KIB;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// 10 Mbit/s with 60 ms of least round trip, one channel, the road's cap of
/// today.
fn path(typing: bool) -> Inputs {
    Inputs {
        typing,
        draining: false,
        carrier: false,
        rate: Some(1_250_000),
        rtt: Some(ms(60)),
        sharing: 1,
        cap: crate::run::WINDOW,
    }
}

#[test]
fn while_a_key_waits_a_window_is_a_round_trip_and_40_ms_of_the_rate() {
    // 1.25 MB/s for 100 ms, three quarters in flight: 166666 bytes.
    let held = of(&path(true));
    assert_eq!(held, 166_666);
    // What waits in front of a key, with three quarters of it in flight,
    // beyond the path's own: 40 ms of the rate, not 512 KiB's 420 ms.
    let queued = f64::from(held) * 0.75 / 1_250_000.0 - 0.060;
    assert!((queued - 0.040).abs() < 0.001, "{queued}");
}

#[test]
fn idle_a_window_is_a_round_trip_and_200_ms_of_the_rate() {
    // 1.25 MB/s for 260 ms, three quarters in flight: 433333 bytes.
    assert_eq!(of(&path(false)), 433_333);
    assert!(of(&path(false)) > of(&path(true)));
}

#[test]
fn a_window_is_never_under_16_kib_nor_over_the_cap() {
    let slow = Inputs { rate: Some(1_000), ..path(true) };
    assert_eq!(of(&slow), FLOOR);
    let fast = Inputs { rate: Some(1_000_000_000), ..path(false) };
    assert_eq!(of(&fast), crate::run::WINDOW);
    let small_cap = Inputs { cap: 64 * KIB, ..fast };
    assert_eq!(of(&small_cap), 64 * KIB);
    // A cap under the floor is no cap: a channel always moves.
    let tiny_cap = Inputs { cap: KIB, ..fast };
    assert_eq!(of(&tiny_cap), FLOOR);
}

#[test]
fn unmeasured_a_window_starts_as_before_and_is_the_floor_while_a_key_waits() {
    let unmeasured = Inputs { rate: None, rtt: None, ..path(false) };
    assert_eq!(of(&unmeasured), START);
    assert_eq!(START, 512 * KIB, "the window that podssh gave each channel before T-661");
    assert_eq!(of(&Inputs { typing: true, ..unmeasured }), FLOOR);
    // A rate with no round trip, or the reverse, is no measure.
    assert_eq!(of(&Inputs { rtt: None, ..path(false) }), START);
    assert_eq!(of(&Inputs { rate: None, ..path(true) }), FLOOR);
    // Under a smaller cap, the start is the cap.
    assert_eq!(of(&Inputs { cap: 128 * KIB, ..unmeasured }), 128 * KIB);
}

#[test]
fn channels_that_share_the_path_share_its_window() {
    let one = of(&path(true));
    let two = of(&Inputs { sharing: 2, ..path(true) });
    assert_eq!(two, one / 2);
    // 0 channels reads as one.
    assert_eq!(of(&Inputs { sharing: 0, ..path(true) }), one);
}

#[test]
fn a_carrier_of_a_hop_gets_the_cap_whatever_is_typed() {
    for typing in [true, false] {
        let carrier = Inputs { carrier: true, ..path(typing) };
        assert_eq!(of(&carrier), crate::run::WINDOW);
        assert_eq!(of(&Inputs { rate: None, ..carrier }), crate::run::WINDOW);
    }
    assert_eq!(of(&Inputs { carrier: true, cap: 16 * MIB, ..path(true) }), 16 * MIB);
}

/// A window that limits the rate grows from round to round, idle and while
/// a key waits, on a long path too: the rate that it measures gives a
/// larger target than the window that limited it.
#[test]
fn a_window_that_limits_the_rate_grows_from_round_to_round() {
    for (typing, rtt) in [(true, 300), (false, 300), (true, 20), (false, 20)] {
        let mut window = FLOOR;
        for _ in 0..8 {
            // In flight: three quarters of the window, each round trip.
            let rate = (f64::from(window) * 0.75 / ms(rtt).as_secs_f64()) as u64;
            let next = of(&Inputs { rate: Some(rate), rtt: Some(ms(rtt)), ..path(typing) });
            assert!(next > window || next == crate::run::WINDOW, "typing {typing}, {rtt} ms: {window} to {next}");
            window = next;
        }
    }
}

#[test]
fn while_the_windows_drain_each_is_the_floor_but_a_carriers() {
    for typing in [true, false] {
        assert_eq!(of(&Inputs { draining: true, ..path(typing) }), FLOOR);
        assert_eq!(of(&Inputs { draining: true, rate: None, ..path(typing) }), FLOOR);
        assert_eq!(of(&Inputs { draining: true, carrier: true, ..path(typing) }), crate::run::WINDOW);
    }
}

/// On a long path half a target holds the path's bytes of a round trip, so
/// the path never runs dry between adjusts: twice the bytes of a round trip,
/// more than the margin's 40 ms there.
#[test]
fn on_a_long_path_half_a_window_still_fills_the_path() {
    let long = Inputs { rtt: Some(ms(200)), ..path(true) };
    // 1.25 MB/s for 200 ms, twice; the margin's would be 400000.
    assert_eq!(of(&long), 500_000);
    // On a short path, the margin's is the larger.
    assert!(of(&path(true)) > (1_250_000.0 * 0.060 * 2.0) as u32);
}

/// T-662: where nobody types, a window grows past today's 512 KiB to what
/// the path asks, up to its road's cap.
#[test]
fn where_nobody_types_a_window_grows_to_the_path_up_to_the_roads_cap() {
    use crate::pace::Road;
    // 10 MB/s and 500 ms: twice the round trip's bytes, 10 MB, under 16 MiB.
    let far = Inputs { rate: Some(10_000_000), rtt: Some(ms(500)), ..path(false) };
    assert_eq!(of(&Inputs { cap: Road::Direct.cap(), ..far }), 10_000_000);
    // 100 MB/s and 200 ms: past each cap, so each road's.
    let fat = Inputs { rate: Some(100_000_000), rtt: Some(ms(200)), ..path(false) };
    for road in [Road::Direct, Road::Iroh, Road::Role, Road::Relay, Road::Pair, Road::Other] {
        assert_eq!(of(&Inputs { cap: road.cap(), ..fat }), road.cap(), "{road:?}");
    }
    // While a key waits, a short path's window is the same on each road.
    assert_eq!(of(&Inputs { cap: Road::Direct.cap(), ..path(true) }), of(&path(true)));
}

/// The channels that carry bulk share the cap, each with today's 512 KiB at
/// least; a carrier of a hop has the whole of it.
#[test]
fn the_channels_that_carry_bulk_share_the_roads_cap() {
    use crate::pace::Road;
    let fat = Inputs { rate: Some(1_000_000_000), rtt: Some(ms(200)), cap: Road::Direct.cap(), ..path(false) };
    assert_eq!(of(&Inputs { sharing: 4, ..fat }), 4 * MIB);
    assert_eq!(of(&Inputs { sharing: 64, ..fat }), 512 * KIB, "never under the window of before");
    assert_eq!(of(&Inputs { sharing: 2, cap: Road::Relay.cap(), ..fat }), 768 * KIB);
    assert_eq!(of(&Inputs { sharing: 4, carrier: true, ..fat }), 16 * MIB);
}
