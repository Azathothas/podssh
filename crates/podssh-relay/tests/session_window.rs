//! The window of a link of the pair's road (T-443): the bytes that a link
//! carries with no acknowledgement stay under what the relay holds for a
//! slow receiver, 1 MiB, while the replay buffer keeps its 4 MiB for the
//! links of other roads. Sans-IO: the link's room, and the records that a
//! resume sends again, before any socket.

use podssh_relay::session::record::MAX_DATA;
use podssh_relay::session::replay::{DEFAULT_CAPACITY, PAIR_WINDOW};
use podssh_relay::session::{Link, Record, Settings};

const MIB: usize = 1 << 20;
/// What the relay holds for a slow receiver before `1011 relay backpressure`.
const RELAY_BOUND: usize = MIB;

/// Each encoded record of `bytes`: a type byte, a 32-bit length, the body.
fn split(mut bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while bytes.len() >= 5 {
        let len = 5 + u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        let (record, rest) = bytes.split_at(len.min(bytes.len()));
        out.push(record);
        bytes = rest;
    }
    out
}

/// The session's bytes in a `DATA` record: its body less the offset.
fn carried(record: &[u8]) -> usize {
    record.len() - 13
}

/// The pair's road has a window under the relay's bound, and keeps the
/// buffer's capacity; another road has none.
#[test]
fn the_pairs_road_takes_a_window_under_the_relays_bound() {
    let pair = Settings::default().on_the_pair();
    let window = pair.window.expect("a window on the pair's road");
    assert_eq!(window, PAIR_WINDOW);
    // The records' headers and the relay's frames fit the rest.
    assert!(window + 256 * 1024 <= RELAY_BOUND, "{window} bytes in flight leave too little under 1 MiB");
    assert_eq!(pair.replay_capacity, DEFAULT_CAPACITY, "the buffer keeps its capacity");
    assert_eq!(pair.off_the_pair().window, None);
    assert_eq!(Settings::default().window, None, "the library's default is the buffer alone");
}

/// The window bounds what a link sends with no acknowledgement, below the
/// buffer's room; an acknowledgement frees as much of it.
#[test]
fn the_window_bounds_the_bytes_in_flight_below_the_buffer() {
    let window = Some(PAIR_WINDOW);
    let mut link = Link::new(0, 0).with_replay(DEFAULT_CAPACITY);
    assert_eq!(link.room_within(window), PAIR_WINDOW);
    assert_eq!(link.room_within(None), DEFAULT_CAPACITY);
    let mut out = Vec::new();
    link.send(&vec![1u8; PAIR_WINDOW - 1000], &mut out).unwrap();
    assert_eq!(link.room_within(window), 1000);
    assert_eq!(link.room_within(None), DEFAULT_CAPACITY - PAIR_WINDOW + 1000);
    link.send(&[2u8; 1000], &mut out).unwrap();
    assert_eq!(link.room_within(window), 0, "a whole window in flight: the writer waits");
    assert_eq!(link.room_within(None), DEFAULT_CAPACITY - PAIR_WINDOW, "the buffer alone would send on");
    link.on_record(Record::Ack { offset: 64 * 1024 }).unwrap();
    assert_eq!(link.room_within(window), 64 * 1024, "an ACK frees its bytes of the window");
    // A window of nothing still lets a byte go, so a link always moves.
    assert_eq!(Link::new(0, 0).with_replay(DEFAULT_CAPACITY).room_within(Some(0)), 1);
}

/// With no replay buffer the peer acknowledges nothing, and a window would
/// stop the link for good: it holds nothing back.
#[test]
fn a_link_with_no_buffer_is_not_held_by_the_window() {
    let mut link = Link::new(0, 0);
    let mut out = Vec::new();
    link.send(&vec![3u8; 2 * PAIR_WINDOW], &mut out).unwrap();
    assert_eq!(link.room_within(Some(PAIR_WINDOW)), PAIR_WINDOW);
}

/// The records that a resume sends again wait for the window too: a buffer
/// filled on a road with no window holds more than a link of the pair's
/// road may carry at once. The first always fits, and another record than
/// `DATA` carries none of the session's bytes.
#[test]
fn bytes_sent_again_wait_for_the_window() {
    let window = Some(PAIR_WINDOW);
    let mut link = Link::new(0, 0).with_replay(DEFAULT_CAPACITY);
    let mut out = Vec::new();
    // Sent on a road with no window, then the link was lost.
    link.send(&vec![4u8; 2 * MIB], &mut out).unwrap();
    let mut again = Vec::new();
    assert_eq!(link.resume(0, &mut again).unwrap(), 2 * MIB as u64);
    let records = split(&again);
    assert!(records.iter().all(|r| carried(r) <= MAX_DATA));
    let fit = records.iter().take_while(|r| link.again_fits(r, window)).count();
    let in_flight: usize = records[..fit].iter().map(|r| r.len() - 13).sum();
    assert!(in_flight <= PAIR_WINDOW, "{in_flight} bytes sent again at once, past the window");
    assert!(in_flight + carried(records[fit]) > PAIR_WINDOW, "each record that fits went: {fit} of them");
    assert!(link.again_fits(records[fit], None), "with no window each record goes at once");
    // The peer's ACK of the first records frees the window for the next.
    link.on_record(Record::Ack { offset: in_flight as u64 }).unwrap();
    assert!(link.again_fits(records[fit], window));
    // With nothing in flight before it, a record fits any window.
    assert!(link.again_fits(records[fit], Some(1)));
    let ack = Record::Ack { offset: 0 }.to_bytes().unwrap();
    assert!(link.again_fits(&ack, Some(1)), "an ACK carries none of the session's bytes");
}
