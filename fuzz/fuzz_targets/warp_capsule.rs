//! connect-ip's capsules in WARP's tunnel (`podssh_warp::capsule`, T-403),
//! as the edge sends them over HTTP/2: the same bytes in one piece or cut
//! anywhere in two give the same capsules, and the same refusal; no capsule
//! is longer than the limit or than its input; a packet, written again as a
//! capsule, reads back to itself; and a variable-length integer, written
//! again in the fewest bytes, reads back to its value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_warp::capsule::{datagram, put_varint, read_varint, Capsule, Reader, DATAGRAM, MAX_CAPSULE, MAX_VARINT};

/// The capsules of `pieces`, pushed in turn, and how they ended: the bytes
/// that wait for the rest of a capsule, or the refusal. Where the refusal
/// came, the bytes not pushed yet differ with the cut, so they are not given.
fn run(pieces: &[&[u8]]) -> (Vec<Capsule>, Result<usize, String>) {
    let mut reader = Reader::default();
    let mut capsules = Vec::new();
    for piece in pieces {
        reader.push(piece);
        loop {
            match reader.next_capsule() {
                Ok(Some(capsule)) => capsules.push(capsule),
                Ok(None) => break,
                Err(why) => return (capsules, Err(why)),
            }
        }
    }
    let waiting = reader.waiting();
    (capsules, Ok(waiting))
}

fuzz_target!(|data: &[u8]| {
    let Some((&cut, input)) = data.split_first() else { return };
    let whole = run(&[input]);
    let (a, b) = input.split_at(usize::from(cut).min(input.len()));
    assert_eq!(run(&[a, b]), whole, "cut at {}", a.len());
    for capsule in &whole.0 {
        // A type and a length of a byte each at least.
        assert!(capsule.payload.len() as u64 <= MAX_CAPSULE && capsule.payload.len() + 2 <= input.len());
        if capsule.kind == DATAGRAM {
            let mut reader = Reader::default();
            reader.push(&datagram(&capsule.payload));
            assert_eq!(reader.next_packet(), Ok(Some(capsule.payload.clone())));
            assert_eq!(reader.waiting(), 0);
        }
    }
    if let Some((value, len)) = read_varint(input) {
        assert!(value <= MAX_VARINT && (1..=8).contains(&len) && len <= input.len(), "{value} in {len}");
        let mut out = Vec::new();
        put_varint(&mut out, value);
        assert!(out.len() <= len, "{value}: {} bytes, read from {len}", out.len());
        assert_eq!(read_varint(&out), Some((value, out.len())));
    }
});
