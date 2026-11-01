//! A message of Cap'n Proto (`podssh_relay::quick::capnp`, T-403), as the
//! edge of a quick tunnel sends one: the frame's length agrees with the
//! reader, and a cut of the frame is no message; each pointer of each
//! struct, to a depth of 5, reads as each kind with no panic; a text or data
//! read lies within the frame; and a list, of structs or of texts, counts no
//! more elements than the budget, so that its count costs no memory
//! (`scripts/fuzz.sh` runs this under `-malloc_limit_mb=64`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_relay::quick::capnp::{frame_len, Message, Struct, CONTROL_BUDGET};

/// Each pointer of the first four of `s` as each kind, and each struct
/// reached, to `depth`; a few elements of each list. Each read that reaches
/// a struct spends the budget, so the walk ends.
fn walk(s: Struct<'_>, depth: u32, frame: usize) {
    if depth == 0 {
        return;
    }
    for i in 0..4u16 {
        let _ = (s.u8(usize::from(i)), s.u16(2 * usize::from(i)), s.u32(4 * usize::from(i)), s.bit(usize::from(i)));
        let _ = s.u64(8 * usize::from(i));
        if let Ok(Some(child)) = s.get_struct(i) {
            walk(child, depth - 1, frame);
        }
        if let Ok(Some(text)) = s.get_text(i) {
            assert!(text.len() < frame, "a text of {} bytes from {frame}", text.len());
        }
        if let Ok(Some(data)) = s.get_data(i) {
            assert!(data.len() <= frame, "data of {} bytes from {frame}", data.len());
        }
        let _ = s.get_capability(i);
        if let Ok(texts) = s.get_text_list(i) {
            assert!(texts.len() as u64 <= CONTROL_BUDGET, "{} texts", texts.len());
        }
        if let Ok(list) = s.get_struct_list(i) {
            assert!(list.len() as u64 <= CONTROL_BUDGET, "{} structs", list.len());
            assert_eq!(list.iter().len(), list.len());
            // The first two and the last: a skip jumps, and makes none of
            // the elements between.
            let last = list.len().saturating_sub(1).max(2);
            for element in list.iter().take(2).chain(list.iter().skip(last)) {
                walk(element, depth - 1, frame);
            }
            assert!(list.get(list.len()).is_none());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let read = Message::read_within(data, CONTROL_BUDGET);
    match frame_len(data) {
        Ok(Some(len)) if len <= data.len() => {
            assert!(read.is_ok(), "a frame of {len} bytes measured and not read");
            // A cut of the frame before its end is no message: a frame is
            // at least its table of 8 bytes, so the input has a first byte.
            let cut = len - 1 - usize::from(data[0]) % len;
            assert!(Message::read_within(&data[..cut], CONTROL_BUDGET).is_err(), "cut at {cut} of {len}");
        }
        _ => assert!(read.is_err(), "a frame read that was not measured whole"),
    }
    let Ok(message) = read else { return };
    let Ok(root) = message.root() else { return };
    walk(root, 5, data.len());
});
