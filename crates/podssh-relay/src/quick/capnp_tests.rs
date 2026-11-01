//! The builder and the reader against bytes of the reference encoder,
//! `capnp encode` of Cap'n Proto 1.0, with cloudflared's schema at 2026.10.6
//! (`scripts/quick-fixtures.sh` makes them, from the text beside each).

use super::*;
use crate::quick::register::{read_results, Registered, Registration, FEATURES, REGISTER_PARAMS};

const PARAMS: &[u8] = include_bytes!("../../tests/fixtures/quick/register-params.bin");
const DETAILS: &[u8] = include_bytes!("../../tests/fixtures/quick/register-results-details.bin");
const REFUSED: &[u8] = include_bytes!("../../tests/fixtures/quick/register-results-error.bin");

/// The values of `register-params.txt`.
pub(crate) fn registration() -> Registration<'static> {
    const SECRET: [u8; 32] = {
        let mut s = [0u8; 32];
        let mut k = 0;
        while k < 32 {
            s[k] = k as u8;
            k += 1;
        }
        s
    };
    Registration {
        account_tag: "0123456789abcdef0123456789abcdef",
        secret: &SECRET,
        tunnel_id: [0x8e, 0x9d, 0x2f, 0x0c, 0x4b, 0x1a, 0x4f, 0x6e, 0x9c, 0x3d, 0x5a, 0x7b, 0x2e, 0x1f, 0x0d, 0x4c],
        conn_index: 0,
        client_id: [0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00],
        features: FEATURES,
        version: "podssh 1.0.0-beta.2",
        arch: "linux_amd64",
    }
}

#[test]
fn the_builder_writes_the_reference_encoder_s_bytes_for_a_registration() {
    let (mut b, params) = Builder::new(REGISTER_PARAMS.0, REGISTER_PARAMS.1);
    registration().write(&mut b, params);
    assert_eq!(b.frame(), PARAMS);
}

#[test]
fn the_reader_reads_each_field_of_the_reference_registration() {
    let message = Message::read(PARAMS).unwrap();
    let params = message.root().unwrap();
    let auth = params.get_struct(0).unwrap().unwrap();
    assert_eq!(auth.get_text(0).unwrap(), Some("0123456789abcdef0123456789abcdef"));
    assert_eq!(auth.get_data(1).unwrap().unwrap(), registration().secret);
    assert_eq!(params.get_data(1).unwrap().unwrap(), registration().tunnel_id);
    assert_eq!(params.u8(0), 0);
    let options = params.get_struct(2).unwrap().unwrap();
    assert!(!options.bit(0));
    assert_eq!((options.u8(1), options.u8(2)), (0, 0));
    assert_eq!(options.get_data(1).unwrap(), None, "no originLocalIp");
    let client = options.get_struct(0).unwrap().unwrap();
    assert_eq!(client.get_data(0).unwrap().unwrap(), registration().client_id);
    assert_eq!(client.get_text_list(1).unwrap(), FEATURES);
    assert_eq!(client.get_text(2).unwrap(), Some("podssh 1.0.0-beta.2"));
    assert_eq!(client.get_text(3).unwrap(), Some("linux_amd64"));
    // A field past the end of a section reads as its default.
    assert_eq!((params.u64(8), params.get_struct(3).unwrap().is_none()), (0, true));
}

#[test]
fn a_registration_s_answer_reads_as_details_or_a_refusal() {
    let message = Message::read(DETAILS).unwrap();
    let details = read_results(message.root().unwrap()).unwrap();
    let uuid = vec![0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0];
    assert_eq!(details, Registered::Details { uuid, location: "msp01".into(), remotely_managed: false });
    let message = Message::read(REFUSED).unwrap();
    let refused = read_results(message.root().unwrap()).unwrap();
    let after = std::time::Duration::from_secs(5);
    assert_eq!(refused, Registered::Refused { cause: "the tunnel is not known".into(), retry: true, after });
}

/// The edge's texts of a refusal and of a place, with ESC, BEL and a CR,
/// read as one line with none of them (T-401).
#[test]
fn the_edge_s_cause_and_place_read_with_no_control_character() {
    let answer = |kind: u16, fill: &dyn Fn(&mut Builder, At)| {
        let (mut b, results) = Builder::new(0, 1);
        let response = b.init_struct(results, 0, 1, 1);
        b.set_u16(response, 0, kind);
        fill(&mut b, response);
        b.frame()
    };
    let refused = answer(0, &|b, response| {
        let error = b.init_struct(response, 0, 2, 1);
        b.set_text(error, 0, "no\x1b[31m such\x07 tunnel\r\nhere");
        b.set_u64(error, 0, 5_000_000_000);
        b.set_bit(error, 64, true);
    });
    let message = Message::read(&refused).unwrap();
    let after = std::time::Duration::from_secs(5);
    assert_eq!(
        read_results(message.root().unwrap()).unwrap(),
        Registered::Refused { cause: "no[31m such tunnel here".into(), retry: true, after }
    );
    let details = answer(1, &|b, response| {
        let details = b.init_struct(response, 0, 1, 2);
        b.set_data(details, 0, &[1u8; 16]);
        b.set_text(details, 1, "msp01\x1b]0;title\x07");
    });
    let message = Message::read(&details).unwrap();
    let Registered::Details { location, .. } = read_results(message.root().unwrap()).unwrap() else {
        panic!("not details")
    };
    assert_eq!(location, "msp01]0;title");
}

#[test]
fn a_frame_is_measured_from_its_table_before_it_is_whole() {
    assert_eq!(frame_len(&PARAMS[..3]), Ok(None), "no table yet");
    assert_eq!(frame_len(&PARAMS[..8]), Ok(Some(PARAMS.len())));
    assert!(Message::read(&PARAMS[..PARAMS.len() - 8]).is_err(), "a frame cut short");
    // Three segments: a table of 16 bytes, padded to a word.
    let mut three = Vec::new();
    for word in [2u32, 1, 0, 2] {
        three.extend_from_slice(&word.to_le_bytes());
    }
    assert_eq!(frame_len(&three), Ok(Some(16 + 3 * 8)));
    assert_eq!(frame_len(&[0xff, 0xff, 0, 0]), Err(Malformed("too many segments")));
}

/// A message of the segments `segs`, framed.
pub(crate) fn framed(segs: &[&[u64]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(segs.len() as u32 - 1).to_le_bytes());
    for seg in segs {
        out.extend_from_slice(&(seg.len() as u32).to_le_bytes());
    }
    if out.len() % 8 != 0 {
        out.extend_from_slice(&[0; 4]);
    }
    for seg in segs {
        for word in *seg {
            out.extend_from_slice(&word.to_le_bytes());
        }
    }
    out
}

#[test]
fn the_reader_follows_single_and_double_far_pointers() {
    // A struct of one data word, 7, in segment 1, its landing pad before it.
    let struct_ptr = |offset: u64| (offset << 2) | (1 << 32);
    let single = framed(&[&[2 | (1 << 32)], &[struct_ptr(0), 7]]);
    let message = Message::read(&single).unwrap();
    assert_eq!(message.root().unwrap().u64(0), 7);
    // Double: the pad in segment 1 is a far pointer to the struct in
    // segment 2, then the tag that tells its size.
    let double = framed(&[&[2 | 4 | (1 << 32)], &[2 | (2 << 32), struct_ptr(0)], &[9]]);
    let message = Message::read(&double).unwrap();
    assert_eq!(message.root().unwrap().u64(0), 9);
}

#[test]
fn a_message_that_points_out_of_its_segment_or_in_a_loop_is_malformed() {
    // A struct pointer past the end of the segment.
    let out = framed(&[&[(5 << 2) | (1 << 32)]]);
    assert!(Message::read(&out).unwrap().root().is_err());
    // A text with no NUL.
    // Three bytes, "abc", with no NUL at their end.
    let text = framed(&[&[1 << 48, 1 | (2 << 32) | (3 << 35), u64::from_le_bytes(*b"abc\0\0\0\0\0")]]);
    let message = Message::read(&text).unwrap();
    assert_eq!(message.root().unwrap().get_text(0), Err(Malformed("a text with no NUL")));
    // A struct whose one pointer points at itself: each read spends words,
    // until the limit ends it.
    let looped = framed(&[&[1 << 48, (0x3fff_ffffu64 << 2) | (1 << 48)]]);
    let message = Message::read(&looped).unwrap();
    let mut at = message.root().unwrap();
    let mut reads = 0u64;
    let ended = loop {
        match at.get_struct(0) {
            Ok(Some(next)) => at = next,
            Ok(None) => panic!("the loop ended"),
            Err(e) => break e,
        }
        reads += 1;
        assert!(reads <= BUDGET + 1, "no limit");
    };
    assert_eq!(ended, Malformed("more words read than the limit"));
}

#[test]
fn a_struct_of_no_size_points_at_its_own_pointer() {
    let (b, _) = Builder::new(0, 0);
    // The root pointer: offset -1, no data, no pointers, as capnp writes it.
    assert_eq!(&b.frame()[8..16], &0xffff_fffcu64.to_le_bytes());
    let frame = b.frame();
    let message = Message::read(&frame).unwrap();
    assert_eq!(message.root().unwrap().u64(0), 0);
}

/// An empty list of bytes behind a double far pointer whose landing pad
/// names a segment that is not there: an error, not a panic, as the release
/// aborts on a panic and the node would end.
#[test]
fn a_double_far_pointer_to_a_missing_segment_is_malformed() {
    let words: [u64; 4] = [
        // The root: a struct at the next word, with no data and one pointer.
        1 << 48,
        // Its pointer: double far, the landing pad at word 2 of segment 0.
        2 | 4 | (2 << 3),
        // The pad: the object at word 0 of segment 5, which is not there.
        2 | (5 << 32),
        // The tag: a list of bytes, none.
        1 | (BYTE << 32),
    ];
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&(words.len() as u32).to_le_bytes());
    for word in words {
        frame.extend_from_slice(&word.to_le_bytes());
    }
    let message = Message::read(&frame).unwrap();
    let root = message.root().unwrap();
    assert_eq!(root.get_data(0).unwrap_err(), Malformed("a pointer to a segment that is not there"));
}

/// A message whose root has one pointer, to a list of structs whose tag
/// counts `count` elements of no size: three words in all, as cfrs's fuzz
/// target found one (its GitHub #5, 80 MiB from 96 bytes).
pub(crate) fn list_of_nothing(count: u64) -> Vec<u8> {
    framed(&[&[
        // The root: a struct at the next word, with no data and one pointer.
        1 << 48,
        // Its pointer: a list of structs at the next word, of no words.
        1 | (COMPOSITE << 32),
        // The tag: `count` elements, each of no data and no pointers.
        count << 2,
    ]])
}

/// A list's value owns no memory: a `Copy` type cannot.
fn owns_nothing<T: Copy>(_: &T) {}

/// A list of 2^23 structs of no size: refused by the budget, as the root's
/// word was spent first; one within the budget reads, and holds no element,
/// each made when it is asked for (T-403).
#[test]
fn a_list_of_structs_of_no_size_is_charged_a_word_each_and_holds_none() {
    let frame = list_of_nothing(1 << 23);
    assert_eq!(frame.len(), 32, "a header and three words");
    let message = Message::read(&frame).unwrap();
    let refused = message.root().unwrap().get_struct_list(0).err();
    assert_eq!(refused, Some(Malformed("more words read than the limit")));
    let message = Message::read_within(&frame, CONTROL_BUDGET).unwrap();
    assert!(message.root().unwrap().get_struct_list(0).is_err(), "nor within the control stream's budget");

    // Capnp's own limit, less the root's word.
    let count = BUDGET - 1;
    let frame = list_of_nothing(count);
    let message = Message::read(&frame).unwrap();
    let list = message.root().unwrap().get_struct_list(0).unwrap();
    owns_nothing(&list);
    assert_eq!((list.len(), list.iter().len()), (count as usize, count as usize));
    let last = list.iter().nth(count as usize - 1).expect("the last element, reached with no walk");
    assert_eq!((last.u64(0), last.get_struct(0).unwrap().is_none()), (0, true));
    assert!(list.get(count as usize).is_none(), "no element past the count");

    // The control stream's budget, the same way.
    let frame = list_of_nothing(CONTROL_BUDGET - 1);
    let message = Message::read_within(&frame, CONTROL_BUDGET).unwrap();
    assert_eq!(message.root().unwrap().get_struct_list(0).unwrap().len(), CONTROL_BUDGET as usize - 1);
    let frame = list_of_nothing(CONTROL_BUDGET);
    let message = Message::read_within(&frame, CONTROL_BUDGET).unwrap();
    assert!(message.root().unwrap().get_struct_list(0).is_err());
}

/// A list whose elements need more words than it has, also where the product
/// passes 32 bits, and a tag that is no struct pointer, are malformed.
#[test]
fn a_list_of_structs_must_hold_its_elements_and_a_struct_tag() {
    // 2^16 elements of 2^16 words each (65,535 data words and one pointer):
    // 2^32 words, which a usize of 32 bits would read as none.
    let tag = (1u64 << 18) | (65_535 << 32) | (1 << 48);
    let frame = framed(&[&[1 << 48, 1 | (COMPOSITE << 32), tag]]);
    let message = Message::read(&frame).unwrap();
    let refused = message.root().unwrap().get_struct_list(0).err();
    assert_eq!(refused, Some(Malformed("a list of structs longer than its words")));
    // A tag of the kind of a list pointer.
    let frame = framed(&[&[1 << 48, 1 | (COMPOSITE << 32), (3 << 2) | 1]]);
    let message = Message::read(&frame).unwrap();
    let refused = message.root().unwrap().get_struct_list(0).err();
    assert_eq!(refused, Some(Malformed("the tag of a list of structs is not a struct pointer")));
    // Two elements of one data word each, as capnp lays them out, read each.
    let frame = framed(&[&[1 << 48, 1 | (COMPOSITE << 32) | (2 << 35), (2 << 2) | (1 << 32), 7, 9]]);
    let message = Message::read(&frame).unwrap();
    let values: Vec<u64> = message.root().unwrap().get_struct_list(0).unwrap().iter().map(|s| s.u64(0)).collect();
    assert_eq!(values, [7, 9]);
}

/// The length of a frame is summed so that no count of words wraps it.
#[test]
fn a_frame_of_segments_too_large_to_add_is_refused() {
    let mut table = 511u32.to_le_bytes().to_vec();
    for _ in 0..512 {
        table.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    assert_eq!(frame_len(&table), Err(Malformed("a frame larger than the limit")));
}
