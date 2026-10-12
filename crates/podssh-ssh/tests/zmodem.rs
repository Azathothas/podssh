//! ZMODEM in a terminal session (T-148), against byte vectors derived from
//! the spec, Chuck Forsberg's "The ZMODEM Inter Application File Transfer
//! Protocol" (1988-10-14; a number such as 7.2 is its section), and from
//! the bytes that lrzsz's `sz` and `rz` print: the search for a start in a
//! session's output, the headers and the subpackets with their escapes and
//! CRCs, the limit of each wait, and a file each way, between podssh's two
//! sides and through the session's question, its temporary name and its
//! rename (`tests/zmodem_session/mod.rs`). The vectors of binary frames were
//! computed by a separate implementation of the spec's rules, not by this
//! crate.

mod cleanup;
mod zmodem_session;

use std::io::Cursor;
use std::time::{Duration, Instant};

use podssh_ssh::zmodem::detect::{Detector, Start, HOLD};
use podssh_ssh::zmodem::files::{self, Outgoing};
use podssh_ssh::zmodem::receive::{Offer, Receiver, FLAGS};
use podssh_ssh::zmodem::send::Sender;
use podssh_ssh::zmodem::wire::{self, Escaper, Event, Form, Header, Reader};
use podssh_ssh::zmodem::{Act, Ended, CANCEL, TRIES, WAIT};

/// The bytes that the acts send, and the other acts.
fn split(acts: Vec<Act>) -> (Vec<u8>, Vec<Act>) {
    let mut bytes = Vec::new();
    let mut other = Vec::new();
    for act in acts {
        match act {
            Act::Send(b) => bytes.extend(b),
            act => other.push(act),
        }
    }
    (bytes, other)
}

fn events(bytes: &[u8]) -> Vec<Event> {
    let mut reader = Reader::new();
    bytes.iter().filter_map(|&b| reader.push(b)).collect()
}

fn read_header(bytes: &[u8]) -> Header {
    match events(bytes).into_iter().next() {
        Some(Event::Header(header)) => header,
        other => panic!("no header first: {other:?}"),
    }
}

fn zrinit() -> Header {
    Header { kind: wire::ZRINIT, bytes: [0, 0, 0, FLAGS], form: Form::Hex }
}

fn outgoing(name: &str, size: usize) -> Outgoing {
    Outgoing { name: name.into(), size: size as u64, mtime: 0o14672417660, mode: 0o100644 }
}

/// The check values over "123456789": CRC-16/XMODEM, ZMODEM's CRC-16
/// (polynomial 0x1021 from 0), gives 0x31C3; the CRC-32 of Ethernet, with
/// "-1 preset, inversion" (3.3), gives 0xCBF43926. In two pieces too, as a
/// subpacket's CRC takes its data, then its frame end.
#[test]
fn the_crcs_give_their_check_values() {
    assert_eq!(wire::crc16(b"123456789"), 0x31c3);
    assert_eq!(wire::crc32(b"123456789"), 0xcbf4_3926);
    assert_eq!(wire::crc16_update(wire::crc16_update(0, b"1234"), b"56789"), 0x31c3);
    assert_eq!(!wire::crc32_update(wire::crc32_update(!0, b"1234"), b"56789"), 0xcbf4_3926);
}

/// Hex headers (7.3.3): "* * ZDLE B TYPE F3/P0 F2/P1 F1/P2 F0/P3 CRC-1
/// CRC-2 CR LF XON", in lowercase hex. The first two are what lrzsz prints:
/// `rz` after "rz waiting to receive." (ZRINIT, with CANFC32, CANOVIO and
/// CANFDX, 0x23), and `sz` after `rz\r` (ZRQINIT). "An XON character is
/// appended to all HEX packets except ZACK and ZFIN." A position goes low
/// byte first (ZP0).
#[test]
fn hex_headers_are_the_bytes_that_lrzsz_prints() {
    assert_eq!(FLAGS, 0x23);
    assert_eq!(wire::hex_header(wire::ZRINIT, [0, 0, 0, FLAGS]), b"**\x18B0100000023be50\r\x8a\x11");
    assert_eq!(wire::hex_header(wire::ZRQINIT, [0; 4]), b"**\x18B00000000000000\r\x8a\x11");
    assert_eq!(wire::hex_header(wire::ZFIN, [0; 4]), b"**\x18B0800000000022d\r\x8a");
    assert_eq!(wire::hex_header(wire::ZACK, wire::at(1)), b"**\x18B03010000009866\r\x8a");
    assert_eq!(wire::hex_header(wire::ZRPOS, wire::at(0x1234)), b"**\x18B09341200006367\r\x8a\x11");
    // And each reads back, with its CRC.
    let header = read_header(b"**\x18B09341200006367\r\x8a\x11");
    assert_eq!((header.kind, header.position(), header.form), (wire::ZRPOS, 0x1234, Form::Hex));
}

/// Binary headers (7.3.1, 7.3.2): ZPAD ZDLE ZBIN, the type, four bytes and
/// the CRC-16 high byte first; with ZBIN32, "four characters of CRC", low
/// byte first. Each reads back with its form.
#[test]
fn binary_headers_are_the_bytes_of_the_spec() {
    let zfile16: &[u8] = b"*\x18A\x04\x00\x00\x00\x01\x99'";
    let zfile32: &[u8] = b"*\x18C\x04\x00\x00\x00\x01Ka\xa5D";
    let zdata32: &[u8] = b"*\x18C\x0a4\x12\x00\x00T\xf7y\xec";
    assert_eq!(Escaper::new(false).header(wire::ZFILE, [0, 0, 0, wire::ZCBIN], false), zfile16);
    assert_eq!(Escaper::new(false).header(wire::ZFILE, [0, 0, 0, wire::ZCBIN], true), zfile32);
    assert_eq!(Escaper::new(false).header(wire::ZDATA, wire::at(0x1234), true), zdata32);
    let want =
        [(zfile16, wire::ZFILE, Form::Bin16), (zfile32, wire::ZFILE, Form::Bin32), (zdata32, wire::ZDATA, Form::Bin32)];
    for (bytes, kind, form) in want {
        let header = read_header(bytes);
        assert_eq!((header.kind, header.form), (kind, form));
    }
    assert_eq!(read_header(zdata32).position(), 0x1234);
    assert_eq!(read_header(zfile32).flags(), wire::ZCBIN);
}

/// "ZMODEM software escapes ZDLE, 020, 0220, 021, 0221, 023, and 0223"
/// (7.2): ZDLE, then the byte with bit 6 inverted. CR goes as it is, and is
/// escaped after `@` (lrzsz's rule, for Telenet's `@ CR`); DEL and bytes
/// with bit 5 or 6 set never are. With the receiver's ESCCTL, each control
/// character is. A subpacket (7.4) ends with ZDLE, its frame end and the
/// CRC of the data and the frame end; ZCRCW adds an XON.
#[test]
fn escapes_and_subpackets_follow_sections_7_2_and_7_4() {
    let data = [0x18, 0x10, 0x90, 0x11, 0x91, 0x13, 0x93, b'\r', b'@', b'\r', 0x00, 0x7f, 0xff, b'A', 0x8d];
    let want: &[u8] = b"\x18X\x18P\x18\xd0\x18Q\x18\xd1\x18S\x18\xd3\x0d@\x18M\x00\x7f\xffA\x8d\x18h\x17\xb7";
    assert_eq!(Escaper::new(false).subpacket(&data, wire::ZCRCE, false), want);
    let ctl: &[u8] = b"\x18@\x18[\x7f\x18\xdba\x18i3b";
    assert_eq!(Escaper::new(true).subpacket(&[0x00, 0x1b, 0x7f, 0x9b, b'a'], wire::ZCRCG, false), ctl);
    assert_eq!(Escaper::new(false).subpacket(b"hi\x18\x11@\r", wire::ZCRCE, false), b"hi\x18X\x18Q@\x18M\x18h\xdav");
    assert_eq!(Escaper::new(false).subpacket(b"hi\x18\x11@\r", wire::ZCRCE, true), b"hi\x18X\x18Q@\x18M\x18h0u\xa64");
    assert_eq!(Escaper::new(false).subpacket(b"", wire::ZCRCW, false), b"\x18k\xdd\xcd\x11");
}

/// Data subpackets carry each byte value, with each frame end and each
/// CRC, and read back whole; ZCRCG and ZCRCQ keep the frame, ZCRCE ends it
/// (8.2). ZRUB0 and ZRUB1 after a ZDLE are DEL and DEL with the parity bit,
/// and an XON in the data is dropped (7.2).
#[test]
fn subpackets_carry_each_byte_value_with_each_crc() {
    let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
    for crc32 in [false, true] {
        let mut esc = Escaper::new(false);
        let mut stream = esc.header(wire::ZDATA, wire::at(0), crc32);
        let ends = [wire::ZCRCG, wire::ZCRCQ, wire::ZCRCE];
        for end in ends {
            stream.extend(esc.subpacket(&data, end, crc32));
        }
        let mut reader = Reader::new();
        let found: Vec<Event> = stream.iter().filter_map(|&b| reader.push(b)).collect();
        assert_eq!(found.len(), 4, "{crc32}");
        let form = if crc32 { Form::Bin32 } else { Form::Bin16 };
        assert!(matches!(&found[0], Event::Header(h) if h.kind == wire::ZDATA && h.form == form));
        for (event, end) in found[1..].iter().zip(ends) {
            assert_eq!(event, &Event::Data { data: data.clone(), end });
        }
        assert!(reader.hunting(), "ZCRCE ends the frame");
    }
    // DEL by ZRUB0 and ZRUB1, and an XON that is no data, by hand.
    let mut stream = Escaper::new(false).header(wire::ZDATA, wire::at(0), false);
    stream.extend_from_slice(&[0x18, wire::ZRUB0, 0x11, 0x18, wire::ZRUB1, b'x', 0x18, wire::ZCRCE]);
    stream.extend_from_slice(&wire::crc16(&[0x7f, 0xff, b'x', wire::ZCRCE]).to_be_bytes());
    let found = events(&stream);
    assert_eq!(found.get(1), Some(&Event::Data { data: vec![0x7f, 0xff, b'x'], end: wire::ZCRCE }), "{found:?}");
}

/// A changed byte fails the CRC: of a hex header, and of a subpacket with
/// each CRC.
#[test]
fn a_changed_byte_fails_the_crc() {
    let mut hex = wire::hex_header(wire::ZRPOS, wire::at(4096));
    hex[6] = if hex[6] == b'0' { b'1' } else { b'0' };
    assert_eq!(events(&hex), vec![Event::Bad]);
    for crc32 in [false, true] {
        let mut esc = Escaper::new(false);
        let mut stream = esc.header(wire::ZDATA, wire::at(0), crc32);
        let start = stream.len();
        stream.extend(esc.subpacket(b"hello, world", wire::ZCRCE, crc32));
        stream[start] ^= 0x01;
        let found = events(&stream);
        assert!(matches!(found.as_slice(), [Event::Header(_), Event::Bad]), "{found:?}");
    }
}

/// "Receipt of five successive CAN characters will abort a ZMODEM session"
/// (7.2); the cancel sequence is "eight CAN characters and ten backspace
/// characters" (8.4). Four CAN before a header do not cancel.
#[test]
fn five_can_cancel_and_four_do_not() {
    assert_eq!(CANCEL.len(), 18);
    assert!(CANCEL[..8].iter().all(|&b| b == 0x18) && CANCEL[8..].iter().all(|&b| b == 0x08));
    assert_eq!(events(CANCEL), vec![Event::Cancel]);
    let mut stream = vec![0x18; 4];
    stream.extend(wire::hex_header(wire::ZFIN, [0; 4]));
    let found = events(&stream);
    assert!(matches!(found.as_slice(), [Event::Header(h)] if h.kind == wire::ZFIN), "{found:?}");
}

/// The start of `sz` (8.1: the output "may be scanned for B00 indicating a
/// ZRQINIT header") and of `rz` (B01), in the bytes that lrzsz prints, with
/// the text around them. Text with stars, and a header whose CRC fails,
/// pass as they came; a start that the end of a message cut is found in
/// the next, and bytes that were no start show after HOLD.
#[test]
fn the_detector_finds_sz_and_rz_and_passes_the_rest() {
    let now = Instant::now();
    let mut out = b"$ sz notes.txt\r\nrz\r".to_vec();
    out.extend(wire::hex_header(wire::ZRQINIT, [0; 4]));
    let scan = Detector::new().feed(&out, now);
    assert_eq!(scan.shown, b"$ sz notes.txt\r\nrz\r");
    assert!(matches!(scan.start, Some(Start::Offer(h)) if h.kind == wire::ZRQINIT), "{scan:?}");
    assert_eq!(scan.rest, b"\r\x8a\x11");

    let mut out = b"rz waiting to receive.".to_vec();
    out.extend(wire::hex_header(wire::ZRINIT, [0, 0, 0, FLAGS]));
    let scan = Detector::new().feed(&out, now);
    assert_eq!(scan.shown, b"rz waiting to receive.");
    assert!(matches!(scan.start, Some(Start::Ready(h)) if h.flags() == 0x23), "{scan:?}");

    let text = b"a ** b *** c **\x18B00000000000001 d";
    let scan = Detector::new().feed(text, now);
    assert_eq!((scan.shown.as_slice(), scan.start), (&text[..], None));

    let header = wire::hex_header(wire::ZRQINIT, [0; 4]);
    let mut d = Detector::new();
    let scan = d.feed(&[b"ok ".as_slice(), &header[..9]].concat(), now);
    assert_eq!((scan.shown.as_slice(), scan.start), (&b"ok "[..], None));
    assert_eq!(d.deadline(), Some(now + HOLD));
    assert!(matches!(d.feed(&header[9..], now).start, Some(Start::Offer(_))));

    let mut d = Detector::new();
    assert_eq!(d.feed(b"price: 5*", now).shown, b"price: 5");
    assert!(d.flush(now + HOLD / 2).is_empty());
    assert_eq!(d.flush(now + HOLD), b"*");
    assert_eq!(d.deadline(), None);
}

/// ZFILE's data (section 13): "The pathname (conventionally, the file
/// name) is sent as a null terminated ASCII string", then the length in
/// decimal, and the modification date and the mode in octal; "If only the
/// pathname is sent, the pathname is terminated with two nulls."
#[test]
fn zfile_data_is_read_and_written_as_section_13_says() {
    let offer = Offer::parse(b"notes.txt\x00300000 14672417660 100644 0 1 300000\x00").expect("an offer");
    let want =
        Offer { name: "notes.txt".into(), size: Some(300_000), mtime: Some(0o14672417660), mode: Some(0o100644) };
    assert_eq!(offer, want);
    let bare = Offer::parse(b"bare\x00\x00").expect("an offer");
    assert_eq!((bare.name.as_str(), bare.size, bare.mtime, bare.mode), ("bare", None, None, None));
    assert_eq!(Offer::parse(b"no nul"), None);
    let out = outgoing("up.bin", 5);
    assert_eq!(out.zfile(), b"up.bin\x005 14672417660 100644 0 1 5\x00");
    let back = Offer::parse(&out.zfile()).expect("an offer");
    assert_eq!((back.size, back.mtime, back.mode), (Some(5), Some(0o14672417660), Some(0o100644)));
}

/// A name that the server offers is one component that may be written
/// here: the last of a path, never `.`, `..`, empty, or with a control
/// character; on Windows also no device and no character that a name there
/// cannot hold.
#[test]
fn an_offered_name_is_one_component_that_may_be_written() {
    assert_eq!(files::check_name("notes.txt"), Ok("notes.txt".to_string()));
    assert_eq!(files::check_name("/home/u/notes.txt"), Ok("notes.txt".to_string()));
    for bad in ["", ".", "..", "dir/", "a/..", "evil\x1b[2Jname", "line\nbreak"] {
        assert!(files::check_name(bad).is_err(), "{bad:?}");
    }
    if cfg!(windows) {
        for bad in ["CON", "aux.txt", "a:b", "back\\slash", "trailing."] {
            assert!(files::check_name(bad).is_err(), "{bad:?}");
        }
    }
}

/// One file crosses between podssh's two sides, with each byte value and a
/// length that is no multiple of a subpacket: ZFILE, ZRPOS 0, ZDATA, ZEOF,
/// ZRINIT, ZFIN and "OO" (8.2, 8.3), with CRC-32 as ZRINIT allows.
#[test]
fn a_file_crosses_between_the_two_sides() {
    let now = Instant::now();
    let data: Vec<u8> = (0..70_001u32).map(|i| (i * 7 + i / 255) as u8).collect();
    let (mut receiver, _) = Receiver::new(now);
    let (mut sender, first) = Sender::new(Cursor::new(data.clone()), outgoing("data.bin", data.len()), &zrinit(), now);
    let (mut to_receiver, mut to_sender) = (split(first).0, Vec::new());
    let (mut written, mut closed) = (Vec::new(), Vec::new());
    let (mut receiver_end, mut sender_end) = (None, None);
    for _ in 0..100_000 {
        let (bytes, acts) = split(receiver.feed(&std::mem::take(&mut to_receiver), now));
        to_sender.extend(bytes);
        for act in acts {
            match act {
                Act::Offer(offer) => {
                    assert_eq!((offer.name.as_str(), offer.size), ("data.bin", Some(data.len() as u64)));
                    to_sender.extend(split(receiver.decide(true, now)).0);
                }
                Act::Write(bytes) => written.extend(bytes),
                Act::Close(n) => closed.push(("received", n)),
                Act::End { ended, .. } => receiver_end = Some(ended),
                _ => {}
            }
        }
        let (bytes, acts) = split(sender.feed(&std::mem::take(&mut to_sender), now));
        to_receiver.extend(bytes);
        for act in acts {
            match act {
                Act::Close(n) => closed.push(("sent", n)),
                Act::End { ended, .. } => sender_end = Some(ended),
                _ => {}
            }
        }
        if sender.streaming() {
            to_receiver.extend(split(sender.pull(now)).0);
        }
        if receiver_end.is_some() && sender_end.is_some() {
            break;
        }
    }
    assert_eq!(written.len(), data.len());
    assert!(written == data, "the bytes differ");
    let len = data.len() as u64;
    assert_eq!(closed, vec![("received", len), ("sent", len)]);
    assert_eq!((receiver_end, sender_end), (Some(Ended::Done), Some(Ended::Done)));
}

/// "resends its header at response time (default 10 second) intervals for
/// a suitable period of time (40 seconds total)" (8.1): the receiver sends
/// ZRINIT again after each wait, and after TRIES waits it cancels; the
/// sender does the same with ZFILE. Nothing goes before a wait ends.
#[test]
fn each_wait_has_its_limit_and_its_tries() {
    let t0 = Instant::now();
    let (mut receiver, first) = Receiver::new(t0);
    let first = split(first).0;
    assert_eq!(receiver.deadline(), Some(t0 + WAIT));
    assert!(receiver.timeout(t0 + WAIT - Duration::from_millis(1)).is_empty());
    let mut at = t0;
    for _ in 1..TRIES {
        at += WAIT;
        assert_eq!(split(receiver.timeout(at)), (first.clone(), Vec::new()), "ZRINIT again");
    }
    at += WAIT;
    let (bytes, other) = split(receiver.timeout(at));
    assert_eq!(bytes, CANCEL);
    assert!(matches!(other.as_slice(), [Act::End { ended: Ended::Stopped(_), .. }]), "{other:?}");
    assert_eq!(at - t0, Duration::from_secs(40), "40 seconds in all");
    assert_eq!(receiver.deadline(), None);

    let (mut sender, first) = Sender::new(Cursor::new(vec![1u8]), outgoing("x", 1), &zrinit(), t0);
    let first = split(first).0;
    let mut at = t0;
    for _ in 1..TRIES {
        at += WAIT;
        assert_eq!(split(sender.timeout(at)).0, first, "ZFILE again");
    }
    at += WAIT;
    let (bytes, other) = split(sender.timeout(at));
    assert_eq!(bytes, CANCEL);
    assert!(matches!(other.as_slice(), [Act::End { ended: Ended::Stopped(_), .. }]), "{other:?}");
}

/// "If they do not agree, a ZRPOS error response is generated to force the
/// sender to the right position within the file" (8.2); a subpacket whose
/// CRC fails gets the same (9.1); and "The receiver should ignore a ZEOF
/// with an offset that does not match the current file length".
#[test]
fn a_wrong_position_or_a_bad_crc_asks_for_the_right_position() {
    let now = Instant::now();
    let (mut receiver, _) = Receiver::new(now);
    let mut esc = Escaper::new(false);
    let mut zfile = esc.header(wire::ZFILE, [0, 0, 0, wire::ZCBIN], true);
    zfile.extend(esc.subpacket(b"f\x00", wire::ZCRCW, true));
    let (_, acts) = split(receiver.feed(&zfile, now));
    assert!(matches!(acts.as_slice(), [Act::Offer(offer)] if offer.name == "f"), "{acts:?}");
    let zrpos0 = split(receiver.decide(true, now)).0;
    assert_eq!(zrpos0, wire::hex_header(wire::ZRPOS, wire::at(0)));

    let mut wrong = esc.header(wire::ZDATA, wire::at(5), true);
    wrong.extend(esc.subpacket(b"abc", wire::ZCRCG, true));
    assert_eq!(split(receiver.feed(&wrong, now)), (zrpos0, Vec::new()));

    let mut good = esc.header(wire::ZDATA, wire::at(0), true);
    good.extend(esc.subpacket(b"abc", wire::ZCRCG, true));
    let start = good.len();
    good.extend(esc.subpacket(b"def", wire::ZCRCE, true));
    good[start] ^= 0x01;
    let (bytes, acts) = split(receiver.feed(&good, now));
    assert_eq!(bytes, wire::hex_header(wire::ZRPOS, wire::at(3)));
    assert_eq!(acts, vec![Act::Write(b"abc".to_vec()), Act::Progress(3)]);

    assert_eq!(split(receiver.feed(&esc.header(wire::ZEOF, wire::at(6), true), now)), (Vec::new(), Vec::new()));
    let (bytes, acts) = split(receiver.feed(&esc.header(wire::ZEOF, wire::at(3), true), now));
    assert_eq!(acts, vec![Act::Close(3)]);
    assert_eq!(bytes, wire::hex_header(wire::ZRINIT, [0, 0, 0, FLAGS]));
}
