//! Chat between two podssh ends (T-099), with no I/O: the records against a
//! vector written by hand from the table, whole and one byte at a time; the
//! limits of each type, refused before a body; and two sessions that talk
//! through the codec: a message and its acknowledgement, and a file that
//! moves only once accepted, in order, within its size, with its SHA-256.

use podssh_core::chat::record::{MAX_CHUNK, MAX_TEXT, VERSION};
use podssh_core::chat::{safe_name, DecodeError, Decoder, Event, ProtocolError, Record, Refused, Session};
use sha2::{Digest, Sha256};

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Each record's bytes, decoded whole and one byte at a time.
fn round_trip(record: &Record) {
    let bytes = record.encode();
    let mut whole = Decoder::new();
    whole.push(&bytes);
    assert_eq!(whole.next_record().unwrap().as_ref(), Some(record));
    let mut slow = Decoder::new();
    for (i, byte) in bytes.iter().enumerate() {
        assert_eq!(slow.next_record().unwrap(), None, "a record before its byte {i}");
        slow.push(&[*byte]);
    }
    assert_eq!(slow.next_record().unwrap().as_ref(), Some(record));
    assert_eq!(slow.next_record().unwrap(), None);
}

#[test]
fn each_record_has_the_bytes_of_its_table() {
    // Text: type 2, length 10, the id 1 in 8 bytes, then the text.
    let text = Record::Text { id: 1, text: "hi".into() };
    assert_eq!(text.encode(), [2, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 1, b'h', b'i']);
    assert_eq!(Record::Busy.encode(), [9, 0, 0, 0, 0]);
    assert_eq!(Record::Done { id: 2, whole: true }.encode(), [8, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 2, 1]);
    for record in [
        Record::Hello { version: VERSION, nick: "ana".into() },
        text,
        Record::Ack { id: u64::MAX },
        Record::Offer { id: 3, size: 5_000_000, sha256: sha(b"x"), name: "photo.jpg".into() },
        Record::Accept { id: 3 },
        Record::Decline { id: 4 },
        Record::Chunk { id: 3, offset: 65536, data: vec![7; MAX_CHUNK] },
        Record::Done { id: 3, whole: false },
        Record::Busy,
    ] {
        round_trip(&record);
    }
}

#[test]
fn a_length_past_its_limit_is_refused_before_its_body() {
    let mut d = Decoder::new();
    // A text that says 1 GiB: refused on its header alone.
    d.push(&[2, 0x40, 0, 0, 0]);
    assert!(matches!(d.next_record(), Err(DecodeError::TooLong { kind: 2, .. })));
    let mut d = Decoder::new();
    d.push(&Record::Text { id: 1, text: "x".repeat(MAX_TEXT) }.encode());
    assert!(d.next_record().unwrap().is_some(), "a text at its limit is a record");
    let mut d = Decoder::new();
    d.push(&[42, 0, 0, 0, 0]);
    assert_eq!(d.next_record(), Err(DecodeError::UnknownKind(42)));
    let mut d = Decoder::new();
    d.push(&[3, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 1]);
    assert!(matches!(d.next_record(), Err(DecodeError::Malformed(_))), "an acknowledgement of 7 bytes");
    let mut d = Decoder::new();
    d.push(&[2, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]);
    assert_eq!(d.next_record(), Err(DecodeError::NotUtf8));
}

/// Deliver `first`, records of the first session, to the second; the replies
/// go back, until there are none. The events of the first session, then of
/// the second, each in order.
fn talk(a: &mut Session, b: &mut Session, first: Vec<Record>) -> (Vec<Event>, Vec<Event>) {
    let (mut to_b, mut to_a) = (first, Vec::new());
    let (mut seen_a, mut seen_b) = (Vec::new(), Vec::new());
    while !to_b.is_empty() || !to_a.is_empty() {
        for record in std::mem::take(&mut to_b) {
            let mut d = Decoder::new();
            d.push(&record.encode());
            let (events, replies) = b.receive(d.next_record().unwrap().unwrap()).unwrap();
            seen_b.extend(events);
            to_a.extend(replies);
        }
        for record in std::mem::take(&mut to_a) {
            let (events, replies) = a.receive(record).unwrap();
            seen_a.extend(events);
            to_b.extend(replies);
        }
    }
    (seen_a, seen_b)
}

fn greeted() -> (Session, Session) {
    let (mut a, mut b) = (Session::new(), Session::new());
    let hello_a = a.hello("ana");
    let hello_b = b.hello("bo");
    talk(&mut a, &mut b, vec![hello_a]);
    talk(&mut b, &mut a, vec![hello_b]);
    (a, b)
}

#[test]
fn a_message_is_acknowledged_and_one_with_no_acknowledgement_is_said() {
    let (mut a, mut b) = greeted();
    assert_eq!((a.peer(), b.peer()), (Some("bo"), Some("ana")));
    let (id, record) = a.text("hello, bo").unwrap();
    let (seen_a, seen_b) = talk(&mut a, &mut b, vec![record]);
    assert_eq!(seen_b, [Event::Message { id, text: "hello, bo".into() }]);
    assert_eq!(seen_a, [Event::Delivered { id }]);
    let (lost, _) = a.text("never acknowledged").unwrap();
    assert_eq!(a.undelivered(), [(lost, "never acknowledged")]);
    assert_eq!(a.text(&"x".repeat(MAX_TEXT + 1)), Err(Refused::TooLong));
}

#[test]
fn a_file_moves_only_once_accepted_and_arrives_with_its_digest() {
    let (mut a, mut b) = greeted();
    let file: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (id, offer) = a.offer("../../etc/passwd", file.len() as u64, sha(&file));
    let (_, seen_b) = talk(&mut a, &mut b, vec![offer]);
    assert_eq!(seen_b, [Event::Offered { id, name: "../../etc/passwd".into(), size: 200_000 }]);
    // A chunk before the accept: the conversation ends, and no byte is given.
    assert!(a.chunk(id, vec![1]).is_err(), "no chunk goes before the accept");
    let mut early = Session::new();
    early.receive(Record::Hello { version: VERSION, nick: "x".into() }).unwrap();
    early.receive(Record::Offer { id: 9, size: 3, sha256: sha(b"abc"), name: "a".into() }).unwrap();
    assert_eq!(
        early.receive(Record::Chunk { id: 9, offset: 0, data: b"abc".to_vec() }),
        Err(ProtocolError::NotAccepted(9))
    );

    let (accept, done_now) = b.accept(id).unwrap();
    assert!(done_now.is_none());
    let (_, seen_a) = talk(&mut b, &mut a, accept);
    assert_eq!(seen_a, [Event::Accepted { id }]);
    let mut received = Vec::new();
    let mut last = Vec::new();
    for piece in file.chunks(MAX_CHUNK) {
        let chunk = a.chunk(id, piece.to_vec()).unwrap();
        let (seen_a, seen_b) = talk(&mut a, &mut b, vec![chunk]);
        for e in &seen_b {
            if let Event::Bytes { data, .. } = e {
                received.extend_from_slice(data);
            }
        }
        last = [seen_a, seen_b].concat();
    }
    assert_eq!(received, file);
    assert!(last.contains(&Event::Received { id, whole: true }), "{last:?}");
    assert!(last.contains(&Event::Sent { id, whole: true }), "{last:?}");
    assert_eq!(a.left(id), 0);
    assert_eq!(safe_name("../../etc/passwd").as_deref(), Some("passwd"), "the receiver writes its last part only");
}

#[test]
fn bytes_out_of_order_too_many_or_with_another_digest_are_refused() {
    let peer = |offer: Record| {
        let mut s = Session::new();
        s.receive(Record::Hello { version: VERSION, nick: "x".into() }).unwrap();
        s.receive(offer).unwrap();
        s.accept(1).unwrap();
        s
    };
    let mut s = peer(Record::Offer { id: 1, size: 4, sha256: sha(b"abcd"), name: "f".into() });
    let out_of_order = s.receive(Record::Chunk { id: 1, offset: 2, data: b"cd".to_vec() });
    assert_eq!(out_of_order, Err(ProtocolError::OutOfOrder { id: 1, expected: 0, got: 2 }));
    let mut s = peer(Record::Offer { id: 1, size: 4, sha256: sha(b"abcd"), name: "f".into() });
    assert_eq!(s.receive(Record::Chunk { id: 1, offset: 0, data: b"abcde".to_vec() }), Err(ProtocolError::TooMuch(1)));
    let mut s = peer(Record::Offer { id: 1, size: 4, sha256: sha(b"abcd"), name: "f".into() });
    let (events, replies) = s.receive(Record::Chunk { id: 1, offset: 0, data: b"abcX".to_vec() }).unwrap();
    assert!(events.contains(&Event::Received { id: 1, whole: false }), "{events:?}");
    assert_eq!(replies, [Record::Done { id: 1, whole: false }]);
}

#[test]
fn an_empty_file_ends_at_its_accept_and_a_declined_one_never_moves() {
    let (mut a, mut b) = greeted();
    let (id, offer) = a.offer("empty", 0, sha(b""));
    talk(&mut a, &mut b, vec![offer]);
    let (records, done) = b.accept(id).unwrap();
    assert_eq!(done, Some(Event::Received { id, whole: true }));
    let (_, seen_a) = talk(&mut b, &mut a, records);
    assert!(seen_a.contains(&Event::Sent { id, whole: true }), "{seen_a:?}");
    let (id, offer) = a.offer("nope", 10, sha(b"0123456789"));
    talk(&mut a, &mut b, vec![offer]);
    let decline = b.decline(id).unwrap();
    let (_, seen_a) = talk(&mut b, &mut a, vec![decline]);
    assert_eq!(seen_a, [Event::Declined { id }]);
    assert!(a.chunk(id, b"0123456789".to_vec()).is_err(), "a declined file does not move");
    assert_eq!(b.accept(id), Err(Refused::NoOffer(id)), "once declined, it stays declined");
}

#[test]
fn the_greeting_comes_first_and_names_its_version() {
    let mut s = Session::new();
    assert_eq!(s.receive(Record::Text { id: 1, text: "hi".into() }), Err(ProtocolError::NoHello));
    assert_eq!(
        s.receive(Record::Hello { version: VERSION + 1, nick: "z".into() }),
        Err(ProtocolError::Version(VERSION + 1))
    );
    assert_eq!(s.receive(Record::Busy).unwrap().0, [Event::Busy], "busy comes from a side that never greets");
}

#[test]
fn an_offered_name_is_written_by_its_last_part_only() {
    for (offered, safe) in [
        ("photo.jpg", Some("photo.jpg")),
        ("../../.bashrc", Some(".bashrc")),
        (r"C:\Windows\system.ini", Some("system.ini")),
        ("a\u{1b}[2Jb", Some("a[2Jb")),
        ("..", None),
        ("dir/", None),
        ("x:stream", None),
        ("trailing. ", Some("trailing")),
    ] {
        assert_eq!(safe_name(offered).as_deref(), safe, "{offered:?}");
    }
    assert_eq!(safe_name(&"n".repeat(300)), None);
}
