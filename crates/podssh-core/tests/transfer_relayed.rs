//! A file chunk as the server relays it, and the acknowledgements (T-097).
//! The server puts the sender's prefix, `:nick!user@host `, in front of
//! each line it relays: a chunk sized for the line as podssh writes it can
//! pass 512 bytes there, and a server that cuts it breaks the base64. The
//! limits are InspIRCd 4.11.0's `005`, captured on 2026-10-10.

use podssh_core::irc::isupport::Isupport;
use podssh_core::irc::message::{Command, Message};
use podssh_core::irc::transfer::{chunk_bytes, chunk_line_length, Chunk, Line, Offer, Receiver, Sender};
use podssh_core::irc::TransferLimits;

/// The limits of InspIRCd 4.11.0's `005`: `NICKLEN=30`, `USERLEN=10` and
/// `HOSTLEN=64`.
fn inspircd() -> Isupport {
    let mut isupport = Isupport::empty();
    for line in [
        "pa AWAYLEN=200 CASEMAPPING=ascii CHANLIMIT=#:20 CHANMODES=b,k,l,imnpst CHANNELLEN=60 CHANTYPES=# ELIST=CMNTU EXTBAN=, HOSTLEN=64 KEYLEN=32 KICKLEN=300 LINELEN=512",
        "pa MAXLIST=b:100 MAXTARGETS=5 MODES=20 NAMELEN=130 NETWORK=PodTest NICKLEN=30 PREFIX=(ov)@+ SAFELIST STATUSMSG=@+ TOPICLEN=330 USERLEN=10 USERMODES=,,s,iow",
    ] {
        isupport.merge(&line.split(' ').map(str::to_string).collect::<Vec<_>>());
    }
    isupport
}

fn line_of(message: &Message) -> Line {
    let Command::Privmsg { text, .. } = &message.command else { panic!("not a PRIVMSG: {message:?}") };
    Line::parse(text.as_str()).expect("a transfer line")
}

#[test]
fn a_chunk_line_fits_512_with_the_worst_prefix() {
    // NICKLEN 30, a channel of 50 characters, the last chunk of 60 MiB.
    let isupport = inspircd();
    let target = format!("#{}", "c".repeat(49));
    let (id, total) = ("0123456789abcdef", 60 * 1024 * 1024u64);
    let size = chunk_bytes(&isupport, &target, id, total).expect("room for a chunk");
    let limits = TransferLimits { chunk_bytes: size, ..TransferLimits::default() };
    let last = limits.chunk_count(total) - 1;
    let (offset, _) = limits.chunk_range(total, last).expect("the last chunk");
    let length = chunk_line_length(&limits, &isupport, &target, id, last, offset);
    assert!(length <= 512, "the relayed line is {length} bytes, for chunks of {size}");
    // Three bytes more, four of base64, pass it: the size is the most that fits.
    let more = TransferLimits { chunk_bytes: size + 3, ..limits };
    assert!(chunk_line_length(&more, &isupport, &target, id, last, offset) > 512);
    // The fixed 320 bytes of before do not fit the relayed line.
    let old = TransferLimits::default();
    assert!(chunk_line_length(&old, &isupport, &target, id, last, offset) > 512);
}

#[test]
fn a_target_that_leaves_no_room_is_refused() {
    let isupport = inspircd();
    // 251 characters still leave 84 bytes; 330 leave fewer than 48.
    assert!(chunk_bytes(&isupport, &format!("#{}", "c".repeat(250)), "t1", 1000).is_ok());
    let target = format!("#{}", "c".repeat(329));
    let err = chunk_bytes(&isupport, &target, "t1", 1000).expect_err("a 330-character target leaves no room");
    assert!(err.contains("under 48"), "{err}");
}

#[test]
fn the_last_ack_names_the_short_last_chunk() {
    // 1000 bytes in chunks that do not divide it: the sender completes on
    // the receiver's acks, each read back from the wire.
    let isupport = inspircd();
    let size = chunk_bytes(&isupport, "#c", "t1", 1000).expect("room");
    assert_ne!(1000 % size, 0, "the last chunk must be short for the test to mean anything");
    let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let limits = TransferLimits { chunk_bytes: size, ..TransferLimits::default() };
    let mut sender = Sender::new("t1", "f.bin", 1000, limits).expect("a safe id and name");
    let Line::Offer(offer) = line_of(&sender.offer("#c")) else { panic!("an offer") };
    let mut receiver = Receiver::from_offer(&offer).expect("the offer is accepted");
    let mut written = Vec::new();
    while let Some((offset, len)) = sender.next_range() {
        let message = sender.next_chunk_message("#c", &data[offset as usize..offset as usize + len]).unwrap();
        let Line::Chunk(chunk) = line_of(&message) else { panic!("a chunk") };
        written.extend(receiver.accept(&chunk).expect("in order"));
        let Line::Ack(ack) = line_of(&receiver.ack("#c")) else { panic!("an ack") };
        assert!(sender.acknowledge(ack.index), "the ack of chunk {} named {}", chunk.index, ack.index);
    }
    assert!(sender.is_complete() && receiver.is_complete());
    assert_eq!(written, data);
}

#[test]
fn the_ack_goes_to_the_transfer_target() {
    let offer = Offer { transfer_id: "t1".into(), name: "f.bin".into(), total: 10, chunks: 1, chunk_bytes: 48 };
    let receiver = Receiver::from_offer(&offer).unwrap();
    let ack = receiver.ack("#podssh-1a2b");
    let Command::Privmsg { target, .. } = &ack.command else { panic!("a PRIVMSG") };
    assert_eq!(target.0, "#podssh-1a2b");
}

#[test]
fn a_wrong_index_writes_nothing() {
    let data = [7u8; 100];
    let offer = Offer { transfer_id: "t1".into(), name: "f.bin".into(), total: 100, chunks: 3, chunk_bytes: 48 };
    let mut receiver = Receiver::from_offer(&offer).unwrap();
    let before = receiver.sha256_hex();
    // The right offset, the wrong index.
    let wrong = Chunk {
        transfer_id: "t1".into(),
        index: 1,
        offset: 0,
        payload: podssh_core::irc::transfer::b64::encode(&data[..48]),
    };
    let err = receiver.accept(&wrong).expect_err("the wrong index");
    assert!(err.contains("before its bytes"), "{err}");
    assert_eq!((receiver.bytes_received(), receiver.sha256_hex()), (0, before));
}

#[test]
fn an_offer_names_its_chunk_size_and_the_receiver_checks_it() {
    let offer = |chunk_bytes: u64, chunks: u64| Offer {
        transfer_id: "t1".into(),
        name: "f.bin".into(),
        total: 1000,
        chunks,
        chunk_bytes,
    };
    assert!(Receiver::from_offer(&offer(219, 5)).is_ok());
    for (size, chunks) in [(47, 22), (321, 4), (0, 0)] {
        let err = Receiver::from_offer(&offer(size, chunks)).expect_err("a size out of its bounds");
        assert!(err.contains("48 to 320"), "{size}: {err}");
    }
    let err = Receiver::from_offer(&offer(219, 4)).expect_err("a count that the size does not make");
    assert!(err.contains("which make 5"), "{err}");
    // The size rides in the offer line, and back.
    let line = Line::Offer(offer(219, 5));
    assert_eq!(line.render(), "PODSSH1|offer|t1|f.bin|1000|5|219");
    assert_eq!(Line::parse(&line.render()), Some(line));
}
