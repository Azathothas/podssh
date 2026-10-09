//! The replay buffer of the resumable layer (T-152): a writer that waits
//! when the buffer is full and goes on when an `ACK` frees room; a resume
//! that sends exactly the missing bytes, also after a lost frame; no byte
//! that is not acknowledged ever dropped (GitHub #31); and a resume from an
//! offset that is not kept refused with both offsets, never a silent gap.

use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use podssh_relay::session::client::{self, Found};
use podssh_relay::session::link::ACK_EVERY;
use podssh_relay::session::record::MAX_DATA;
use podssh_relay::session::replay::{self, Full, NotKept, Replay};
use podssh_relay::session::{
    Acceptance, Ask, Decoder, Event, Hello, Link, LinkError, Nonce, OsEntropy, Record, RefuseCode, Role, SessionId,
    Settings,
};

const PIPE: usize = 256 * 1024;
const LIMIT: Duration = Duration::from_secs(30);
const MIB: usize = 1 << 20;

/// Bytes from a fixed xorshift, so that a test repeats.
fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn records(bytes: &[u8]) -> Vec<Record> {
    let mut decoder = Decoder::new();
    decoder.push(bytes);
    let mut out = Vec::new();
    while let Some(record) = decoder.next().unwrap() {
        out.push(record);
    }
    out
}

#[test]
fn the_setting_raises_the_capacity_up_to_16_mib_and_ignores_the_rest() {
    assert_eq!(replay::capacity(None), 4 * MIB);
    assert_eq!(replay::capacity(Some("8388608")), 8 * MIB);
    assert_eq!(replay::capacity(Some(" 16777216 ")), 16 * MIB);
    for ignored in ["1000", "16777217", "8M", "", "-1"] {
        assert_eq!(replay::capacity(Some(ignored)), 4 * MIB, "{ignored:?}");
    }
}

/// The capacity is a bound: bytes past the room are refused whole, and
/// nothing is kept or sent.
#[test]
fn the_buffer_never_grows_past_its_capacity() {
    let mut buffer = Replay::new(0, 1000);
    buffer.keep(&[1; 600]).unwrap();
    assert_eq!(buffer.keep(&[2; 401]), Err(Full { room: 400, asked: 401 }));
    assert_eq!(buffer.kept(), 600);
    buffer.keep(&[3; 400]).unwrap();
    assert_eq!(buffer.room(), 0);

    let mut link = Link::new(0, 0).with_replay(1000);
    let mut out = Vec::new();
    link.send(&[0; 1000], &mut out).unwrap();
    let sent = out.len();
    assert_eq!(link.send(&[0; 1], &mut out), Err(LinkError::Full(Full { room: 0, asked: 1 })));
    assert_eq!(out.len(), sent, "nothing went out past the capacity");
    assert_eq!((link.sent(), link.kept()), (1000, 1000));
}

/// The invariant of GitHub #31, against a model: after any run of sends and
/// acknowledgements, the buffer holds exactly the bytes from the highest
/// acknowledgement to the last byte sent.
#[test]
fn the_buffer_never_drops_a_byte_that_is_not_acknowledged() {
    let all = pseudo_random(3 * MIB, 7);
    let mut buffer = Replay::new(0, MIB);
    let (mut sent, mut acked) = (0usize, 0usize);
    let mut x: u32 = 0x9e37_79b9;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x as usize
    };
    while sent < all.len() {
        if next() % 3 == 0 && sent > acked {
            // An acknowledgement anywhere up to the bytes sent, sometimes an
            // old one.
            let offset = acked.saturating_sub(next() % 4096) + next() % (sent - acked + 1);
            buffer.release(offset as u64).unwrap();
            acked = acked.max(offset);
        } else {
            let n = (next() % 70_000).min(buffer.room()).min(all.len() - sent);
            buffer.keep(&all[sent..sent + n]).unwrap();
            sent += n;
        }
        assert_eq!((buffer.start(), buffer.end()), (acked as u64, sent as u64));
        let (a, b) = buffer.since(acked as u64).unwrap();
        assert_eq!([a, b].concat(), all[acked..sent], "the bytes kept are the bytes not acknowledged");
    }
    assert!(buffer.release(sent as u64 + 1).unwrap_err().to_string().contains("acknowledges"));
}

/// A relay that drops one frame makes a gap; the link ends, and the resume
/// on a new link sends exactly the bytes from the receiver's offset: the
/// digests at both ends are equal.
#[test]
fn a_resume_sends_exactly_the_missing_bytes_after_a_lost_frame() {
    let sent = pseudo_random(2 * MIB, 11);
    let mut sender = Link::new(0, 0).with_replay(4 * MIB);
    let mut receiver = Link::new(0, 0).with_replay(4 * MIB);
    let mut delivered = Vec::new();

    let mut wire = Vec::new();
    for chunk in sent.chunks(32 * 1024) {
        sender.send(chunk, &mut wire).unwrap();
    }
    let mut lost = false;
    for (i, record) in records(&wire).into_iter().enumerate() {
        if i == 20 {
            continue; // the relay dropped this frame
        }
        match receiver.on_record(record) {
            Ok(Event::Deliver(bytes)) => delivered.extend(bytes),
            Ok(other) => panic!("{other:?}"),
            Err(LinkError::Offset(_)) => {
                lost = true;
                break;
            }
            Err(e) => panic!("{e}"),
        }
        if receiver.ack_due() {
            let ack = receiver.ack();
            assert!(matches!(sender.on_record(ack), Ok(Event::Nothing)));
        }
    }
    assert!(lost, "the gap ended the link");
    assert_eq!(delivered.len(), 20 * 32 * 1024, "each byte before the gap, and none after");
    assert!(sender.kept() < sent.len(), "acknowledged bytes were freed");

    // The new link: each side's handshake gave the other's received offset.
    let mut again = Vec::new();
    let resent = sender.resume(receiver.received(), &mut again).unwrap();
    assert_eq!(resent, (sent.len() - delivered.len()) as u64, "exactly the missing bytes");
    receiver.resume(sender.received(), &mut Vec::new()).unwrap();
    for record in records(&again) {
        if let Ok(Event::Deliver(bytes)) = receiver.on_record(record) {
            delivered.extend(bytes);
        }
    }
    assert_eq!(Sha256::digest(&delivered), Sha256::digest(&sent));
}

/// A resume from below the acknowledged offset, or past the bytes sent,
/// cannot be served: it is refused with both offsets, never answered with a
/// gap.
#[test]
fn a_resume_from_an_offset_not_kept_is_refused_with_both_offsets() {
    let mut sender = Link::new(0, 0).with_replay(4 * MIB);
    let mut out = Vec::new();
    sender.send(&pseudo_random(100_000, 3), &mut out).unwrap();
    sender.on_record(Record::Ack { offset: 65_536 }).unwrap();

    let below = sender.resume(10_000, &mut Vec::new()).unwrap_err();
    assert_eq!(below, NotKept { asked: 10_000, start: 65_536, end: 100_000 });
    let past = sender.resume(200_000, &mut Vec::new()).unwrap_err();
    assert_eq!(past, NotKept { asked: 200_000, start: 65_536, end: 100_000 });

    let Record::Refuse { code, reason } = below.refusal() else { panic!() };
    assert_eq!(code, RefuseCode::NOT_KEPT);
    assert!(reason.contains("10000") && reason.contains("65536") && reason.contains("100000"), "{reason}");
    assert!(Record::Refuse { code, reason }.to_bytes().is_ok(), "the reason fits the record");

    // With no buffer, only a resume from the end is possible.
    let mut bare = Link::new(0, 0);
    bare.send(b"abc", &mut Vec::new()).unwrap();
    assert_eq!(bare.resume(3, &mut Vec::new()), Ok(0));
    assert_eq!(bare.resume(1, &mut Vec::new()), Err(NotKept { asked: 1, start: 3, end: 3 }));
}

/// A far end, scripted: the bytes of a real `GREETING` with `features`,
/// then an `ACCEPT` of a new session once the client's `OPEN` comes.
async fn scripted(features: &[&str]) -> (client::Client<DuplexStream>, DuplexStream, Decoder) {
    let (client_link, mut far) = tokio::io::duplex(PIPE);
    let started =
        tokio::spawn(async move { client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy).await });
    let hello = Hello {
        version: 1,
        role: Role::NODE,
        nonce: Nonce([7; 32]),
        features: features.iter().map(|f| f.to_string()).collect(),
    };
    far.write_all(&Record::Greeting(hello).to_bytes().unwrap()).await.unwrap();
    let mut decoder = Decoder::new();
    let open = read_record(&mut far, &mut decoder).await;
    assert!(matches!(open, Record::Open { .. }), "{open:?}");
    // RFC 7748's public key of Bob: any key that is not of low order.
    let public: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83,
        0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    ];
    let accept = Record::Accept(Acceptance::New { id: SessionId([5; 16]), public });
    far.write_all(&accept.to_bytes().unwrap()).await.unwrap();
    let client = tokio::time::timeout(LIMIT, started).await.unwrap().unwrap().unwrap();
    assert!(matches!(client.found(), Found::Layer { .. }));
    (client, far, decoder)
}

async fn read_record(link: &mut DuplexStream, decoder: &mut Decoder) -> Record {
    let mut buf = [0u8; 64 * 1024];
    loop {
        if let Some(record) = decoder.next().unwrap() {
            return record;
        }
        let n = link.read(&mut buf).await.unwrap();
        assert!(n > 0, "the client closed the link");
        decoder.push(&buf[..n]);
    }
}

/// The `DATA` bytes that come within `wait`, `want` bytes at most, and the
/// records of other kinds.
async fn data_within(
    far: &mut DuplexStream,
    decoder: &mut Decoder,
    want: usize,
    wait: Duration,
) -> (Vec<u8>, Vec<Record>) {
    let mut bytes = Vec::new();
    let mut others = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    while bytes.len() < want {
        let Ok(record) = tokio::time::timeout_at(deadline, read_record(far, decoder)).await else { break };
        match record {
            Record::Data { bytes: b, .. } => bytes.extend(b),
            other => others.push(other),
        }
    }
    (bytes, others)
}

/// The application writes 32 MiB to a far end that does not acknowledge:
/// the layer sends exactly the capacity, 4 MiB, and stops; each `ACK` frees
/// its bytes, and the rest follows, whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_buffer_makes_the_writer_wait_until_an_ack() {
    let (client, mut far, mut decoder) = scripted(&["replay.v1"]).await;
    let (app, app_end) = tokio::io::duplex(PIPE);
    let run = tokio::spawn(client.run(app_end));
    let sent = pseudo_random(32 * MIB, 23);
    let (_app_r, mut app_w) = tokio::io::split(app);
    let writer = {
        let sent = sent.clone();
        tokio::spawn(async move {
            app_w.write_all(&sent).await.unwrap();
            app_w
        })
    };

    let (mut received, _) = data_within(&mut far, &mut decoder, usize::MAX, Duration::from_secs(3)).await;
    assert_eq!(received.len(), 4 * MIB, "the writer stops at the capacity");
    let (more, _) = data_within(&mut far, &mut decoder, usize::MAX, Duration::from_millis(500)).await;
    assert_eq!(more.len(), 0, "and stays stopped with no ACK");

    far.write_all(&Record::Ack { offset: MIB as u64 }.to_bytes().unwrap()).await.unwrap();
    let (freed, _) = data_within(&mut far, &mut decoder, usize::MAX, Duration::from_secs(2)).await;
    assert_eq!(freed.len(), MIB, "an ACK of 1 MiB lets exactly 1 MiB more through");
    received.extend(freed);

    // Each ACK of all that came frees the whole buffer: the rest follows,
    // 4 MiB at a time, and nothing is lost or repeated.
    while received.len() < sent.len() {
        far.write_all(&Record::Ack { offset: received.len() as u64 }.to_bytes().unwrap()).await.unwrap();
        let want = (sent.len() - received.len()).min(4 * MIB);
        let (bytes, _) = data_within(&mut far, &mut decoder, want, Duration::from_secs(5)).await;
        assert_eq!(bytes.len(), want, "after an ACK at {}", received.len());
        received.extend(bytes);
    }
    assert_eq!(Sha256::digest(&received), Sha256::digest(&sent));
    drop(writer.await.unwrap());
    drop(far);
    let _ = tokio::time::timeout(LIMIT, run).await;
}

/// The receiver acknowledges each 64 KiB at once, and fewer bytes after
/// about 200 ms: not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acknowledgements_go_out_each_64_kib_and_after_200_ms() {
    let (client, mut far, mut decoder) = scripted(&["replay.v1"]).await;
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let run = tokio::spawn(client.run(app_end));

    // 64 KiB in two records: one record carries 65528 bytes at most.
    let half = ACK_EVERY as usize / 2;
    let mut block = Record::Data { offset: 0, bytes: vec![1; half] }.to_bytes().unwrap();
    block.extend(Record::Data { offset: half as u64, bytes: vec![1; half] }.to_bytes().unwrap());
    far.write_all(&block).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_millis(150), read_record(&mut far, &mut decoder)).await;
    assert_eq!(ack.expect("an ACK at once"), Record::Ack { offset: ACK_EVERY });

    let few = Record::Data { offset: ACK_EVERY, bytes: vec![2; 10] };
    far.write_all(&few.to_bytes().unwrap()).await.unwrap();
    let early = tokio::time::timeout(Duration::from_millis(80), read_record(&mut far, &mut decoder)).await;
    assert!(early.is_err(), "no ACK before the delay: {early:?}");
    let late = tokio::time::timeout(Duration::from_secs(2), read_record(&mut far, &mut decoder)).await;
    assert_eq!(late.expect("an ACK after the delay"), Record::Ack { offset: ACK_EVERY + 10 });

    let mut got = vec![0u8; ACK_EVERY as usize + 10];
    app.read_exact(&mut got).await.unwrap();
    drop(app);
    drop(far);
    let _ = tokio::time::timeout(LIMIT, run).await;
}

/// A far end that does not name `replay.v1` gets no buffer and no `ACK`: a
/// peer that does not acknowledge would fill it and stop the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_with_no_replay_gets_no_buffer_and_no_acks() {
    let (client, mut far, mut decoder) = scripted(&["heartbeat.v1"]).await;
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let run = tokio::spawn(client.run(app_end));
    far.write_all(&Record::Data { offset: 0, bytes: vec![1; 60_000] }.to_bytes().unwrap()).await.unwrap();
    let mut got = vec![0u8; 60_000];
    app.read_exact(&mut got).await.unwrap();
    // 6 MiB out with no ACK: more than a buffer would let through.
    let writer = tokio::spawn(async move {
        app.write_all(&vec![3; 6 * MIB]).await.unwrap();
        app
    });
    let (bytes, others) = data_within(&mut far, &mut decoder, 6 * MIB, Duration::from_secs(5)).await;
    assert_eq!(bytes.len(), 6 * MIB);
    // A late ACK would show in the half second after.
    let (_, late) = data_within(&mut far, &mut decoder, usize::MAX, Duration::from_millis(500)).await;
    assert!(others.is_empty() && late.is_empty(), "no ACK: {others:?} {late:?}");
    drop(writer.await.unwrap());
    drop(far);
    let _ = tokio::time::timeout(LIMIT, run).await;
}

#[test]
fn records_of_the_resume_are_cut_at_max_data() {
    let mut sender = Link::new(0, 0).with_replay(4 * MIB);
    sender.send(&pseudo_random(3 * MAX_DATA, 5), &mut Vec::new()).unwrap();
    let mut again = Vec::new();
    assert_eq!(sender.resume(10, &mut again), Ok(3 * MAX_DATA as u64 - 10));
    let sizes: Vec<(u64, usize)> = records(&again)
        .into_iter()
        .map(|r| match r {
            Record::Data { offset, bytes } => (offset, bytes.len()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(sizes.first(), Some(&(10, MAX_DATA)));
    assert_eq!(sizes.iter().map(|(_, n)| n).sum::<usize>(), 3 * MAX_DATA - 10);
}
