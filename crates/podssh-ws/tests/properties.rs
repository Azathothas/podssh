//! Properties of the WebSocket layer and of the sanitizer (T-202), each
//! checked on the inputs that proptest makes, 256 by default, and shrunk to
//! the smallest that fails: a frame read back from its bytes is the frame
//! that was written, and no shorter prefix of them is a frame; a message cut
//! into any fragments, its bytes cut into any reads, arrives whole, and one
//! past 16 MiB ends the session with a Close 1009; text made safe holds no
//! control and no bidirectional character, and made safe again stays the
//! same.
//!
//! A property that fails writes its input to
//! `tests/properties.proptest-regressions`, committed with the repair:
//! proptest tries those inputs first at each run.

use std::time::Duration;

use podssh_ws::frame::{self, decode, encode, Frame, Role, FORWARD_MAX_FRAME, MAX_CONTROL_PAYLOAD};
use podssh_ws::session::{close_code_and_reason, RelaySession, MAX_MESSAGE};
use podssh_ws::text::{multi_line, one_line};
use podssh_ws::SessionError;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// How long a read of the session may take.
const LIMIT: Duration = Duration::from_secs(30);

/// proptest's settings, 256 inputs unless `PROPTEST_CASES` says otherwise,
/// and a failing input kept beside this file.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    }
}

/// Bytes from a fixed xorshift: a long payload that costs little to make.
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

/// A payload: short ones of any bytes, and long ones near the lengths where
/// the length field changes (125, 126, 65535, 65536), near the forward cap,
/// and of any length up to it.
fn payload() -> impl Strategy<Value = Vec<u8>> {
    let long =
        prop_oneof![120usize..=131, 65_530usize..=65_541, 262_134usize..=FORWARD_MAX_FRAME, 0usize..=FORWARD_MAX_FRAME];
    prop_oneof![
        3 => vec(any::<u8>(), 0..=300),
        1 => (long, any::<u32>()).prop_map(|(len, seed)| pseudo_random(len, seed)),
    ]
}

/// A frame that RFC 6455 allows: a data frame with or without FIN, or a
/// control frame with FIN, 125 bytes or less, and never a Close of 1 byte.
fn frame() -> impl Strategy<Value = Frame> {
    let opcode = prop::sample::select(vec![0x0u8, 0x1, 0x2, 0x8, 0x9, 0xa]);
    (opcode, any::<bool>(), payload()).prop_map(|(opcode, fin, mut payload)| {
        if opcode < frame::OPCODE_CLOSE {
            return Frame { fin, opcode, payload };
        }
        payload.truncate(MAX_CONTROL_PAYLOAD);
        if opcode == frame::OPCODE_CLOSE && payload.len() == 1 {
            payload.clear();
        }
        Frame { fin: true, opcode, payload }
    })
}

fn role() -> impl Strategy<Value = Role> {
    prop_oneof![Just(Role::Client), Just(Role::Server)]
}

proptest! {
    #![proptest_config(config())]

    /// `decode(encode(f))` gives `f` and uses each byte; each shorter
    /// prefix is a frame not yet whole; bytes after the frame stay unread.
    #[test]
    fn a_frame_reads_back_whole_and_no_prefix_is_a_frame(
        f in frame(),
        role in role(),
        key in any::<[u8; 4]>(),
        tail in vec(any::<u8>(), 0..8),
    ) {
        let bytes = encode(&f, role, key);
        let (back, used) = decode(&bytes, role).expect("a frame that RFC 6455 allows").expect("a whole frame");
        prop_assert_eq!(&back, &f);
        prop_assert_eq!(used, bytes.len());
        for end in 0..bytes.len() {
            prop_assert!(matches!(decode(&bytes[..end], role), Ok(None)), "the first {} of {} bytes", end, bytes.len());
        }
        let mut more = bytes.clone();
        more.extend_from_slice(&tail);
        let (again, used) = decode(&more, role).expect("a frame").expect("a whole frame");
        prop_assert_eq!(again, f);
        prop_assert_eq!(used, bytes.len());
    }

    /// A control frame that is cut, longer than 125 bytes, or a Close of 1
    /// byte is refused; each other control frame is read.
    #[test]
    fn a_control_frame_that_rfc_6455_forbids_is_refused(
        opcode in prop::sample::select(vec![0x8u8, 0x9, 0xa]),
        len in 0usize..=300,
        fin in any::<bool>(),
        role in role(),
        key in any::<[u8; 4]>(),
    ) {
        let allowed = fin && len <= MAX_CONTROL_PAYLOAD && !(opcode == frame::OPCODE_CLOSE && len == 1);
        let bytes = encode(&Frame { fin, opcode, payload: vec![7; len] }, role, key);
        let got = decode(&bytes, role);
        prop_assert_eq!(got.is_ok(), allowed, "opcode {:#x}, {} bytes, FIN {}: {:?}", opcode, len, fin, got.err());
    }

    /// A message cut into any fragments, with a Ping between them or none,
    /// and its bytes cut into any writes, arrives whole; each Ping is
    /// answered with its payload.
    #[test]
    fn a_message_cut_into_any_fragments_arrives_whole(
        text in any::<bool>(),
        len in prop_oneof![0usize..=2_000, 0usize..=3 * FORWARD_MAX_FRAME + 10],
        seed in any::<u32>(),
        cuts in vec(any::<usize>(), 0..12),
        writes in vec(1usize..=70_000, 1..6),
        pings in any::<bool>(),
    ) {
        let opcode = if text { frame::OPCODE_TEXT } else { frame::OPCODE_BINARY };
        let payload = pseudo_random(len, seed);
        let cut = pieces(len, &cuts);
        let (wire, sent) = relay_frames(opcode, &payload, &cut, pings);
        let (got, pongs) = block_on(through_a_session(wire, writes, sent.len()));
        let got = got.map_err(|e| TestCaseError::fail(format!("{len} bytes in {} pieces: {e}", cut.len())))?;
        prop_assert_eq!((got.fin, got.opcode), (true, opcode));
        prop_assert!(got.payload == payload, "{} bytes in {} pieces came back as {}", len, cut.len(), got.payload.len());
        prop_assert!(pongs.iter().all(|f| f.opcode == frame::OPCODE_PONG), "{:?}", pongs);
        prop_assert_eq!(pongs.into_iter().map(|f| f.payload).collect::<Vec<_>>(), sent);
    }

    /// `one_line` leaves no control and no bidirectional character, no
    /// space but U+0020, none at either end and never two together; and a
    /// second pass changes nothing.
    #[test]
    fn one_line_leaves_one_line_and_a_second_pass_changes_nothing(text in hostile()) {
        let safe = one_line(&text);
        prop_assert!(!safe.chars().any(|c| c.is_control() || BIDI.contains(&c)), "{:?} gave {:?}", text, safe);
        prop_assert!(!safe.chars().any(|c| c.is_whitespace() && c != ' '), "{:?} gave {:?}", text, safe);
        prop_assert!(!safe.contains("  ") && !safe.starts_with(' ') && !safe.ends_with(' '), "{:?} gave {:?}", text, safe);
        prop_assert_eq!(one_line(&safe), safe);
    }

    /// `multi_line` leaves LF and TAB of the controls, and no bidirectional
    /// character; and a second pass changes nothing.
    #[test]
    fn multi_line_leaves_lines_and_a_second_pass_changes_nothing(text in hostile()) {
        let safe = multi_line(&text);
        let bad = |c: char| (c.is_control() && c != '\n' && c != '\t') || BIDI.contains(&c);
        prop_assert!(!safe.chars().any(bad), "{:?} gave {:?}", text, safe);
        prop_assert_eq!(multi_line(&safe), safe);
    }
}

proptest! {
    // Each input moves more than 16 MiB through the session: four of them,
    // as 256 would hold the gate for minutes.
    #![proptest_config(ProptestConfig { cases: 4, ..config() })]

    /// A message past 16 MiB, in any fragments, ends the session with a
    /// Close 1009, and the read says why.
    #[test]
    fn a_message_past_16_mib_in_any_fragments_ends_the_session_with_1009(
        extra in 1usize..=FORWARD_MAX_FRAME,
        cuts in vec(any::<usize>(), 0..16),
        writes in vec(1usize..=300_000, 1..4),
    ) {
        let len = MAX_MESSAGE + extra;
        let cut = pieces(len, &cuts);
        let (wire, _) = relay_frames(frame::OPCODE_BINARY, &vec![0; len], &cut, false);
        let (got, back) = block_on(through_a_session(wire, writes, 1));
        match got {
            Err(SessionError::TooLarge(why)) => prop_assert!(why.contains("exceeded 16777216 bytes"), "{}", why),
            other => prop_assert!(false, "{} pieces gave {:?}", cut.len(), other.map(|f| f.payload.len())),
        }
        prop_assert_eq!(back[0].opcode, frame::OPCODE_CLOSE);
        prop_assert_eq!(close_code_and_reason(&back[0].payload).0, Some(1009));
    }
}

/// The bidirectional controls that the sanitizer drops.
const BIDI: [char; 12] = [
    '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}',
    '\u{2067}', '\u{2068}', '\u{2069}',
];

/// Text as a hostile peer writes it: many controls, bidirectional
/// characters and spaces of each kind among letters, and any character
/// besides.
fn hostile() -> impl Strategy<Value = String> {
    let controls = vec![
        '\x1b', '\x07', '\x08', '\r', '\n', '\t', '\x0b', '\x0c', '\x7f', '\0', '\u{85}', '\u{9b}', '\u{9c}', '\u{a0}',
        '\u{2028}', '\u{3000}',
    ];
    let piece = prop_oneof![
        2 => any::<char>(),
        2 => prop::sample::select(controls),
        1 => prop::sample::select(BIDI.to_vec()),
        3 => prop::sample::select(vec!['a', 'b', ' ', '[', '3', '1', 'm', '\u{e9}', '\u{4e2d}']),
    ];
    vec(piece, 0..64).prop_map(|chars| chars.into_iter().collect())
}

/// The bounds of the pieces of `len` bytes cut at `cuts`, each taken modulo
/// `len + 1`, in order, each at most the forward cap. A message of no bytes
/// is one piece of none.
fn pieces(len: usize, cuts: &[usize]) -> Vec<(usize, usize)> {
    let mut at: Vec<usize> = cuts.iter().map(|c| c % (len + 1)).filter(|&c| c > 0 && c < len).collect();
    at.extend([0, len]);
    at.sort_unstable();
    at.dedup();
    let mut out = Vec::new();
    for pair in at.windows(2) {
        let (mut start, end) = (pair[0], pair[1]);
        while end - start > FORWARD_MAX_FRAME {
            out.push((start, start + FORWARD_MAX_FRAME));
            start += FORWARD_MAX_FRAME;
        }
        out.push((start, end));
    }
    if out.is_empty() {
        out.push((0, 0));
    }
    out
}

/// The relay's frames of one message, unmasked: `payload` in `pieces`, the
/// first with `opcode` and each after it a continuation, FIN on the last;
/// with `pings`, a Ping before each piece after the first. The payload of
/// each Ping, in order.
fn relay_frames(opcode: u8, payload: &[u8], pieces: &[(usize, usize)], pings: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
    let (mut wire, mut sent) = (Vec::new(), Vec::new());
    for (i, &(start, end)) in pieces.iter().enumerate() {
        if pings && i > 0 {
            let ping = Frame { fin: true, opcode: frame::OPCODE_PING, payload: (i as u32).to_be_bytes().to_vec() };
            wire.extend(encode(&ping, Role::Server, [0; 4]));
            sent.push(ping.payload);
        }
        let opcode = if i == 0 { opcode } else { frame::OPCODE_CONTINUATION };
        let piece = Frame { fin: i + 1 == pieces.len(), opcode, payload: payload[start..end].to_vec() };
        wire.extend(encode(&piece, Role::Server, [0; 4]));
    }
    (wire, sent)
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime").block_on(future)
}

/// `wire`, written by a stand-in relay in writes of the sizes of `writes`
/// in turn, and read by a session: what `read_frame` gave, and the first
/// `n` frames that the session sent back.
async fn through_a_session(wire: Vec<u8>, writes: Vec<usize>, n: usize) -> (Result<Frame, SessionError>, Vec<Frame>) {
    let (stream, peer) = tokio::io::duplex(64 * 1024);
    let session = RelaySession::new(stream, Vec::new(), None, Duration::from_secs(5));
    let (mut from_session, mut to_session) = tokio::io::split(peer);
    let writer = tokio::spawn(async move {
        let mut at = 0;
        for size in writes.iter().cycle() {
            let end = (at + size).min(wire.len());
            if at == end || to_session.write_all(&wire[at..end]).await.is_err() {
                break;
            }
            at = end;
        }
        // The write half stays, so that the stream does not end.
        to_session
    });
    let got = tokio::time::timeout(LIMIT, session.read_frame()).await.expect("the read within the limit");
    let back = frames_from(&mut from_session, n).await;
    writer.abort();
    (got, back)
}

/// The first `n` frames that the session wrote, masked as a client's.
async fn frames_from<R: AsyncRead + Unpin>(from_session: &mut R, n: usize) -> Vec<Frame> {
    let (mut buf, mut out) = (Vec::new(), Vec::new());
    while out.len() < n {
        if let Some((f, used)) = decode(&buf, Role::Client).expect("a frame that podssh wrote") {
            buf.drain(..used);
            out.push(f);
            continue;
        }
        let mut chunk = [0u8; 4096];
        let read = tokio::time::timeout(LIMIT, from_session.read(&mut chunk)).await.expect("a frame within the limit");
        let count = read.expect("the stream");
        assert!(count > 0, "the session closed the stream");
        buf.extend_from_slice(&chunk[..count]);
    }
    out
}
