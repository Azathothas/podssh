//! The record of a handshake (T-588): each direction read as it passes, the
//! words of each case, the time of the host key's question left out of the
//! limit, and the first word 10 s in.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::options::LogLevel;

/// OpenSSH 10.0p2's version line, as its sshd writes it with no addendum:
/// `SSH-%d.%d-%.100s` of SSH_RELEASE, then CR LF.
const OPENSSH: &[u8] = b"SSH-2.0-OpenSSH_10.0p2\r\n";

/// A binary packet of RFC 4253, section 6, with no encryption: its length,
/// its padding's length, the message number and `body` more bytes of
/// payload, and padding to a multiple of 8, 4 bytes at least.
fn packet(number: u8, body: usize) -> Vec<u8> {
    let mut padding = 8 - (6 + body) % 8;
    if padding < 4 {
        padding += 8;
    }
    let length = (2 + body + padding) as u32;
    let mut out = length.to_be_bytes().to_vec();
    out.push(padding as u8);
    out.push(number);
    out.resize(out.len() + body, 0x41);
    out.resize(out.len() + padding, 0);
    out
}

fn wait<'a>(limit: u64, road: Option<&'a Road>, log: &'a Log) -> Wait<'a> {
    Wait { label: "node://lab", limit: Duration::from_secs(limit), road, log }
}

fn node_road(channel: bool) -> Road {
    Road { far: "the node's TARGET".into(), end: "the node".into(), flow: Arc::new(Flow::default()), channel }
}

/// The version line, then the server's packets up to NEWKEYS, after which
/// the bytes are counted and not read.
#[test]
fn a_version_line_then_packets_are_read_to_newkeys() {
    let mut side = Side::default();
    side.feed(OPENSSH);
    assert_eq!(side.version.as_deref(), Some("SSH-2.0-OpenSSH_10.0p2"));
    assert_eq!(side.last, None);
    side.feed(&packet(20, 1100));
    assert_eq!(side.last, Some(20));
    side.feed(&[packet(31, 1200), packet(21, 0)].concat());
    assert_eq!(side.last, Some(21));
    assert!(side.sealed(), "after NEWKEYS");
    // Encrypted bytes that would read as a packet of number 2 are not read.
    side.feed(&packet(2, 10));
    assert_eq!(side.last, Some(21));
    let packets = [packet(20, 1100), packet(31, 1200), packet(21, 0), packet(2, 10)];
    let all = OPENSSH.len() + packets.iter().map(Vec::len).sum::<usize>();
    assert_eq!(side.bytes, all as u64);
}

/// One byte at a time reads as one write of all.
#[test]
fn a_handshake_split_byte_by_byte_reads_the_same() {
    let bytes = [OPENSSH.to_vec(), packet(20, 300), packet(30, 32)].concat();
    let mut side = Side::default();
    for byte in &bytes {
        side.feed(std::slice::from_ref(byte));
    }
    assert_eq!(side.version.as_deref(), Some("SSH-2.0-OpenSSH_10.0p2"));
    assert_eq!(side.last, Some(30));
    assert_eq!(side.step(), "KEX_ECDH_INIT");
}

/// Another service's answer: its first line is kept, and no version line.
#[test]
fn another_service_s_first_line_is_kept() {
    let mut side = Side::default();
    side.feed(b"\r\nHTTP/1.1 400 Bad Request\r\nServer: x\r\n\r\n");
    assert_eq!(side.version, None);
    assert_eq!(side.other.as_deref(), Some("HTTP/1.1 400 Bad Request"));
    // RFC 4253 lets a server send lines before its version line.
    side.feed(OPENSSH);
    assert_eq!(side.version.as_deref(), Some("SSH-2.0-OpenSSH_10.0p2"));
}

/// A length that no packet of a key exchange has stops the reading, and
/// the bytes are still counted.
#[test]
fn a_length_that_is_no_packet_stops_the_reading() {
    let mut side = Side::default();
    side.feed(OPENSSH);
    side.feed(&[0xff, 0xff, 0xff, 0xff, 4, 20, 1, 2, 3]);
    assert_eq!(side.last, None);
    side.feed(&packet(20, 100));
    assert_eq!(side.last, None, "no packet is read after bytes that were none");
    assert_eq!(side.step(), "version line");
}

/// The stream between russh and the road records each way, and changes no
/// byte.
#[tokio::test]
async fn the_watched_stream_records_each_way() {
    let record = Record::default();
    let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
    let mut watched = record.watch(ours);
    watched.write_all(b"SSH-2.0-podssh_1\r\n").await.unwrap();
    watched.write_all(&packet(20, 500)).await.unwrap();
    theirs.write_all(OPENSSH).await.unwrap();
    let mut got = vec![0u8; OPENSSH.len()];
    watched.read_exact(&mut got).await.unwrap();
    assert_eq!(got, OPENSSH);
    let mut sent = vec![0u8; 18];
    theirs.read_exact(&mut sent).await.unwrap();
    assert_eq!(sent, b"SSH-2.0-podssh_1\r\n");
    let log = Log::new(LogLevel::Quiet);
    let line = Wait { label: "h", limit: Duration::from_secs(3), road: None, log: &log }.timed_out(&record);
    assert_eq!(
        line,
        "h: the SSH handshake did not finish within 3 s: SSH-2.0-OpenSSH_10.0p2 came, then nothing after this side's \
         KEXINIT"
    );
}

/// The words of each case, one form for each.
#[test]
fn each_case_has_its_words() {
    let log = Log::new(LogLevel::Quiet);
    let at = |feed: &[&[u8]]| {
        let record = Record::default();
        for bytes in feed {
            record.feed(true, bytes);
        }
        record.feed(false, &[b"SSH-2.0-podssh_1\r\n".to_vec(), packet(20, 400), packet(30, 32)].concat());
        wait(25, None, &log).timed_out(&record)
    };
    let head = "node://lab: the SSH handshake did not finish within 25 s: ";
    assert_eq!(at(&[]), format!("{head}no byte came from the server"));
    assert_eq!(
        at(&[b"HTTP/1.1 400 Bad Request\r\n".as_slice()]),
        format!(
            "{head}26 bytes came from the server, with no SSH version line: the first line was \"HTTP/1.1 400 Bad \
             Request\""
        )
    );
    assert_eq!(
        at(&[b"\x16\x03\x01".as_slice()]),
        format!("{head}3 bytes came from the server, with no end of a line and no SSH version line")
    );
    let kexinit = packet(20, 1000);
    assert_eq!(
        at(&[OPENSSH, kexinit.as_slice()]),
        format!(
            "{head}SSH-2.0-OpenSSH_10.0p2 came; the last messages were the server's KEXINIT and this side's \
             KEX_ECDH_INIT"
        )
    );
}

/// On a node's road: a layer that never opened, and the bytes of the layer
/// and of the channel each way, with and without the channel.
#[test]
fn a_node_s_road_names_its_layer_and_its_channel() {
    let log = Log::new(LogLevel::Quiet);
    let road = node_road(true);
    let record = Record::default();
    let head = "node://lab: the SSH handshake did not finish within 25 s: ";
    assert_eq!(
        wait(25, Some(&road), &log).timed_out(&record),
        format!("{head}the resumable layer to the node did not open")
    );
    let mut layer = Counted::new(Vec::<u8>::new(), Some(road.flow.clone()));
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(Pin::new(&mut layer).poll_write(&mut cx, &[0u8; 96]), Poll::Ready(Ok(96))));
    record.feed(false, b"SSH-2.0-podssh_1\r\n");
    assert_eq!(
        wait(25, Some(&road), &log).timed_out(&record),
        format!(
            "{head}no byte came from the node's TARGET after the layer opened (through the layer: 96 bytes from the \
             node, 0 to it; through the end-to-end channel: 0 from it, 18 to it)"
        )
    );
    let plain = Road { channel: false, ..road.clone() };
    assert!(wait(25, Some(&plain), &log)
        .timed_out(&record)
        .ends_with("(through the layer: 96 bytes from the node, 0 to it)"));
}

/// A counted stream marks the layer's open at its first poll, and counts
/// each way; with no flow it counts nothing.
#[tokio::test]
async fn a_counted_stream_counts_each_way() {
    let flow = Arc::new(Flow::default());
    let (ours, mut theirs) = tokio::io::duplex(1024);
    let mut layer = Counted::new(ours, Some(flow.clone()));
    assert_eq!(flow.opened(), None);
    layer.write_all(b"from the node").await.unwrap();
    assert!(flow.opened().is_some());
    theirs.write_all(b"to it").await.unwrap();
    let mut got = [0u8; 5];
    layer.read_exact(&mut got).await.unwrap();
    assert_eq!(flow.carried(), (13, 5));
    let mut none = Counted::new(Vec::<u8>::new(), None);
    none.write_all(b"x").await.unwrap();
    assert_eq!(flow.carried(), (13, 5));
}

/// The time of the host key's question does not count: 1 s, a question of
/// 10 s, then 1 s more, within a limit of 3 s; the same 12 s with no
/// question run out at 3 s.
#[tokio::test(start_paused = true)]
async fn the_time_of_the_host_key_s_question_does_not_count() {
    let log = Log::new(LogLevel::Quiet);
    let record = Record::default();
    let asked = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        record.question(true);
        tokio::time::sleep(Duration::from_secs(10)).await;
        record.question(false);
        tokio::time::sleep(Duration::from_secs(1)).await;
        7
    };
    assert_eq!(wait(3, None, &log).run(&record, asked).await, Ok(7));
    let plain = Record::default();
    let started = Instant::now();
    let unasked = tokio::time::sleep(Duration::from_secs(12));
    let out = wait(3, None, &log).run(&plain, unasked).await;
    assert_eq!(
        out,
        Err("node://lab: the SSH handshake did not finish within 3 s: no byte came from the server".into())
    );
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(3) && took < Duration::from_secs(4), "{took:?}");
}

/// A question inside a check of a host key is marked on its handshake while
/// it asks; outside a check it marks nothing.
#[test]
fn a_question_inside_a_check_is_marked_on_its_handshake() {
    let record = Record::default();
    assert!(checking(&record, || asking(|| record.asking())));
    assert!(!record.asking(), "the answer came");
    assert!(!asking(|| record.asking()));
}

/// The first word, while the question waits: with nobody to see it, the
/// remedy; with a person at the terminal, nothing.
#[test]
fn the_first_word_of_a_question_names_the_remedy_when_nobody_sees_it() {
    let log = Log::new(LogLevel::Quiet);
    let record = Record::default();
    record.question(true);
    let said = wait(25, None, &log).early(&record, true).expect("a line with nobody at the terminal");
    assert!(
        said.starts_with("node://lab: the SSH handshake waits for the answer to the question of the host key"),
        "{said}"
    );
    assert!(said.contains("within 60 s") && said.contains("StrictHostKeyChecking=accept-new"), "{said}");
    assert_eq!(wait(25, None, &log).early(&record, false), None, "a person sees the question");
}

/// The first word comes 10 s after a node's layer opened, once, and the
/// wait goes on: here the layer opens at 4 s, and the line comes at 14 s.
#[tokio::test(start_paused = true)]
async fn the_first_word_comes_10_s_after_the_layer_opened() {
    let path = std::env::temp_dir().join(format!("podssh-first-word-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let log = Log::to_file(LogLevel::Info, &path).unwrap();
    let road = node_road(true);
    let record = Record::default();
    let read = || std::fs::read_to_string(&path).unwrap_or_default();
    let opens = async {
        tokio::time::sleep(Duration::from_secs(4)).await;
        road.flow.open();
    };
    let looks = async {
        tokio::time::sleep(Duration::from_secs(12)).await;
        let at_12 = read();
        tokio::time::sleep(Duration::from_secs(8)).await;
        (at_12, read())
    };
    let never = std::future::pending::<()>();
    let waiting = wait(60, Some(&road), &log);
    let waited = tokio::time::timeout(Duration::from_secs(30), waiting.run(&record, never));
    let (waited, (), (at_12, at_20)) = tokio::join!(waited, opens, looks);
    assert!(waited.is_err(), "the limit is 60 s");
    assert_eq!(at_12, "", "10 s after the start, the layer had been open 8 s");
    assert_eq!(
        at_20,
        "podssh: node://lab: the SSH handshake has not finished after 10 s: no byte came from the node's TARGET after \
         the layer opened (through the layer: 0 bytes from the node, 0 to it; through the end-to-end channel: 0 from \
         it, 0 to it); it waits until ConnectTimeout, 60 s\n"
    );
    assert_eq!(read().lines().count(), 1, "once");
    let _ = std::fs::remove_file(&path);
}
