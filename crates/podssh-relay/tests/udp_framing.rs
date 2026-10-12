//! UDP in a stream (T-168): the framing, byte for byte, and one flow to a
//! UDP target on the loopback. Each datagram is its length in two bytes,
//! big-endian, then its bytes; a length over 65,507 is refused; a datagram
//! stays whole however the stream's bytes are cut, and two datagrams stay
//! two. A flow carries each datagram to its target and each reply back,
//! and ends after its idle limit.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_relay::udp::flow::{self, FlowEnd};
use podssh_relay::udp::{encode, framed, Decoder, FrameError, Frames, MAX_DATAGRAM};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

/// A DNS query for `example.org`, type A, written out: the shape of the
/// traffic that this road is for.
const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03org\x00\x00\x01\x00\x01";

/// Three datagrams, framed by hand: `abc`, an empty one, and one byte.
const THREE: &[u8] = b"\x00\x03abc\x00\x00\x00\x01\xff";

fn decode_all(decoder: &mut Decoder) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(datagram) = decoder.next_datagram().expect("the framing") {
        out.push(datagram);
    }
    out
}

#[test]
fn fixed_bytes_decode_to_their_datagrams() {
    let mut decoder = Decoder::new();
    decoder.push(THREE);
    assert_eq!(decode_all(&mut decoder), vec![b"abc".to_vec(), Vec::new(), vec![0xff]]);
    assert_eq!(decoder.pending(), 0);
    // The query: its length, 29, then its bytes.
    let mut decoder = Decoder::new();
    let mut bytes = vec![0x00, 0x1d];
    bytes.extend_from_slice(QUERY);
    decoder.push(&bytes);
    assert_eq!(QUERY.len(), 29);
    assert_eq!(decode_all(&mut decoder), vec![QUERY.to_vec()]);
}

#[test]
fn a_datagram_is_framed_as_its_length_then_its_bytes() {
    let mut expected = vec![0x00, 0x1d];
    expected.extend_from_slice(QUERY);
    assert_eq!(framed(QUERY).unwrap(), expected);
    assert_eq!(framed(b"").unwrap(), vec![0x00, 0x00]);
    let mut out = Vec::new();
    for datagram in [&b"abc"[..], b"", b"\xff"] {
        assert!(encode(datagram, &mut out));
    }
    assert_eq!(out, THREE);
}

#[test]
fn a_datagram_too_long_for_udp_is_not_framed_and_the_longest_is() {
    let longest = vec![7u8; MAX_DATAGRAM];
    let bytes = framed(&longest).expect("65,507 bytes are one datagram");
    assert_eq!(&bytes[..2], b"\xff\xe3");
    assert_eq!(bytes.len(), 2 + MAX_DATAGRAM);
    assert!(framed(&vec![7u8; MAX_DATAGRAM + 1]).is_none());
    let mut out = b"kept".to_vec();
    assert!(!encode(&vec![7u8; MAX_DATAGRAM + 1], &mut out));
    assert_eq!(out, b"kept", "nothing is appended for a datagram that is dropped");
}

#[test]
fn a_length_over_65507_is_refused_as_soon_as_it_is_read() {
    let mut decoder = Decoder::new();
    decoder.push(b"\xff\xe4");
    assert_eq!(decoder.next_datagram(), Err(FrameError::TooLong(65_508)));
    let mut decoder = Decoder::new();
    decoder.push(b"\xff\xff\x00");
    assert_eq!(decoder.next_datagram(), Err(FrameError::TooLong(65_535)));
    // 65,507 is a length that waits for its bytes.
    let mut decoder = Decoder::new();
    decoder.push(b"\xff\xe3\x00");
    assert_eq!(decoder.next_datagram(), Ok(None));
    assert_eq!(decoder.pending(), 3);
}

#[test]
fn each_datagram_stays_whole_across_split_reads() {
    let datagrams: Vec<Vec<u8>> =
        vec![QUERY.to_vec(), Vec::new(), vec![0xa5; 300], vec![1], (0..=255u8).cycle().take(4000).collect()];
    let mut stream = Vec::new();
    for d in &datagrams {
        assert!(encode(d, &mut stream));
    }
    // Every cut: one byte at a time, and pieces of 2, 3, 7 and 1000 bytes.
    for step in [1, 2, 3, 7, 1000, stream.len()] {
        let mut decoder = Decoder::new();
        let mut got = Vec::new();
        for piece in stream.chunks(step) {
            decoder.push(piece);
            got.extend(decode_all(&mut decoder));
        }
        assert_eq!(got, datagrams, "cut in pieces of {step}");
        assert_eq!(decoder.pending(), 0);
    }
}

/// The check that a decoder which joins two datagrams fails: both come in
/// one push, and two must come out.
#[test]
fn two_datagrams_in_one_read_stay_two() {
    let mut decoder = Decoder::new();
    decoder.push(b"\x00\x02hi\x00\x02yo");
    assert_eq!(decoder.next_datagram(), Ok(Some(b"hi".to_vec())));
    assert_eq!(decoder.next_datagram(), Ok(Some(b"yo".to_vec())));
    assert_eq!(decoder.next_datagram(), Ok(None));
}

/// A reader that gives at most `step` bytes at each read.
struct Trickle {
    bytes: Vec<u8>,
    at: usize,
    step: usize,
}

impl AsyncRead for Trickle {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let n = self.step.min(self.bytes.len() - self.at).min(buf.remaining());
        let at = self.at;
        buf.put_slice(&self.bytes[at..at + n]);
        self.at += n;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn frames_read_each_datagram_whole_from_a_stream_that_trickles() {
    let mut bytes = THREE.to_vec();
    assert!(encode(QUERY, &mut bytes));
    for step in [1, 2, 5] {
        let mut frames = Frames::new(Trickle { bytes: bytes.clone(), at: 0, step });
        let mut got = Vec::new();
        while let Some(datagram) = frames.recv().await.unwrap() {
            got.push(datagram);
        }
        assert_eq!(got, vec![b"abc".to_vec(), Vec::new(), vec![0xff], QUERY.to_vec()], "pieces of {step}");
    }
}

#[tokio::test]
async fn a_stream_that_ends_inside_a_datagram_or_is_not_the_framing_is_an_error() {
    let mut frames = Frames::new(Trickle { bytes: b"\x00\x05abc".to_vec(), at: 0, step: 64 });
    let e = frames.recv().await.unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "{e}");
    let mut frames = Frames::new(Trickle { bytes: b"\x00\x01a\xff\xff".to_vec(), at: 0, step: 64 });
    assert_eq!(frames.recv().await.unwrap(), Some(b"a".to_vec()));
    let e = frames.recv().await.unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
    assert!(e.to_string().contains("65535"), "{e}");
}

/// A UDP server on the loopback that answers each datagram as a DNS server
/// answers a query: the same bytes with the QR bit set. Its port.
async fn answering_server() -> u16 {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        while let Ok((n, from)) = server.recv_from(&mut buf).await {
            let mut answer = buf[..n].to_vec();
            if answer.len() > 2 {
                answer[2] |= 0x80;
            }
            let _ = server.send_to(&answer, from).await;
        }
    });
    port
}

fn answer_to(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    answer[2] |= 0x80;
    answer
}

#[tokio::test]
async fn a_flow_carries_each_datagram_to_its_target_and_each_answer_back() {
    let port = answering_server().await;
    let socket = flow::connect("127.0.0.1", port, Duration::from_secs(5)).await.expect("a UDP socket on the loopback");
    let (near, far) = tokio::io::duplex(64 * 1024);
    let carried = tokio::spawn(flow::carry(far, socket, flow::IDLE));
    let (read, mut write) = tokio::io::split(near);
    let mut frames = Frames::new(read);
    let queries: Vec<Vec<u8>> = (0..5u8)
        .map(|i| {
            let mut q = QUERY.to_vec();
            q[1] = i;
            q
        })
        .collect();
    for q in &queries {
        write.write_all(&framed(q).unwrap()).await.unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(10), frames.recv()).await.expect("an answer").unwrap();
        assert_eq!(answer, Some(answer_to(q)));
    }
    // The end of the stream ends the flow, and the near side reads its end.
    write.shutdown().await.unwrap();
    let carried = tokio::time::timeout(Duration::from_secs(10), carried).await.expect("the flow ends").unwrap();
    assert_eq!(carried.end, FlowEnd::Closed);
    assert_eq!((carried.sent, carried.received, carried.dropped), (5, 5, 0));
    assert_eq!(frames.recv().await.unwrap(), None);
}

#[tokio::test]
async fn a_flow_with_no_datagram_ends_after_its_idle_limit() {
    let port = answering_server().await;
    let socket = flow::connect("127.0.0.1", port, Duration::from_secs(5)).await.unwrap();
    let (near, far) = tokio::io::duplex(1024);
    let started = std::time::Instant::now();
    let carried = tokio::time::timeout(Duration::from_secs(10), flow::carry(far, socket, Duration::from_millis(300)))
        .await
        .expect("the flow ends by itself");
    assert_eq!(carried.end, FlowEnd::Idle);
    assert!(started.elapsed() >= Duration::from_millis(300));
    // Its stream got the end.
    let mut rest = Vec::new();
    let (mut read, _write) = tokio::io::split(near);
    read.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn a_flow_whose_stream_is_not_the_framing_ends_and_says_so() {
    let port = answering_server().await;
    let socket = flow::connect("127.0.0.1", port, Duration::from_secs(5)).await.unwrap();
    let (mut near, far) = tokio::io::duplex(1024);
    let carried = tokio::spawn(flow::carry(far, socket, flow::IDLE));
    near.write_all(b"\xff\xffnot a datagram").await.unwrap();
    let carried = tokio::time::timeout(Duration::from_secs(10), carried).await.expect("the flow ends").unwrap();
    assert!(matches!(carried.end, FlowEnd::Framing(_)), "{:?}", carried.end);
    assert!(carried.note().unwrap().contains("not the framing"), "{:?}", carried.note());
    assert_eq!(carried.sent, 0, "nothing of a broken stream goes out");
}

#[tokio::test]
async fn the_probe_sends_nothing_and_names_the_address() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    let addr = flow::probe("127.0.0.1", port, Duration::from_secs(5)).await.expect("UDP on the loopback");
    assert_eq!(addr, server.local_addr().unwrap());
    let mut buf = [0u8; 16];
    let nothing = tokio::time::timeout(Duration::from_millis(300), server.recv_from(&mut buf)).await;
    assert!(nothing.is_err(), "the probe sent a datagram");
}
