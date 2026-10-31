//! The carrier of an IAP session (T-351) against a stand-in of IAP's relay,
//! over links in memory, so that no test listens. The stand-in writes each
//! message by hand, as gcloud's and IAP Desktop's sources lay them out, and
//! reads the client's frames:
//! a session carries bytes both ways in messages of 16 KiB at most and
//! acknowledges what came; a lost link is taken up on a new one at the
//! bytes that each side has, and what the server did not take goes again;
//! a Close or silence before the session is named; a bad acknowledgement
//! ends the session; the end of SSH's input sends a Close, and the server's
//! last bytes still arrive.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use super::*;
use crate::frame::{self as wsf, Frame, Role};
use crate::iap::{session, upgrade, Target};

const TOKEN: &str = "TEST-TOKEN-NOT-A-CREDENTIAL";
const SHORT: Duration = Duration::from_secs(5);
/// Room in each direction of a link, as a socket's buffers give a TCP one.
const ROOM: usize = 1 << 20;

/// Where each dial hands the stand-in its end of a new link.
type Board = UnboundedSender<DuplexStream>;
type Links = UnboundedReceiver<DuplexStream>;

fn switchboard() -> (Board, Links) {
    unbounded_channel()
}

/// The stand-in's end of one link: the upgraded stream, the head of the
/// client's request, and the bytes read past the last frame.
struct Peer {
    link: DuplexStream,
    head: String,
    buf: Vec<u8>,
}

impl Peer {
    /// The next link that the client dials, answered with a 101.
    async fn accept(links: &mut Links) -> Peer {
        let mut link = links.recv().await.expect("a link that the client dials");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            link.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap().trim().to_string();
        let answer = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: relay.tunnel.cloudproxy.app\r\n\r\n",
            crate::handshake::accept_key(&key)
        );
        link.write_all(answer.as_bytes()).await.unwrap();
        Peer { link, head, buf: Vec::new() }
    }

    fn path(&self) -> &str {
        self.head.split_whitespace().nth(1).unwrap()
    }

    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        let f = Frame { fin: true, opcode, payload: payload.to_vec() };
        self.link.write_all(&wsf::encode(&f, Role::Server, [0; 4])).await.unwrap();
    }

    async fn message(&mut self, bytes: &[u8]) {
        self.send(wsf::OPCODE_BINARY, bytes).await;
    }

    /// The client's next frame, or `None` at the end of its stream.
    async fn frame(&mut self) -> Option<Frame> {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            if let Some((f, used)) = wsf::decode(&self.buf, Role::Client).unwrap() {
                self.buf.drain(..used);
                return Some(f);
            }
            let n = self.link.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// IAP's messages, laid out by hand: a tag of two bytes, then the fields.
fn array(tag: u16, bytes: &[u8]) -> Vec<u8> {
    let mut m = tag.to_be_bytes().to_vec();
    m.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    m.extend_from_slice(bytes);
    m
}

fn number(tag: u16, n: u64) -> Vec<u8> {
    let mut m = tag.to_be_bytes().to_vec();
    m.extend_from_slice(&n.to_be_bytes());
    m
}

/// A message of the client: its tag, and its data or its number.
enum Sent {
    Data(Vec<u8>),
    Ack(u64),
}

fn parse(m: &[u8]) -> Sent {
    match u16::from_be_bytes([m[0], m[1]]) {
        4 => {
            let len = u32::from_be_bytes(m[2..6].try_into().unwrap()) as usize;
            assert_eq!(m.len(), 6 + len, "a data message holds its length");
            Sent::Data(m[6..].to_vec())
        }
        7 => Sent::Ack(u64::from_be_bytes(m[2..10].try_into().unwrap())),
        other => panic!("the client sent tag {other}"),
    }
}

fn target() -> Target {
    Target::new("a-project", "us-central1-a", "a-vm", 22).unwrap()
}

/// Links to the stand-in, each upgraded as the road upgrades one.
fn dial_to(board: Board) -> Dial<DuplexStream, String> {
    let target = target();
    Arc::new(move |resume: Option<Resume>| -> Dialing<DuplexStream, String> {
        let (target, board) = (target.clone(), board.clone());
        Box::pin(async move {
            let (near, far) = tokio::io::duplex(ROOM);
            board.send(far).map_err(|_| "the stand-in is gone".to_string())?;
            let upgraded = upgrade(near, crate::iap::HOST, &target, resume.as_ref(), TOKEN, SHORT).await;
            let (link, pending) = upgraded.map_err(|e| e.to_string())?;
            Ok::<_, String>(session(link, pending))
        })
    })
}

fn quiet() -> Say {
    Arc::new(|_: Line| {})
}

/// The lines that the task says, kept.
fn heard() -> (Say, Arc<std::sync::Mutex<Vec<Line>>>) {
    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = lines.clone();
    (Arc::new(move |line: Line| kept.lock().unwrap().push(line)), lines)
}

/// 100 KiB each way: each message of the client is at most 16 KiB of data,
/// the echo comes back whole and in order, and the client acknowledges
/// what it got, each acknowledgement at least the last, the last all of it.
#[tokio::test]
async fn iap_session_carries_bytes_both_ways_and_acknowledges() {
    const TOTAL: usize = 100 * 1024;
    let (board, mut links) = switchboard();
    let server = tokio::spawn(async move {
        let mut peer = Peer::accept(&mut links).await;
        assert!(peer.path().starts_with("/v4/connect?project=a-project&port=22&newWebsocket=True"), "{}", peer.path());
        assert!(peer.head.contains(&format!("\r\nAuthorization: Bearer {TOKEN}\r\n")), "{}", peer.head);
        peer.message(&array(1, b"a-sid")).await;
        let (mut got, mut acks, mut largest) = (0u64, Vec::new(), 0usize);
        while let Some(f) = peer.frame().await {
            if f.opcode == wsf::OPCODE_CLOSE {
                peer.send(wsf::OPCODE_CLOSE, &f.payload[..2]).await;
                break;
            }
            assert_eq!(f.opcode, wsf::OPCODE_BINARY);
            largest = largest.max(f.payload.len());
            match parse(&f.payload) {
                Sent::Data(data) => {
                    got += data.len() as u64;
                    peer.message(&array(4, &data)).await;
                    peer.message(&number(7, got)).await;
                }
                Sent::Ack(n) => acks.push(n),
            }
        }
        (got, acks, largest)
    });
    let (stream, mut carried) = open_within(dial_to(board.clone()), quiet(), SHORT).await.unwrap();
    let (mut from, mut to) = tokio::io::split(stream);
    let data: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        to.write_all(&sent).await.unwrap();
        to
    });
    let mut back = vec![0u8; TOTAL];
    tokio::time::timeout(SHORT, from.read_exact(&mut back)).await.expect("in time").unwrap();
    assert_eq!(back, data);
    let mut to = writer.await.unwrap();
    to.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(SHORT, from.read_to_end(&mut rest)).await.expect("the end of the stream").unwrap();
    assert!(rest.is_empty());
    assert_eq!(tokio::time::timeout(SHORT, carried.ended()).await.unwrap(), Ended::Normal);
    let (got, acks, largest) = tokio::time::timeout(SHORT, server).await.unwrap().unwrap();
    assert_eq!(got, TOTAL as u64);
    assert!(largest <= frame::MAX_MESSAGE, "a message of {largest} bytes");
    assert!(acks.windows(2).all(|w| w[0] <= w[1]), "{acks:?}");
    assert_eq!(acks.last(), Some(&(TOTAL as u64)), "the last acknowledgement takes in each byte: {acks:?}");
}

/// A link lost with no Close: the new one is a reconnect with the session's
/// id and the 500 bytes that the client got; the server says that it took
/// 1000 of the client's 3000, and the other 2000 go again before new bytes.
#[tokio::test]
async fn iap_session_is_taken_up_on_a_new_link_after_a_lost_one() {
    let (board, mut links) = switchboard();
    let (cut_tx, cut_rx) = tokio::sync::oneshot::channel::<()>();
    let first: Vec<u8> = (0..3000).map(|i| (i % 7) as u8).collect();
    let expected = first.clone();
    let server = tokio::spawn(async move {
        let mut peer = Peer::accept(&mut links).await;
        peer.message(&array(1, b"a-sid")).await;
        let mut got = Vec::new();
        while got.len() < 3000 {
            let f = peer.frame().await.expect("the first bytes");
            if let Sent::Data(data) = parse(&f.payload) {
                got.extend(data);
            }
        }
        assert_eq!(got, expected);
        peer.message(&array(4, &[9u8; 500])).await;
        cut_rx.await.unwrap();
        // The link goes with no Close, as a proxy that cuts it.
        drop(peer);
        let mut peer = Peer::accept(&mut links).await;
        assert_eq!(peer.path(), "/v4/reconnect?sid=a-sid&ack=500&newWebsocket=True&zone=us-central1-a");
        assert!(peer.head.contains(&format!("\r\nAuthorization: Bearer {TOKEN}\r\n")));
        peer.message(&number(2, 1000)).await;
        let mut again = Vec::new();
        while again.len() < 2000 + 1000 {
            let f = peer.frame().await.expect("the bytes again, then new ones");
            if let Sent::Data(data) = parse(&f.payload) {
                again.extend(data);
            }
        }
        peer.message(&array(4, &[8u8; 500])).await;
        while let Some(f) = peer.frame().await {
            if f.opcode == wsf::OPCODE_CLOSE {
                peer.send(wsf::OPCODE_CLOSE, &f.payload[..2]).await;
                break;
            }
        }
        again
    });
    let (say, lines) = heard();
    let (stream, mut carried) = open_within(dial_to(board.clone()), say, SHORT).await.unwrap();
    let (mut from, mut to) = tokio::io::split(stream);
    to.write_all(&first).await.unwrap();
    let mut back = vec![0u8; 500];
    tokio::time::timeout(SHORT, from.read_exact(&mut back)).await.expect("in time").unwrap();
    assert_eq!(back, vec![9u8; 500]);
    cut_tx.send(()).unwrap();
    // The new bytes go after the reconnect, behind the 2000 again.
    let more = vec![5u8; 1000];
    to.write_all(&more).await.unwrap();
    tokio::time::timeout(SHORT * 2, from.read_exact(&mut back)).await.expect("in time").unwrap();
    assert_eq!(back, vec![8u8; 500], "the server's bytes on the new link, once each");
    to.shutdown().await.unwrap();
    assert_eq!(tokio::time::timeout(SHORT, carried.ended()).await.unwrap(), Ended::Normal);
    let again = tokio::time::timeout(SHORT, server).await.unwrap().unwrap();
    assert_eq!(&again[..2000], &first[1000..], "what the server did not take goes again first");
    assert_eq!(&again[2000..], &more[..]);
    let said = lines.lock().unwrap().clone();
    assert!(said.iter().any(|l| matches!(l, Line::Info(t) if t.contains("link to IAP was lost"))), "{said:?}");
    assert!(said.iter().any(|l| matches!(l, Line::Info(t) if t.contains("new link"))), "{said:?}");
}

/// A Close before the session, its code and reason given back; silence,
/// and data before the connect's success, each named.
#[tokio::test]
async fn iap_no_session_is_named_by_what_came() {
    let (board, mut links) = switchboard();
    let server = tokio::spawn(async move {
        let mut peer = Peer::accept(&mut links).await;
        let mut payload = 4033u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"not authorized");
        peer.send(wsf::OPCODE_CLOSE, &payload).await;
        let silent = Peer::accept(&mut links).await;
        let mut early = Peer::accept(&mut links).await;
        early.message(&array(4, b"too early")).await;
        (silent, early)
    });
    match open_within(dial_to(board.clone()), quiet(), SHORT).await {
        Err(NotOpen::Closed { code: Some(4033), reason }) => assert_eq!(reason, "not authorized"),
        other => panic!("{:?}", other.err()),
    }
    let wait = Duration::from_millis(300);
    assert!(matches!(open_within(dial_to(board.clone()), quiet(), wait).await, Err(NotOpen::Silent(w)) if w == wait));
    match open_within(dial_to(board.clone()), quiet(), SHORT).await {
        Err(NotOpen::Fault(why)) => assert!(why.contains("data before the session opened"), "{why}"),
        other => panic!("{:?}", other.err()),
    }
    drop(server.await.unwrap());
}

/// An acknowledgement of bytes that never went ends the session, with a
/// Close 1002; a Close 4033 on an open session ends it with its code; and
/// the stream ends for SSH either way.
#[tokio::test]
async fn iap_a_bad_ack_or_a_refusal_ends_the_session() {
    let (board, mut links) = switchboard();
    let server = tokio::spawn(async move {
        let mut peer = Peer::accept(&mut links).await;
        peer.message(&array(1, b"a-sid")).await;
        peer.message(&number(7, 10)).await;
        let f = peer.frame().await.expect("the client's Close");
        assert_eq!((f.opcode, &f.payload[..2]), (wsf::OPCODE_CLOSE, &1002u16.to_be_bytes()[..]));
        let mut peer = Peer::accept(&mut links).await;
        peer.message(&array(1, b"b-sid")).await;
        let mut payload = 4033u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"denied");
        peer.send(wsf::OPCODE_CLOSE, &payload).await;
        peer
    });
    let (stream, mut carried) = open_within(dial_to(board.clone()), quiet(), SHORT).await.unwrap();
    match tokio::time::timeout(SHORT, carried.ended()).await.unwrap() {
        Ended::Fault(why) => assert!(why.contains("acknowledged 10 bytes"), "{why}"),
        other => panic!("{other:?}"),
    }
    let mut rest = Vec::new();
    let (mut from, _to) = tokio::io::split(stream);
    tokio::time::timeout(SHORT, from.read_to_end(&mut rest)).await.unwrap().unwrap();
    let (_stream, mut carried) = open_within(dial_to(board.clone()), quiet(), SHORT).await.unwrap();
    let end = tokio::time::timeout(SHORT, carried.ended()).await.unwrap();
    assert_eq!(end, Ended::Closed { code: Some(4033), reason: "denied".into() });
    drop(server.await.unwrap());
}

/// The end of SSH's input sends a Close 1000; the bytes that the server
/// sent before its own Close still reach SSH.
#[tokio::test]
async fn iap_the_end_of_input_closes_and_keeps_the_last_bytes() {
    let (board, mut links) = switchboard();
    let server = tokio::spawn(async move {
        let mut peer = Peer::accept(&mut links).await;
        peer.message(&array(1, b"a-sid")).await;
        loop {
            let f = peer.frame().await.expect("the client's Close");
            if f.opcode == wsf::OPCODE_CLOSE {
                assert_eq!(&f.payload[..2], &1000u16.to_be_bytes());
                break;
            }
        }
        peer.message(&array(4, b"last words")).await;
        peer.send(wsf::OPCODE_CLOSE, &1000u16.to_be_bytes()).await;
    });
    let (stream, mut carried) = open_within(dial_to(board.clone()), quiet(), SHORT).await.unwrap();
    let (mut from, mut to) = tokio::io::split(stream);
    to.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(SHORT, from.read_to_end(&mut rest)).await.unwrap().unwrap();
    assert_eq!(rest, b"last words");
    assert_eq!(tokio::time::timeout(SHORT, carried.ended()).await.unwrap(), Ended::Normal);
    server.await.unwrap();
}
