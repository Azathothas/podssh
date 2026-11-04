//! A node's socket gives each session a turn (T-648), offline: `serve` over
//! an in-memory stream, against a scripted relay as in `reverse_node.rs`,
//! which reads nothing while a session's backlog builds. Four bytes of a
//! second session then go before the backlog, not after it; with both backed
//! up, their frames alternate; a session's `close` follows its last bytes;
//! and a session that the relay closed sends nothing more. Each wait for a
//! backlog is a condition: a write to the local side that stays pending
//! while each other task of the test's one thread runs, which is when each
//! queue between it and the relay is full.
#![cfg(feature = "pair")]

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use podssh_relay::reverse::{serve, End, Handler, Opening, SessionId, Settings};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::session::RelaySession;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

const HELLO: &str = r#"{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}"#;
const A: &str = "127def7af9734ef39930ae7be7c1e4ee";
const B: &str = "1d4e025bb2ab4f3f81fd62df0f6c6d7d";
const LIMIT: Duration = Duration::from_secs(20);
/// The turns of the other tasks that a pending write waits through before
/// the queues count as full: each step of a task on this thread takes one.
const QUIET_TURNS: usize = 1000;
/// Bytes of a busy session that may go before another session's four: the
/// relay's pipe, and two reads of the busy one. One queue for all held 16 MiB.
const BEFORE: usize = 2 << 20;

fn id(text: &str) -> SessionId {
    SessionId::parse(text.as_bytes()).unwrap()
}

/// The test's end of each session's local side, by id.
type Ends = Arc<Mutex<HashMap<SessionId, DuplexStream>>>;

/// Each session's local side is a pipe, whose other end the test holds.
#[derive(Default)]
struct Local {
    ends: Ends,
}

impl Handler for Local {
    type Stream = DuplexStream;

    fn open(&self, id: SessionId) -> Opening<DuplexStream> {
        let ends = self.ends.clone();
        Box::pin(async move {
            let (node_end, test_end) = tokio::io::duplex(64 * 1024);
            ends.lock().unwrap().insert(id, test_end);
            Ok(node_end)
        })
    }
}

/// The relay's side of the socket.
struct Relay {
    peer: DuplexStream,
    buf: Vec<u8>,
}

impl Relay {
    async fn text(&mut self, text: &str) {
        let bytes = frame::encode(
            &Frame { fin: true, opcode: frame::OPCODE_TEXT, payload: text.as_bytes().to_vec() },
            Role::Server,
            [0; 4],
        );
        self.peer.write_all(&bytes).await.unwrap();
    }

    /// The node's next frame other than a Ping.
    async fn next(&mut self) -> Frame {
        let read = tokio::time::timeout(LIMIT, async {
            loop {
                if let Some((f, used)) = frame::decode(&self.buf, Role::Client).expect("a valid node frame") {
                    self.buf.drain(..used);
                    if f.opcode != frame::OPCODE_PING {
                        return f;
                    }
                    continue;
                }
                let mut chunk = vec![0u8; 64 * 1024];
                let n = self.peer.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the node closed the stream");
                self.buf.extend_from_slice(&chunk[..n]);
            }
        });
        read.await.expect("a node frame in time")
    }

    /// The session and the payload of the node's next binary frame, or the
    /// text of a text frame, with no session.
    async fn next_of(&mut self) -> (Option<String>, Vec<u8>) {
        let f = self.next().await;
        match f.opcode {
            frame::OPCODE_BINARY => {
                let session = String::from_utf8(f.payload[..32].to_vec()).unwrap();
                (Some(session), f.payload[32..].to_vec())
            }
            frame::OPCODE_TEXT => (None, f.payload),
            other => panic!("a frame of opcode {other}"),
        }
    }
}

/// A node on one end of a pipe of 256 KiB, the scripted relay on the other;
/// the node stops when `stop` is notified.
fn start() -> (Relay, Arc<Notify>, tokio::task::JoinHandle<End>, Ends) {
    let (client, peer) = tokio::io::duplex(256 * 1024);
    let handler = Local::default();
    let ends = handler.ends.clone();
    let stop = Arc::new(Notify::new());
    let stopper = stop.clone();
    let settings = Settings { ping_every: Duration::from_secs(60), pings_allowed: 3, ..Settings::default() };
    let task = tokio::spawn(async move {
        let session = RelaySession::new(client, Vec::new(), None, LIMIT);
        let mut stop = Box::pin(async move { stopper.notified().await });
        serve(session, Arc::new(handler), settings, &mut stop).await
    });
    (Relay { peer, buf: Vec::new() }, stop, task, ends)
}

/// The relay opens `ids`, and reads each `ready`.
async fn open(relay: &mut Relay, ends: &Ends, ids: &[&str]) -> Vec<DuplexStream> {
    for id in ids {
        relay.text(&format!(r#"{{"type":"open","id":"{id}"}}"#)).await;
        let (session, text) = relay.next_of().await;
        assert_eq!((session, String::from_utf8(text).unwrap()), (None, format!(r#"{{"type":"ready","id":"{id}"}}"#)));
    }
    ids.iter().map(|text| ends.lock().unwrap().remove(&id(text)).expect("a local side")).collect()
}

/// Write to `end` until a write stays pending while each other task of this
/// thread runs: the node's queues of this session, and the relay's pipe, are
/// full. The bytes written.
async fn fill(end: &mut DuplexStream, byte: u8) -> usize {
    let chunk = vec![byte; 64 * 1024];
    let mut written = 0;
    loop {
        let mut write = std::pin::pin!(end.write(&chunk));
        let mut quiet = 0;
        let took = loop {
            match std::future::poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await {
                Poll::Ready(n) => break Some(n.expect("the node's local side")),
                Poll::Pending if quiet == QUIET_TURNS => break None,
                Poll::Pending => {
                    quiet += 1;
                    tokio::task::yield_now().await;
                }
            }
        };
        match took {
            Some(n) => written += n,
            None => return written,
        }
        assert!(written < 64 << 20, "the node took 64 MiB of one session and held it");
    }
}

/// The issue's case: a bulk session on a slow egress beside an interactive
/// one. With A's backlog in the node's queue, B's four bytes go out before
/// 2 MiB more of A's; one queue for all held 16 MiB of A ahead of them.
#[tokio::test]
async fn a_sessions_four_bytes_go_before_anothers_backlog() {
    let (mut relay, _stop, _task, ends) = start();
    relay.text(HELLO).await;
    let mut locals = open(&mut relay, &ends, &[A, B]).await;
    let mut b = locals.pop().unwrap();
    let mut a = locals.pop().unwrap();
    let held = fill(&mut a, b'a').await;
    assert!(held > 0, "A's local side took nothing");
    b.write_all(b"to b").await.unwrap();
    let mut before = 0;
    loop {
        match relay.next_of().await {
            (Some(session), payload) if session == A => before += payload.len(),
            (Some(session), payload) if session == B => {
                assert_eq!(payload, b"to b");
                break;
            }
            other => panic!("{other:?}"),
        }
        assert!(before < BEFORE, "{before} bytes of A came before B's four, of {held} that A wrote");
    }
}

/// With both sessions backed up, the frames alternate from B's first one:
/// a turn each, whatever each one holds.
#[tokio::test]
async fn with_both_backed_up_the_frames_alternate_by_session() {
    let (mut relay, _stop, _task, ends) = start();
    relay.text(HELLO).await;
    let mut locals = open(&mut relay, &ends, &[A, B]).await;
    let mut b = locals.pop().unwrap();
    let mut a = locals.pop().unwrap();
    fill(&mut a, b'a').await;
    fill(&mut b, b'b').await;
    let mut seen = Vec::new();
    while seen.len() < 21 {
        let (session, _) = relay.next_of().await;
        let session = session.expect("data alone");
        if seen.is_empty() && session != B {
            continue;
        }
        seen.push(session);
    }
    for pair in seen.windows(2) {
        assert_ne!(pair[0], pair[1], "two frames of one session in a row: {seen:?}");
    }
}

/// A session's local side that ends with a backlog: the relay gets each of
/// its bytes, then its `close`, beside another session that is backed up.
#[tokio::test]
async fn a_sessions_close_follows_its_last_bytes() {
    let (mut relay, _stop, _task, ends) = start();
    relay.text(HELLO).await;
    let mut locals = open(&mut relay, &ends, &[A, B]).await;
    let mut b = locals.pop().unwrap();
    let mut a = locals.pop().unwrap();
    fill(&mut b, b'b').await;
    let held = fill(&mut a, b'a').await;
    drop(a);
    let mut got = 0;
    loop {
        match relay.next_of().await {
            (Some(session), payload) if session == A => got += payload.len(),
            (Some(_), _) => {}
            (None, text) => {
                let text = String::from_utf8(text).unwrap();
                assert!(text.contains(r#""type":"close""#) && text.contains(A), "{text}");
                break;
            }
        }
    }
    assert_eq!(got, held, "each byte of A before its close");
    drop(b);
}

/// The relay closes a session with a backlog: none of its queued bytes go
/// out after the ones already on their way, and the other session goes on.
#[tokio::test]
async fn a_session_that_the_relay_closed_sends_nothing_more() {
    let (mut relay, stop, task, ends) = start();
    relay.text(HELLO).await;
    let mut locals = open(&mut relay, &ends, &[A, B]).await;
    let mut b = locals.pop().unwrap();
    let mut a = locals.pop().unwrap();
    fill(&mut a, b'a').await;
    relay.text(&format!(r#"{{"type":"close","id":"{A}"}}"#)).await;
    // The relay's pipe, and the read on its way, at most.
    let mut after = 0;
    b.write_all(b"to b").await.unwrap();
    loop {
        match relay.next_of().await {
            (Some(session), payload) if session == A => after += payload.len(),
            (Some(session), payload) if session == B => {
                assert_eq!(payload, b"to b");
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(after <= 256 * 1024 + 2 * 64 * 1024, "{after} bytes of A after its close");
    stop.notify_one();
    let (session, text) = relay.next_of().await;
    let text = String::from_utf8(text).unwrap();
    assert!(session.is_none() && text.contains(B) && text.contains(r#""type":"close""#), "only B was live: {text}");
    assert_eq!(relay.next().await.opcode, frame::OPCODE_CLOSE, "nothing of A, then the socket's Close");
    assert!(matches!(task.await.unwrap(), End::Stopped));
    drop(a);
}
