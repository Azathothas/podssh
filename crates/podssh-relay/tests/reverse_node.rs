//! The node runner (T-079), offline: `serve` over an in-memory stream, against
//! a scripted relay that writes WebSocket frames as the live relay did. The
//! control frames are the ones that `scripts/capture-reverse.py` recorded on
//! 2026-10-09 (`hello`, `open {id}`, `close {id}`), with test ids.
#![cfg(feature = "pair")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::reverse::{after_close, serve, End, Handler, Next, Opening, Settings};
use podssh_relay::reverse::{RelayClose, SessionId};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::session::RelaySession;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

const HELLO: &str = r#"{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}"#;
const A: &str = "127def7af9734ef39930ae7be7c1e4ee";
const B: &str = "1d4e025bb2ab4f3f81fd62df0f6c6d7d";
const LIMIT: Duration = Duration::from_secs(5);

fn id(text: &str) -> SessionId {
    SessionId::parse(text.as_bytes()).unwrap()
}

fn open(id: &str) -> String {
    format!(r#"{{"type":"open","id":"{id}"}}"#)
}

fn close(id: &str) -> String {
    format!(r#"{{"type":"close","id":"{id}"}}"#)
}

/// The local side of each session: the handler keeps one end of a pipe for
/// the node, and gives the test the other.
#[derive(Default)]
struct Local {
    ends: Arc<Mutex<HashMap<SessionId, DuplexStream>>>,
    /// When set, `open` waits for this before it returns.
    wait: Option<Arc<Notify>>,
    refuse: Option<String>,
}

impl Handler for Local {
    type Stream = DuplexStream;

    fn open(&self, id: SessionId) -> Opening<DuplexStream> {
        let (ends, wait, refuse) = (self.ends.clone(), self.wait.clone(), self.refuse.clone());
        Box::pin(async move {
            if let Some(wait) = wait {
                wait.notified().await;
            }
            if let Some(why) = refuse {
                return Err(why);
            }
            let (node_end, test_end) = tokio::io::duplex(64 * 1024);
            ends.lock().unwrap().insert(id, test_end);
            Ok(node_end)
        })
    }
}

/// The relay's side of the socket: it writes server frames and reads the
/// node's (masked) frames.
struct Relay {
    peer: DuplexStream,
    buf: Vec<u8>,
}

impl Relay {
    async fn text(&mut self, text: &str) {
        self.send(frame::OPCODE_TEXT, text.as_bytes()).await;
    }

    async fn data(&mut self, id: &str, payload: &[u8]) {
        let mut bytes = id.as_bytes().to_vec();
        bytes.extend_from_slice(payload);
        self.send(frame::OPCODE_BINARY, &bytes).await;
    }

    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        let bytes = frame::encode(&Frame { fin: true, opcode, payload: payload.to_vec() }, Role::Server, [0; 4]);
        self.peer.write_all(&bytes).await.unwrap();
    }

    /// The node's next frame other than a Ping, or `None` after `wait`.
    async fn next(&mut self, wait: Duration) -> Option<Frame> {
        tokio::time::timeout(wait, async {
            loop {
                if let Some((f, used)) = frame::decode(&self.buf, Role::Client).expect("a valid node frame") {
                    self.buf.drain(..used);
                    if f.opcode == frame::OPCODE_PING {
                        continue;
                    }
                    return f;
                }
                let mut chunk = [0u8; 8192];
                let n = self.peer.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the node closed the stream");
                self.buf.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .ok()
    }

    async fn expect(&mut self) -> Frame {
        self.next(LIMIT).await.expect("a node frame in time")
    }
}

/// A node on one end of a pipe, the scripted relay on the other; `stop` ends
/// the node when it is notified.
fn start(handler: Local) -> (Relay, Arc<Notify>, tokio::task::JoinHandle<End>, Arc<Mutex<HashMap<SessionId, DuplexStream>>>) {
    let (client, peer) = tokio::io::duplex(256 * 1024);
    let ends = handler.ends.clone();
    let stop = Arc::new(Notify::new());
    let stopper = stop.clone();
    let settings = Settings { open_limit: Duration::from_secs(3), ping_every: Duration::from_secs(60), pings_allowed: 3 };
    let task = tokio::spawn(async move {
        let session = RelaySession::new(client, Vec::new(), None, LIMIT);
        let mut stop = Box::pin(async move { stopper.notified().await });
        serve(session, Arc::new(handler), settings, &mut stop).await
    });
    (Relay { peer, buf: Vec::new() }, stop, task, ends)
}

fn text_of(f: &Frame) -> String {
    assert_eq!(f.opcode, frame::OPCODE_TEXT, "{f:?}");
    String::from_utf8(f.payload.clone()).unwrap()
}

async fn local(ends: &Arc<Mutex<HashMap<SessionId, DuplexStream>>>, id_text: &str) -> DuplexStream {
    for _ in 0..100 {
        if let Some(end) = ends.lock().unwrap().remove(&id(id_text)) {
            return end;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no local side for {id_text}");
}

#[tokio::test]
async fn two_sessions_carry_their_own_bytes_both_ways() {
    let (mut relay, stop, task, ends) = start(Local::default());
    relay.text(HELLO).await;
    relay.text(&open(A)).await;
    relay.text(&open(B)).await;
    let mut readied = vec![text_of(&relay.expect().await), text_of(&relay.expect().await)];
    readied.sort();
    assert_eq!(readied, vec![format!(r#"{{"type":"ready","id":"{A}"}}"#), format!(r#"{{"type":"ready","id":"{B}"}}"#)]);

    let (mut a, mut b) = (local(&ends, A).await, local(&ends, B).await);
    relay.data(A, b"to a").await;
    relay.data(B, b"to b").await;
    let mut got = [0u8; 4];
    a.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"to a");
    b.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"to b");

    a.write_all(b"from a").await.unwrap();
    b.write_all(b"from b").await.unwrap();
    let mut out = HashMap::new();
    for _ in 0..2 {
        let f = relay.expect().await;
        assert_eq!(f.opcode, frame::OPCODE_BINARY);
        out.insert(String::from_utf8(f.payload[..32].to_vec()).unwrap(), f.payload[32..].to_vec());
    }
    assert_eq!(out[A], b"from a");
    assert_eq!(out[B], b"from b");

    stop.notify_one();
    let mut closes = vec![text_of(&relay.expect().await), text_of(&relay.expect().await)];
    closes.sort();
    assert!(closes[0].contains(A) && closes[1].contains(B) && closes[0].contains(r#""type":"close""#), "{closes:?}");
    assert_eq!(relay.expect().await.opcode, frame::OPCODE_CLOSE, "then the socket's Close");
    assert!(matches!(task.await.unwrap(), End::Stopped));
}

#[tokio::test]
async fn late_bytes_after_close_are_dropped_and_the_socket_stays() {
    let (mut relay, _stop, _task, ends) = start(Local::default());
    relay.text(&open(A)).await;
    relay.text(&open(B)).await;
    relay.expect().await;
    relay.expect().await;
    let (mut a, mut b) = (local(&ends, A).await, local(&ends, B).await);

    relay.text(&close(A)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = a.write_all(b"late").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(a);

    relay.data(B, b"still").await;
    let mut got = [0u8; 5];
    b.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"still", "the socket and the other session go on");
    b.write_all(b"b-out").await.unwrap();
    let f = relay.expect().await;
    assert_eq!((f.opcode, &f.payload[..32], &f.payload[32..]), (frame::OPCODE_BINARY, B.as_bytes(), &b"b-out"[..]), "no frame of the closed session came first");
}

/// `ready` goes out only after the handler returned, and before any data.
#[tokio::test]
async fn ready_waits_for_the_handler_and_comes_before_data() {
    let wait = Arc::new(Notify::new());
    let (mut relay, _stop, _task, ends) = start(Local { wait: Some(wait.clone()), ..Local::default() });
    relay.text(&open(A)).await;
    assert!(relay.next(Duration::from_millis(500)).await.is_none(), "nothing before the handler returns");
    wait.notify_one();
    let mut a = local(&ends, A).await;
    a.write_all(b"banner").await.unwrap();
    assert_eq!(text_of(&relay.expect().await), format!(r#"{{"type":"ready","id":"{A}"}}"#));
    let f = relay.expect().await;
    assert_eq!((&f.payload[..32], &f.payload[32..]), (A.as_bytes(), &b"banner"[..]));
}

#[tokio::test]
async fn a_refusal_and_a_session_over_the_limit_get_reject() {
    let (mut relay, _stop, _task, _ends) = start(Local { refuse: Some("connection refused".into()), ..Local::default() });
    relay.text(&open(A)).await;
    let text = text_of(&relay.expect().await);
    assert_eq!(text, format!(r#"{{"type":"reject","id":"{A}","reason":"connection refused"}}"#));

    let (mut relay, _stop, _task, _ends) = start(Local::default());
    relay.text(r#"{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":1}"#).await;
    relay.text(&open(A)).await;
    relay.expect().await;
    relay.text(&open(B)).await;
    let text = text_of(&relay.expect().await);
    assert!(text.contains(r#""type":"reject""#) && text.contains(B), "{text}");
}

#[tokio::test]
async fn a_close_of_the_relay_ends_the_socket_with_its_code_and_reason() {
    let (mut relay, _stop, task, _ends) = start(Local::default());
    let mut payload = 1001u16.to_be_bytes().to_vec();
    payload.extend_from_slice(b"pair expired");
    relay.send(frame::OPCODE_CLOSE, &payload).await;
    match task.await.unwrap() {
        End::Closed(close) => assert_eq!((close.code, close.reason.as_str()), (1001, "pair expired")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn each_close_has_its_action() {
    let close = |code, reason: &str| RelayClose { code, reason: reason.into(), clean: true };
    assert_eq!(after_close(&close(1001, "operator stopped reverse relay")), Next::Exit("stopped"));
    assert_eq!(after_close(&close(1001, "pair expired")), Next::Repair);
    assert_eq!(after_close(&close(1001, "")), Next::Reconnect, "an empty reason never starts a new pair");
    assert_eq!(after_close(&close(1003, "data before ready")), Next::Exit("fault"));
    assert_eq!(after_close(&close(1009, "bad multiplex frame")), Next::Exit("fault"));
    assert_eq!(after_close(&close(1011, "socket error")), Next::Reconnect);
    assert_eq!(after_close(&close(1006, "")), Next::Reconnect);
}
