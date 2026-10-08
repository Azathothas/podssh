//! The operator runner (T-080), offline: `exchange` over an in-memory stream,
//! against a scripted relay that writes WebSocket frames as the live relay
//! did (`ready {id}`, data with no id, a text `reject` before a Close; see
//! `scripts/capture-reverse.py`).
#![cfg(feature = "pair")]

use std::time::Duration;

use podssh_relay::reverse::operator::{exchange, QUEUE_BEFORE_READY};
use podssh_relay::reverse::{OperatorLimits, Outcome};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const ID: &str = "4914e9e009a64fcb88d47bb8bd1a8417";
const LIMIT: Duration = Duration::from_secs(5);

fn ready() -> String {
    format!(r#"{{"type":"ready","id":"{ID}"}}"#)
}

struct Relay {
    peer: DuplexStream,
    buf: Vec<u8>,
}

impl Relay {
    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        let bytes = frame::encode(&Frame { fin: true, opcode, payload: payload.to_vec() }, Role::Server, [0; 4]);
        self.peer.write_all(&bytes).await.unwrap();
    }

    async fn close(&mut self, code: u16, reason: &str) {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        self.send(frame::OPCODE_CLOSE, &payload).await;
    }

    /// The operator's next frame other than a Ping, or `None` after `wait`.
    async fn next(&mut self, wait: Duration) -> Option<Frame> {
        tokio::time::timeout(wait, async {
            loop {
                if let Some((f, used)) = frame::decode(&self.buf, Role::Client).expect("a valid operator frame") {
                    self.buf.drain(..used);
                    if f.opcode == frame::OPCODE_PING {
                        continue;
                    }
                    return f;
                }
                let mut chunk = [0u8; 8192];
                let n = self.peer.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the operator closed the stream");
                self.buf.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .ok()
    }
}

fn limits() -> OperatorLimits {
    OperatorLimits {
        ready_limit: Duration::from_secs(3),
        close_limit: Duration::from_secs(2),
        ping_every: Duration::from_secs(60),
        pings_allowed: 3,
    }
}

/// An operator over one pipe to the scripted relay, with `local` as the
/// user's side.
fn start(limits: OperatorLimits) -> (Relay, DuplexStream, tokio::task::JoinHandle<Outcome>) {
    let (client, peer) = tokio::io::duplex(4 * 1024 * 1024);
    let (io, local) = tokio::io::duplex(4 * 1024 * 1024);
    let task = tokio::spawn(async move {
        let session = RelaySession::new(client, Vec::new(), None, LIMIT);
        exchange(session, io, limits).await
    });
    (Relay { peer, buf: Vec::new() }, local, task)
}

async fn outcome(task: tokio::task::JoinHandle<Outcome>) -> Outcome {
    tokio::time::timeout(LIMIT, task).await.expect("an outcome in time").unwrap()
}

#[tokio::test]
async fn input_before_ready_is_kept_then_sent_in_order() {
    let (mut relay, mut local, _task) = start(limits());
    local.write_all(b"early ").await.unwrap();
    local.write_all(b"bytes").await.unwrap();
    assert!(relay.next(Duration::from_millis(500)).await.is_none(), "no data frame before ready");
    relay.send(frame::OPCODE_TEXT, ready().as_bytes()).await;
    let mut got = Vec::new();
    while got.len() < 11 {
        let f = relay.next(LIMIT).await.expect("the kept input");
        assert_eq!(f.opcode, frame::OPCODE_BINARY, "the operator sends no text frame");
        got.extend_from_slice(&f.payload);
    }
    assert_eq!(got, b"early bytes", "bare and in order: no id added");
    relay.send(frame::OPCODE_BINARY, b"back").await;
    relay.send(frame::OPCODE_BINARY, b"").await;
    let mut back = [0u8; 4];
    local.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"back");
}

#[tokio::test]
async fn each_close_after_ready_but_1000_is_a_failure_with_its_code_and_reason() {
    for (code, reason) in [(1008, "wait for ready"), (1003, "binary frames required"), (1009, "frame byte cap"), (1000, "session ended")] {
        let (mut relay, _local, task) = start(limits());
        relay.send(frame::OPCODE_TEXT, ready().as_bytes()).await;
        relay.close(code, reason).await;
        let got = outcome(task).await;
        assert_eq!(got, Outcome::Ended { code, reason: reason.into() });
        assert_eq!(got.is_success(), code == 1000, "{got:?}");
    }
}

/// The relay cuts the Close's reason to 123 bytes; the text `reject` before
/// it carries the node's whole reason, and that is the one kept.
#[tokio::test]
async fn a_long_reject_reason_reaches_the_outcome_whole() {
    let (mut relay, _local, task) = start(limits());
    let reason = "r".repeat(200);
    let reject = format!(r#"{{"type":"reject","id":"{ID}","reason":"{reason}"}}"#);
    relay.send(frame::OPCODE_TEXT, reject.as_bytes()).await;
    relay.close(1011, &reason[..123]).await;
    let got = outcome(task).await;
    assert_eq!(got, Outcome::NeverReady { code: Some(1011), reason });
    assert!(!got.is_success());
}

#[tokio::test]
async fn no_ready_in_time_fails_and_is_never_a_success() {
    let (mut relay, _local, task) = start(OperatorLimits { ready_limit: Duration::from_millis(300), ..limits() });
    let got = outcome(task).await;
    assert!(matches!(&got, Outcome::NeverReady { code: None, reason } if reason.contains("did not answer")), "{got:?}");
    assert!(!got.is_success());
    let f = relay.next(LIMIT).await.expect("a Close");
    assert_eq!((f.opcode, close_code_and_reason(&f.payload).0), (frame::OPCODE_CLOSE, Some(1000)));
}

#[tokio::test]
async fn more_input_than_the_queue_before_ready_fails() {
    let (_relay, mut local, task) = start(limits());
    let writer = tokio::spawn(async move {
        let _ = local.write_all(&vec![b'x'; QUEUE_BEFORE_READY + 70_000]).await;
        local
    });
    let got = outcome(task).await;
    assert!(matches!(&got, Outcome::NeverReady { reason, .. } if reason.contains("before the node was ready")), "{got:?}");
    drop(writer);
}

/// After `ready`, a text `close` keeps its reason for the outcome.
#[tokio::test]
async fn a_text_close_after_ready_keeps_its_reason() {
    let (mut relay, _local, task) = start(limits());
    relay.send(frame::OPCODE_TEXT, ready().as_bytes()).await;
    let close = format!(r#"{{"type":"close","id":"{ID}","reason":"the node is stopping"}}"#);
    relay.send(frame::OPCODE_TEXT, close.as_bytes()).await;
    relay.close(1000, "close").await;
    assert_eq!(outcome(task).await, Outcome::Ended { code: 1000, reason: "the node is stopping".into() });
}

/// At the end of the input: a Close 1000, then the last bytes still arrive
/// until the relay answers it.
#[tokio::test]
async fn the_end_of_input_sends_a_close_and_waits_for_the_last_bytes() {
    let (mut relay, mut local, task) = start(limits());
    relay.send(frame::OPCODE_TEXT, ready().as_bytes()).await;
    local.write_all(b"last").await.unwrap();
    local.shutdown().await.unwrap();
    let f = relay.next(LIMIT).await.expect("the input");
    assert_eq!(f.payload, b"last");
    let f = relay.next(LIMIT).await.expect("a Close");
    assert_eq!((f.opcode, close_code_and_reason(&f.payload).0), (frame::OPCODE_CLOSE, Some(1000)));
    relay.send(frame::OPCODE_BINARY, b"tail").await;
    relay.close(1000, "").await;
    let mut tail = [0u8; 4];
    local.read_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"tail");
    assert_eq!(outcome(task).await, Outcome::LocalEnd);
}
