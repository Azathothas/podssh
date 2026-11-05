//! A node's ask for sessions readied ahead (T-650), offline: `serve` over an
//! in-memory stream against a scripted relay, as `reverse_node` runs it. A
//! node of `--spares N` asks once a `hello` offers them, `true` alone, and
//! never otherwise; a spare's `open` is readied as each other.
#![cfg(feature = "pair")]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::reverse::{serve, End, Handler, Opening, SessionId, Settings};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::session::RelaySession;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

const A: &str = "127def7af9734ef39930ae7be7c1e4ee";
const LIMIT: Duration = Duration::from_secs(5);

/// The relay's `hello` of the contract, with `extra` members beside.
fn hello(extra: &str) -> String {
    format!(r#"{{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64{extra}}}"#)
}

/// Each session's local side is a pipe whose far end nobody reads.
struct Local;

impl Handler for Local {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async {
            let (ours, theirs) = tokio::io::duplex(64 * 1024);
            // Kept while the session lives: its end is the session's end.
            tokio::spawn(async move {
                let _held = theirs;
                std::future::pending::<()>().await;
            });
            Ok(ours)
        })
    }
}

/// The relay's side of the socket: it writes server frames and reads the
/// node's.
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

    /// The node's next text frame other than a Ping, as JSON.
    async fn expect(&mut self) -> Value {
        let f = tokio::time::timeout(LIMIT, async {
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
        .expect("a node frame in time");
        assert_eq!(f.opcode, frame::OPCODE_TEXT, "{f:?}");
        serde_json::from_slice(&f.payload).expect("JSON")
    }
}

/// A node that wants `spares`, on one end of a pipe, the scripted relay on
/// the other, until `stop` is notified.
fn start(spares: u8) -> (Relay, Arc<Notify>, tokio::task::JoinHandle<End>) {
    let (client, peer) = tokio::io::duplex(256 * 1024);
    let stop = Arc::new(Notify::new());
    let stopper = stop.clone();
    let settings = Settings {
        open_limit: Duration::from_secs(3),
        ping_every: Duration::from_secs(60),
        spares,
        ..Settings::default()
    };
    let task = tokio::spawn(async move {
        let session = RelaySession::new(client, Vec::new(), None, LIMIT);
        let mut stop = Box::pin(async move { stopper.notified().await });
        serve(session, Arc::new(Local), settings, &mut stop).await
    });
    (Relay { peer, buf: Vec::new() }, stop, task)
}

/// A node of `--spares 3` asks once the relay's `hello` offers them, before
/// any other frame of its own, and readies a spare's `open` as each other.
#[tokio::test]
async fn a_node_that_wants_spares_asks_once_the_relay_offers_them() {
    let (mut relay, stop, task) = start(3);
    relay.text(&hello(r#","spares":true"#)).await;
    assert_eq!(relay.expect().await, json!({ "type": "spares", "want": 3 }));
    relay.text(&json!({ "type": "open", "id": A, "spare": true }).to_string()).await;
    assert_eq!(relay.expect().await, json!({ "type": "ready", "id": A }));
    stop.notify_one();
    let _ = relay.expect().await;
    assert!(matches!(tokio::time::timeout(LIMIT, task).await, Ok(Ok(End::Stopped))));
}

/// A relay that offers none, or offers by anything but `true`, hears no ask;
/// nor does one that offers them from a node that wants none: the node's
/// first frame is the `ready` of the relay's `open`.
#[tokio::test]
async fn a_node_asks_nothing_of_a_relay_that_offers_none_or_when_it_wants_none() {
    let cases = [("", 3), (r#","spares":"true""#, 3), (r#","spares":1"#, 3), (r#","spares":true"#, 0)];
    for (extra, want) in cases {
        let (mut relay, stop, task) = start(want);
        relay.text(&hello(extra)).await;
        relay.text(&json!({ "type": "open", "id": A }).to_string()).await;
        assert_eq!(relay.expect().await, json!({ "type": "ready", "id": A }), "{extra} {want}");
        stop.notify_one();
        let _ = relay.expect().await;
        assert!(matches!(tokio::time::timeout(LIMIT, task).await, Ok(Ok(End::Stopped))), "{extra} {want}");
    }
}

/// A node's number is 16 at most, whatever it was given.
#[tokio::test]
async fn a_node_asks_for_sixteen_at_most() {
    let (mut relay, stop, task) = start(40);
    relay.text(&hello(r#","spares":true"#)).await;
    assert_eq!(relay.expect().await["want"], 16);
    stop.notify_one();
    drop(relay);
    let _ = tokio::time::timeout(LIMIT, task).await;
}
