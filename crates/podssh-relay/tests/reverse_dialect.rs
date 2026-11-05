//! The node's run loop against a relay of another dialect of the reverse
//! road (T-643, GitHub #141), on the plain wire to a stand-in on the
//! loopback: a `hello` whose `version` this node does not read, and a `426`
//! to its upgrade as podssh's relay role of another dialect writes it, each
//! end the node as unusable with one sentence that says whom to update, and
//! with no second connection, where the node connected again for ever
//! before. Its upgrade states its own dialect, `X-Podssh-Proto: 1`.
#![cfg(all(feature = "pair", feature = "plain-ws"))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::pair::{self, Pair};
use podssh_relay::relay::Relay;
use podssh_relay::reverse::{self, Exit, Handler, NodeConfig, Opening, SessionId, Settings, Wire};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

const LIMIT: Duration = Duration::from_secs(10);
/// How long the node has to end: one that connected again would be past
/// its second try of the backoff by then, and never end.
const ENDS_WITHIN: Duration = Duration::from_secs(8);
/// The name of the test's pair, of the measured shape.
const NAME: &str = "podssh-test-pair-0123456789abcdef0";
/// What a relay of dialect 2 alone answers this node's upgrade.
const REFUSED: &str = "reverse: the node speaks the reverse road's dialect 1, and the relay reads dialect 2 alone: \
                       update the node";

/// A handler that no session reaches: the stand-in opens none.
struct Nobody;

impl Handler for Nobody {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async { Err("no session in this test".to_string()) })
    }
}

/// What the stand-in answers each upgrade.
#[derive(Clone, Copy)]
enum Answer {
    /// `101`, then this `hello`, and the socket held until the node ends it.
    Hello(&'static str),
    /// [`REFUSED`], as podssh's relay role writes a refusal.
    Refuse,
}

/// The head of each upgrade that reached the stand-in, in order.
type Heads = Arc<Mutex<Vec<String>>>;

/// The stand-in on a free port of the loopback, which answers each upgrade
/// with `answer`.
async fn stand_in(answer: Answer) -> (Relay, Heads) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    let heads: Heads = Arc::default();
    let seen = heads.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if tcp.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                seen.lock().unwrap().push(head.clone());
                match answer {
                    Answer::Hello(hello) => {
                        let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap_or_default();
                        let accept = podssh_ws::handshake::accept_key(key.trim());
                        let switching = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                             Sec-WebSocket-Accept: {accept}\r\n\r\n"
                        );
                        let text = Frame { fin: true, opcode: frame::OPCODE_TEXT, payload: hello.as_bytes().to_vec() };
                        let _ = tcp.write_all(switching.as_bytes()).await;
                        let _ = tcp.write_all(&frame::encode(&text, Role::Server, [0; 4])).await;
                        let mut rest = [0u8; 1024];
                        while matches!(tcp.read(&mut rest).await, Ok(n) if n > 0) {}
                    }
                    Answer::Refuse => {
                        let refusal = podssh_ws::http::request::refusal(426, REFUSED, &[("X-Podssh-Proto", "2")]);
                        let _ = tcp.write_all(&refusal).await;
                        let _ = tcp.shutdown().await;
                    }
                }
            });
        }
    });
    (Relay { host: "127.0.0.1".into(), port }, heads)
}

/// A pair on `relay`, for 72 hours, with test tokens of the measured shape.
fn pair_on(relay: &Relay) -> Pair {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let token = |c: &str| format!("testonly{}", c.repeat(56));
    let body = serde_json::json!({
        "name": NAME, "node_token": token("n"), "connect_token": token("c"), "stop_token": token("s"),
        "expires": now + 72 * 3600 * 1000,
    });
    pair::parse(relay, body.to_string().as_bytes(), now).expect("a test pair")
}

/// podssh's node on `relay`, until it ends, [`ENDS_WITHIN`] at most.
async fn node_on(relay: &Relay) -> Option<Exit> {
    let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
    let mut config = NodeConfig {
        pair: pair_on(relay),
        label: None,
        trust: &trust,
        proxy: &proxy,
        timeout: LIMIT,
        settings: Settings::default(),
        repair: None,
        wire: Wire::PlainLoopback,
        say: None,
    };
    let ran = reverse::run(&mut config, Arc::new(Nobody), std::future::pending::<()>());
    tokio::time::timeout(ENDS_WITHIN, ran).await.ok()
}

#[tokio::test]
async fn a_hello_of_another_dialect_ends_the_node_with_no_second_connection() {
    let (relay, heads) = stand_in(Answer::Hello(r#"{"type":"hello","version":2,"maxFrameBytes":65536}"#)).await;
    let exit = node_on(&relay).await.expect("the node ended; one that connected again would never end");
    match exit {
        Exit::Unusable(why) => {
            assert!(why.starts_with("the relay speaks the reverse road's dialect 2, and this node reads"), "{why}");
            assert!(why.ends_with(": update this node"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    // Nothing comes after the end, even a moment later.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "one connection: {heads:?}");
    assert!(heads[0].starts_with(&format!("GET /v1/node/{NAME} HTTP/1.1\r\n")), "{}", heads[0]);
    assert!(heads[0].contains("\r\nX-Podssh-Proto: 1\r\n"), "the node states its dialect: {}", heads[0]);
}

#[tokio::test]
async fn a_426_of_another_dialect_ends_the_node_with_the_relay_s_words() {
    let (relay, heads) = stand_in(Answer::Refuse).await;
    let exit = node_on(&relay).await.expect("the node ended at the first 426");
    match exit {
        Exit::Unusable(why) => {
            assert!(why.starts_with("the relay refused this node's upgrade (426): reverse: the node speaks"), "{why}");
            assert!(why.ends_with(": update the node"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(heads.lock().unwrap().len(), 1, "a 426 is never asked again");
}

/// A `hello` of the dialect of before, with no `version`, and one of this
/// node's own, are read: the node stays on its one socket.
#[tokio::test]
async fn a_hello_of_the_dialect_of_before_keeps_the_node_on_its_socket() {
    for hello in [r#"{"type":"hello","maxSessions":64}"#, r#"{"type":"hello","version":1,"maxSessions":64}"#] {
        let (relay, heads) = stand_in(Answer::Hello(hello)).await;
        let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
        let mut config = NodeConfig {
            pair: pair_on(&relay),
            label: None,
            trust: &trust,
            proxy: &proxy,
            timeout: LIMIT,
            settings: Settings::default(),
            repair: None,
            wire: Wire::PlainLoopback,
            say: None,
        };
        let ran = reverse::run(&mut config, Arc::new(Nobody), tokio::time::sleep(Duration::from_secs(2)));
        let exit = tokio::time::timeout(LIMIT, ran).await.expect("the stop ends the node");
        assert!(matches!(exit, Exit::Stopped), "{hello}: {exit:?}");
        assert_eq!(heads.lock().unwrap().len(), 1, "{hello}: the node kept its socket");
    }
}
