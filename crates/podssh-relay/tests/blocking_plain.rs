//! The blocking facade (T-081) against a stand-in relay on the loopback, over
//! plain `ws://` (feature `plain-ws`). Each test is a plain `#[test]`, with no
//! runtime of its own, as podbox calls the facade. The stand-in writes
//! WebSocket frames as the live relay did (`scripts/capture-reverse.py`).
#![cfg(all(feature = "blocking", feature = "plain-ws"))]

mod stand_in;

use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use podssh_relay::blocking::{Client, Closed, Config, Local, NodeOptions, Operator, Stopper};
use podssh_relay::reverse::{Exit, Outcome, Wire};
use podssh_ws::frame;
use stand_in::{data, open, pipe, ready, test_pair, Shared, StandIn, CONNECT, ID1, ID2, LIMIT, NAME, NODE};

fn client() -> Client {
    Client::new(Config { wire: Wire::PlainLoopback, timeout: LIMIT, ..Config::default() }).expect("a client")
}

/// Each session echoes its bytes, through a pipe in memory.
fn echo(_: &str) -> Result<Local, String> {
    let (reader, writer) = pipe();
    Ok(Local::new(reader, writer))
}

#[test]
fn a_node_carries_two_sessions_and_stops() {
    let (stand_in, relay) = StandIn::new();
    let mut pair = test_pair(&relay, NAME, 0);
    let client = client();
    let stopper = Stopper::new();
    // The second session goes to a TCP echo, which reports the end it reads.
    let (tcp_port, tcp_ended) = tcp_echo();
    let handler = move |id: &str| {
        if id == ID2 {
            let stream = TcpStream::connect(("127.0.0.1", tcp_port)).map_err(|e| e.to_string())?;
            Local::tcp(stream).map_err(|e| e.to_string())
        } else {
            echo(id)
        }
    };
    std::thread::scope(|s| {
        let node = s.spawn(|| client.run_node(&mut pair, handler, &NodeOptions::default(), &stopper));
        let _guard = StopOnPanic(&stopper);
        let (head, mut peer) = stand_in.accept();
        assert!(head.starts_with(&format!("GET /v1/node/{NAME} HTTP/1.1\r\n")), "{head}");
        assert!(head.contains(&format!("X-Relay-Token: {NODE}\r\n")), "the node token, in its header");
        peer.text(r#"{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}"#);
        peer.text(&open(ID1));
        peer.text(&open(ID2));
        let mut readied = vec![peer.next_text(), peer.next_text()];
        let mut want = vec![ready(ID1), ready(ID2)];
        readied.sort();
        want.sort();
        assert_eq!(readied, want);
        peer.send(frame::OPCODE_BINARY, &data(ID1, b"one"));
        peer.send(frame::OPCODE_BINARY, &data(ID2, b"two"));
        let back = peer.node_bytes(6);
        let mut want = vec![(ID1.to_string(), b"one".to_vec()), (ID2.to_string(), b"two".to_vec())];
        want.sort();
        assert_eq!(back, want, "each echo came back under its own id");
        // The relay closes the TCP session: its peer reads the end.
        peer.text(&format!(r#"{{"type":"close","id":"{ID2}"}}"#));
        assert!(tcp_ended.recv_timeout(LIMIT).is_ok(), "the TCP side read the end of the session");
        stopper.stop();
        let close: serde_json::Value = serde_json::from_str(&peer.next_text()).unwrap();
        assert_eq!(close, serde_json::json!({"type": "close", "id": ID1, "reason": "the node is stopping"}));
        let end = peer.next(LIMIT).expect("a Close of the socket");
        assert_eq!((end.opcode, &end.payload[..2]), (frame::OPCODE_CLOSE, &1000u16.to_be_bytes()[..]));
        peer.close(1000, "");
        let exit = node.join().unwrap();
        assert!(matches!(exit, Ok(Exit::Stopped)), "{exit:?}");
    });
    assert_eq!(pair.name, NAME, "the caller keeps its pair");
}

#[test]
fn an_operator_keeps_its_input_until_ready_and_gives_back_the_last_bytes() {
    let (stand_in, relay) = StandIn::new();
    let client = client();
    let out = Shared::default();
    let to = Operator::new(&relay, NAME, CONNECT);
    std::thread::scope(|s| {
        let writer = out.clone();
        let session = s.spawn(|| client.run_operator(&to, Cursor::new(b"early bytes".to_vec()), writer));
        let (head, mut peer) = stand_in.accept();
        assert!(head.starts_with(&format!("GET /v1/connect/{NAME} HTTP/1.1\r\n")), "{head}");
        assert!(head.contains(&format!("X-Relay-Token: {CONNECT}\r\n")), "the connect token, in its header");
        assert!(peer.next(Duration::from_millis(500)).is_none(), "no data frame before ready");
        peer.text(&ready(ID1));
        let kept = peer.next(LIMIT).expect("the kept input");
        assert_eq!((kept.opcode, kept.payload.as_slice()), (frame::OPCODE_BINARY, &b"early bytes"[..]));
        peer.send(frame::OPCODE_BINARY, b"from the node");
        let close = peer.next(LIMIT).expect("a Close at the end of the input");
        assert_eq!((close.opcode, &close.payload[..2]), (frame::OPCODE_CLOSE, &1000u16.to_be_bytes()[..]));
        peer.close(1000, "");
        let outcome = session.join().unwrap();
        assert!(matches!(outcome, Ok(Outcome::LocalEnd)), "{outcome:?}");
    });
    assert_eq!(out.bytes(), b"from the node", "the last bytes reached the writer before the outcome");
}

#[test]
fn a_close_after_ready_names_its_code_and_reason() {
    let (stand_in, relay) = StandIn::new();
    let client = client();
    let to = Operator::new(&relay, NAME, CONNECT);
    // An input that stays open until the session ended.
    let (input, mut input_end) = pipe();
    std::thread::scope(|s| {
        let session = s.spawn(|| client.run_operator(&to, input, std::io::sink()));
        let (_, mut peer) = stand_in.accept();
        peer.text(&ready(ID1));
        peer.close(1011, "the node's side failed");
        let outcome = session.join().unwrap().expect("an outcome");
        assert_eq!(outcome, Outcome::Ended { code: 1011, reason: "the node's side failed".into() });
        assert!(!outcome.is_success());
    });
    let _ = input_end.flush();
}

/// Two operator sessions at once on one client: two threads share its runtime.
#[test]
fn two_operator_sessions_at_once_on_one_client() {
    let (stand_in, relay) = StandIn::new();
    let client = client();
    let to = Operator::new(&relay, NAME, CONNECT);
    let payloads = [vec![1u8; 300 * 1024], vec![2u8; 200 * 1024]];
    std::thread::scope(|s| {
        let sessions: Vec<_> = payloads
            .iter()
            .map(|payload| {
                let out = Shared::default();
                let (reader, writer, client, to) = (Cursor::new(payload.clone()), out.clone(), &client, &to);
                (s.spawn(move || client.run_operator(to, reader, writer)), out)
            })
            .collect();
        // The stand-in echoes each session in a thread of its own.
        let relays: Vec<_> = (0..2)
            .map(|_| {
                let (_, mut peer) = stand_in.accept();
                s.spawn(move || {
                    peer.text(&ready(ID1));
                    loop {
                        let f = peer.next(LIMIT).expect("a frame");
                        match f.opcode {
                            frame::OPCODE_BINARY => peer.send(frame::OPCODE_BINARY, &f.payload),
                            frame::OPCODE_CLOSE => return peer.close(1000, ""),
                            other => panic!("opcode {other}"),
                        }
                    }
                })
            })
            .collect();
        for relay in relays {
            relay.join().unwrap();
        }
        for ((session, out), payload) in sessions.into_iter().zip(&payloads) {
            let outcome = session.join().unwrap();
            assert!(matches!(outcome, Ok(Outcome::LocalEnd)), "{outcome:?}");
            assert!(out.bytes() == *payload, "each session got its own bytes back, whole");
        }
    });
}

#[test]
fn a_forward_stream_reads_writes_and_ends_with_the_relay_close() {
    let (stand_in, relay) = StandIn::new();
    let client = client();
    std::thread::scope(|s| {
        let relay_side = s.spawn(|| {
            let (head, mut peer) = stand_in.accept();
            assert!(head.starts_with("GET /connect/example.org/22 HTTP/1.1\r\n"), "{head}");
            peer.send(frame::OPCODE_BINARY, b"SSH-2.0-");
            peer.send(frame::OPCODE_BINARY, b"");
            peer.send(frame::OPCODE_BINARY, b"stand-in\r\n");
            let hello = peer.next(LIMIT).expect("the client's bytes");
            assert_eq!(hello.payload, b"hello");
            peer.close(1011, "write failed");
        });
        let forward = client.forward_on_loopback(&relay, "example.org", 22, CONNECT).expect("a session");
        let mut banner = [0u8; 18];
        (&forward).read_exact(&mut banner).unwrap();
        assert_eq!(&banner, b"SSH-2.0-stand-in\r\n", "the empty keepalive frame is skipped");
        (&forward).write_all(b"hello").unwrap();
        let err = (&forward).read(&mut [0u8; 8]).expect_err("the relay's 1011");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
        let closed = err.get_ref().and_then(|e| e.downcast_ref::<Closed>()).expect("the code and the reason");
        assert_eq!(closed, &Closed { code: 1011, reason: "write failed".into() });
        relay_side.join().unwrap();
    });
}

#[test]
fn a_forward_stream_ends_at_a_close_1000_and_closes_cleanly() {
    let (stand_in, relay) = StandIn::new();
    let client = client();
    std::thread::scope(|s| {
        let relay_side = s.spawn(|| {
            let (_, mut peer) = stand_in.accept();
            peer.send(frame::OPCODE_BINARY, b"all of it");
            peer.close(1000, "");
            // `close` sends the Close, and does not wait for the answer.
            let (_, mut second) = stand_in.accept();
            let close = second.next(LIMIT).expect("the client's Close");
            assert_eq!((close.opcode, &close.payload[..2]), (frame::OPCODE_CLOSE, &1000u16.to_be_bytes()[..]));
        });
        let mut forward = client.forward_on_loopback(&relay, "example.org", 22, CONNECT).expect("a session");
        let mut all = Vec::new();
        forward.read_to_end(&mut all).expect("a normal end");
        assert_eq!(all, b"all of it");
        forward.close().expect("the session answered the relay's Close already");
        let second = client.forward_on_loopback(&relay, "example.org", 22, CONNECT).expect("a session");
        second.close().expect("a Close sent");
        relay_side.join().unwrap();
    });
}

/// The relay takes the client's Close as the end of the client's bytes, and
/// still gives the target's, then its own Close (measured 2026-10-09).
#[test]
fn a_forward_stream_shuts_its_write_side_and_reads_to_the_end() {
    let (stand_in, relay) = StandIn::new();
    let client = client();
    std::thread::scope(|s| {
        let relay_side = s.spawn(|| {
            let (_, mut peer) = stand_in.accept();
            let request = peer.next(LIMIT).expect("the request");
            assert_eq!(request.payload, b"request");
            let close = peer.next(LIMIT).expect("the client's Close");
            assert_eq!((close.opcode, &close.payload[..2]), (frame::OPCODE_CLOSE, &1000u16.to_be_bytes()[..]));
            peer.send(frame::OPCODE_BINARY, b"response");
            peer.close(1000, "client half-closed, target idle for 15s");
        });
        let mut forward = client.forward_on_loopback(&relay, "example.org", 22, CONNECT).expect("a session");
        forward.write_all(b"request").unwrap();
        forward.shutdown_write().expect("a Close sent");
        let late = forward.write(b"late").expect_err("no write after the Close");
        assert_eq!(late.kind(), std::io::ErrorKind::BrokenPipe);
        let mut rest = Vec::new();
        forward.read_to_end(&mut rest).expect("a normal end");
        assert_eq!(rest, b"response", "the target's bytes after the client's Close");
        relay_side.join().unwrap();
    });
}

#[test]
fn a_stop_before_the_node_runs_ends_it_at_once() {
    // Nothing listens on this port.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let relay = podssh_relay::relay::Relay { host: "127.0.0.1".into(), port };
    let stopper = Stopper::new();
    stopper.stop();
    let started = Instant::now();
    let exit = in_time(move || client().run_node(&mut test_pair(&relay, NAME, 0), echo, &NodeOptions::default(), &stopper));
    assert!(matches!(exit, Ok(Exit::Stopped)), "{exit:?}");
    assert!(started.elapsed() < LIMIT, "at once: {:?}", started.elapsed());
}

/// Plain `ws://` refuses a host that is not the loopback; a node that is set
/// up so exits, and does not reconnect for ever.
#[test]
fn a_node_that_cannot_connect_as_set_up_exits() {
    let relay = podssh_relay::relay::Relay { host: "relay.example.org".into(), port: 443 };
    let exit = in_time(move || client().run_node(&mut test_pair(&relay, NAME, 0), echo, &NodeOptions::default(), &Stopper::new()));
    assert!(matches!(&exit, Ok(Exit::Unusable(why)) if why.contains("loopback")), "{exit:?}");
}

/// The result of `work` within the limit. A node that never ends fails the
/// test, and its thread is left behind, rather than holding the test for ever.
fn in_time<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx.recv_timeout(LIMIT).expect("an end within the limit")
}

/// An expired pair: the relay answers `403`, the hook gives a new pair on a
/// thread of its own, and the node goes on with it; the caller gets it back.
#[test]
fn an_expired_pair_is_replaced_by_the_hook_and_given_back() {
    let (stand_in, relay) = StandIn::new();
    let hours_ago = 80 * 3600 * 1000;
    let mut pair = test_pair(&relay, NAME, hours_ago);
    let next_name = "podssh-test-pair-fedcba98765432100";
    let hook_relay = relay.clone();
    let options = NodeOptions {
        repair: Some(Arc::new(move || Some(test_pair(&hook_relay, next_name, 0)))),
        ..NodeOptions::default()
    };
    let client = client();
    let stopper = Stopper::new();
    std::thread::scope(|s| {
        let node = s.spawn(|| client.run_node(&mut pair, echo, &options, &stopper));
        let _guard = StopOnPanic(&stopper);
        stand_in.refuse(403, "reverse: forbidden");
        let (head, mut peer) = stand_in.accept();
        assert!(head.starts_with(&format!("GET /v1/node/{next_name} HTTP/1.1\r\n")), "{head}");
        // A session readied: the node serves. A stop before that ends the
        // connection as it is being made, with no Close.
        peer.text(&open(ID1));
        assert_eq!(peer.next_text(), ready(ID1));
        stopper.stop();
        let close: serde_json::Value = serde_json::from_str(&peer.next_text()).unwrap();
        assert_eq!(close["type"], "close");
        let end = peer.next(LIMIT).expect("a Close of the socket");
        assert_eq!(end.opcode, frame::OPCODE_CLOSE);
        peer.close(1000, "");
        let exit = node.join().unwrap();
        assert!(matches!(exit, Ok(Exit::Stopped)), "{exit:?}");
    });
    assert_eq!(pair.name, next_name, "the node ended with the new pair, and gave it back");
}

/// Stops the node when a test fails in the scope, which would otherwise wait
/// for the node's thread for ever.
struct StopOnPanic<'a>(&'a Stopper);

impl Drop for StopOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.stop();
        }
    }
}

/// A TCP echo on the loopback for one connection; it reports the end of the
/// bytes that it reads.
fn tcp_echo() -> (u16, mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (ended, ended_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(LIMIT * 2)).unwrap();
        let mut buf = [0u8; 4096];
        loop {
            match tcp.read(&mut buf) {
                Ok(0) => {
                    let _ = ended.send(());
                    return;
                }
                Ok(n) => tcp.write_all(&buf[..n]).unwrap(),
                Err(_) => return,
            }
        }
    });
    (port, ended_rx)
}
