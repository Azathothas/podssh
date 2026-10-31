//! A quick tunnel's connection when the edge or a visitor misbehaves
//! (T-300, the review's findings), against the stand-in edge: a visitor
//! that the edge resets before its answer ends alone; the edge's GOAWAY,
//! the end of its control stream, and an edge that answers no PING each
//! end the connection, so that the node connects again; a visitor whose
//! user reads nothing holds no other stream; and pings sent while the
//! node's writer waits for the edge's window get one pong, the latest.

#![cfg(feature = "quick")]

mod quick_harness;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use podssh_relay::quick::control::Failure;
use podssh_relay::quick::serve::{Ended, PING_EVERY, PONG_WAIT};
use podssh_ws::frame::{self, Frame, Role};
use quick_harness::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// A frame of a visitor, masked as a client writes it.
fn masked(opcode: u8, payload: &[u8]) -> Bytes {
    Bytes::from(frame::encode(&Frame { fin: true, opcode, payload: payload.to_vec() }, Role::Client, [3, 1, 4, 1]))
}

/// Each frame of the node on `from`, until `done` says that it has them.
async fn frames_until(from: &mut RecvStream, mut done: impl FnMut(&[Frame]) -> bool) -> Vec<Frame> {
    let (mut got, mut frames) = (Vec::new(), Vec::new());
    loop {
        while let Some((frame, used)) = frame::decode(&got, Role::Server).unwrap() {
            got.drain(..used);
            frames.push(frame);
        }
        if done(&frames) {
            return frames;
        }
        let chunk = tokio::time::timeout(LIMIT, from.data()).await.expect("a frame in time");
        let chunk = chunk.expect("more bytes").expect("no error");
        let _ = from.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
}

#[tokio::test]
async fn a_visitor_that_the_edge_resets_before_its_answer_ends_alone() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (mut steps, _stop, served) = node(node_io);
    let (mut edge, conn) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(conn);
    let _control = register(&mut edge, &mut steps).await;
    // The request and its reset leave together: the node takes the stream
    // after the edge reset it.
    let reset = request(Some(podssh_relay::quick::headers::WEBSOCKET)).header("sec-websocket-key", "a2V5");
    let (_, mut to_node) = edge.send_request(reset.body(()).unwrap(), false).unwrap();
    to_node.send_reset(h2::Reason::CANCEL);
    // The next visitor is served on the same connection.
    let (mut out, mut back) = visitor(&mut edge).await;
    out.send_data(masked(0x2, b"after the reset"), false).unwrap();
    let echoed = frames_until(&mut back, |f| !f.is_empty()).await;
    assert_eq!(echoed[0].payload, b"after the reset");
    assert!(!served.is_finished(), "the connection is still served");
}

#[tokio::test]
async fn the_edge_s_goaway_ends_the_connection_at_once() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (mut steps, _stop, served) = node(node_io);
    let shared = Shared::new(edge_io);
    let (mut edge, conn) = h2::client::handshake(shared.clone()).await.unwrap();
    tokio::spawn(conn);
    let _control = register(&mut edge, &mut steps).await;
    // The client is idle: a GOAWAY of the edge's, its last stream the
    // control stream, between the client's frames.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let goaway = [0, 0, 8, 0x7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    shared.clone().write_all(&goaway).await.unwrap();
    let ended = tokio::time::timeout(LIMIT, served).await.expect("the end in time").unwrap().unwrap_err();
    assert!(matches!(ended, Ended::GoingAway), "{ended}");
}

#[tokio::test]
async fn a_control_stream_that_the_edge_ends_ends_the_connection() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (mut steps, _stop, served) = node(node_io);
    let (mut edge, conn) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(conn);
    let (mut to_node, _from_node) = register(&mut edge, &mut steps).await;
    to_node.send_data(Bytes::new(), true).unwrap();
    let ended = tokio::time::timeout(LIMIT, served).await.expect("the end in time").unwrap().unwrap_err();
    assert!(matches!(ended, Ended::Control(Failure::Ended)), "{ended}");
}

#[tokio::test(start_paused = true)]
async fn an_edge_that_answers_no_ping_is_gone() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (mut steps, _stop, served) = node(node_io);
    let shared = Shared::new(edge_io);
    let (mut edge, conn) = h2::client::handshake(shared.clone()).await.unwrap();
    let client = tokio::spawn(conn);
    let _control = register(&mut edge, &mut steps).await;
    // The edge stops answering; its end stays open, in `shared`.
    client.abort();
    let started = tokio::time::Instant::now();
    let ended = tokio::time::timeout(4 * PING_EVERY, served).await.expect("the end in time").unwrap().unwrap_err();
    assert!(matches!(ended, Ended::Silent), "{ended}");
    assert!(started.elapsed() <= PING_EVERY + PONG_WAIT + Duration::from_secs(1), "{:?}", started.elapsed());
    drop((edge, shared));
}

#[tokio::test]
async fn a_visitor_whose_user_reads_nothing_holds_no_other_visitor() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    // The first visitor's user takes its stream and reads nothing of it;
    // each later one echoes.
    let count = Arc::new(AtomicUsize::new(0));
    let visit = move |stream: DuplexStream| {
        let first = count.fetch_add(1, Ordering::SeqCst) == 0;
        async move {
            if first {
                tokio::time::sleep(Duration::from_secs(600)).await;
                drop(stream);
            } else {
                echo(stream).await;
            }
        }
    };
    let (mut steps, _stop, _served) = node_with(node_io, visit);
    let (mut edge, conn) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(conn);
    let _control = register(&mut edge, &mut steps).await;
    let (mut stalled, _stalled_back) = visitor(&mut edge).await;
    for _ in 0..8 {
        stalled.send_data(masked(0x2, &[9u8; 30 * 1024]), false).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (mut out, mut back) = visitor(&mut edge).await;
    out.send_data(masked(0x2, b"beside a stalled stream"), false).unwrap();
    let echoed = frames_until(&mut back, |f| !f.is_empty()).await;
    assert_eq!(echoed[0].payload, b"beside a stalled stream");
}

#[tokio::test]
async fn pings_while_the_writer_waits_get_one_pong_the_latest() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    // The user writes 1 MiB at once, which waits for the visitor's window.
    let visit = |stream: DuplexStream| async move {
        let (mut r, mut w) = tokio::io::split(stream);
        let _ = w.write_all(&vec![7u8; 1 << 20]).await;
        let mut sink = Vec::new();
        let _ = r.read_to_end(&mut sink).await;
    };
    let (mut steps, _stop, _served) = node_with(node_io, visit);
    let (mut edge, conn) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(conn);
    let _control = register(&mut edge, &mut steps).await;
    let (mut out, mut back) = visitor(&mut edge).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    const PINGS: u16 = 300;
    for n in 0..PINGS {
        out.send_data(masked(0x9, &n.to_be_bytes()), false).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let last = (PINGS - 1).to_be_bytes().to_vec();
    let frames = frames_until(&mut back, |f| {
        let data: usize = f.iter().filter(|f| f.opcode == 0x2).map(|f| f.payload.len()).sum();
        data == 1 << 20 && f.iter().any(|f| f.opcode == 0xA && f.payload == last)
    })
    .await;
    let pongs = frames.iter().filter(|f| f.opcode == 0xA).count();
    assert!(pongs < 10, "{pongs} pongs for {PINGS} pings: the pings waited in a queue");
}

#[tokio::test(start_paused = true)]
async fn an_edge_that_never_shakes_hands_is_gone_and_a_stop_ends_the_wait() {
    use podssh_relay::quick::serve::HANDSHAKE_WAIT;
    let (node_io, _edge_io) = tokio::io::duplex(1 << 20);
    let (_steps, _stop, served) = node(node_io);
    let started = tokio::time::Instant::now();
    let ended = tokio::time::timeout(2 * HANDSHAKE_WAIT, served).await.expect("the end in time").unwrap().unwrap_err();
    assert!(matches!(ended, Ended::Silent), "{ended}");
    assert_eq!(started.elapsed(), HANDSHAKE_WAIT);
    let (node_io, _edge_io) = tokio::io::duplex(1 << 20);
    let (_steps, stop, served) = node(node_io);
    stop.send(()).unwrap();
    tokio::time::timeout(LIMIT, served).await.expect("the end in time").unwrap().expect("a stop is no failure");
}
