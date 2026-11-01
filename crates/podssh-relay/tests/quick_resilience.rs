//! A quick tunnel's connection when the edge or a visitor misbehaves
//! (T-300, the review's findings), against the stand-in edge: a visitor
//! that the edge resets before its answer ends alone; the end of its control
//! stream, and an edge that answers no PING, each end the connection, so
//! that the node connects again; a visitor whose user reads nothing holds
//! no other stream; and pings sent while the node's writer waits for the
//! edge's window get one pong, the latest. And the race of the roads to the
//! edge (T-400): a silent road gives way to the next after the stagger, and
//! QUIC whose probe of UDP gets no answer gives way at the probe's end. And
//! the edge's GOAWAY (T-402): said at once, the connection's visitors kept
//! until the edge closes it or for the drain, the node's next connection
//! registered meanwhile; and a second connection, of the index 1.

#![cfg(feature = "quick")]

mod quick_harness;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use podssh_relay::failover::STAGGER;
use podssh_relay::quick::control::Failure;
use podssh_relay::quick::edge::Edge;
use podssh_relay::quick::keep::{self, Keep, Made, Plan, Roads};
use podssh_relay::quick::probe;
use podssh_relay::quick::roads::{self, Link, Road};
use podssh_relay::quick::serve::{Ended, Step, DRAIN, PING_EVERY, PONG_WAIT};
use podssh_ws::frame::{self, Frame, Role};
use quick_harness::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, watch};
use tokio::time::{timeout, Instant};

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

/// The edge's GOAWAY, its last stream `last`, as the edge's client of HTTP/2
/// cannot send one: written between the client's frames, once it is idle.
async fn goaway(shared: &Shared, last: u8) {
    tokio::time::sleep(Duration::from_millis(100)).await;
    let frame = [0, 0, 8, 0x7, 0, 0, 0, 0, 0, 0, 0, 0, last, 0, 0, 0, 0];
    shared.clone().write_all(&frame).await.unwrap();
}

#[tokio::test]
async fn the_edge_s_goaway_is_said_at_once_and_its_close_ends_the_drain() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (mut steps, _stop, served) = node(node_io);
    let shared = Shared::new(edge_io);
    let (mut edge, conn) = h2::client::handshake(shared.clone()).await.unwrap();
    let client = tokio::spawn(conn);
    let control = register(&mut edge, &mut steps).await;
    goaway(&shared, 1).await;
    let said = tokio::time::timeout(LIMIT, steps.recv()).await.expect("said in time");
    assert_eq!(said, Some(Step::GoingAway));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!served.is_finished(), "the connection drains");
    // The edge closes the connection: the drain ends.
    client.abort();
    drop((edge, control, shared));
    let ended = tokio::time::timeout(LIMIT, served).await.expect("the end in time").unwrap().unwrap_err();
    assert!(matches!(ended, Ended::GoingAway), "{ended}");
}

#[tokio::test(start_paused = true)]
async fn after_a_goaway_a_visitor_goes_on_for_the_drain_at_most() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (mut steps, _stop, served) = node(node_io);
    let shared = Shared::new(edge_io);
    let (mut edge, conn) = h2::client::handshake(shared.clone()).await.unwrap();
    tokio::spawn(conn);
    let _control = register(&mut edge, &mut steps).await;
    let (mut out, mut back) = visitor(&mut edge).await;
    assert_eq!(steps.recv().await, Some(Step::Visitor));
    goaway(&shared, 3).await;
    assert_eq!(steps.recv().await, Some(Step::GoingAway));
    let started = Instant::now();
    // The visitor still echoes after the GOAWAY, a minute later too.
    tokio::time::sleep(Duration::from_secs(60)).await;
    out.send_data(masked(0x2, b"a minute into the drain"), false).unwrap();
    assert_eq!(read_frame(&mut back).await.payload, b"a minute into the drain");
    let ended = tokio::time::timeout(2 * DRAIN, served).await.expect("the end in time").unwrap().unwrap_err();
    assert!(matches!(ended, Ended::GoingAway), "{ended}");
    let took = started.elapsed();
    assert!(took >= DRAIN - Duration::from_secs(1) && took <= DRAIN + Duration::from_secs(1), "{took:?}");
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

/// A road that never answers, as an edge whose port takes packets and says
/// nothing: its dial waits for ever, and `dropped` turns when the race lets
/// it go.
fn silent(dropped: Arc<AtomicBool>) -> Road {
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let dial = async move {
        let _dropped = Dropped(dropped);
        std::future::pending::<Result<Link, String>>().await
    };
    Road { name: roads::QUIC, dial: Box::pin(dial) }
}

/// The edge's side of a race of `stand_in` roads: the end of the road that
/// the node dialed, when it came after `started`, HTTP/2's handshake and the
/// registration; the edge's client, and its ends of the control stream.
type EdgeSide = (h2::client::SendRequest<Bytes>, (h2::SendStream<Bytes>, RecvStream, Vec<u8>), Duration);

type Edges = mpsc::UnboundedReceiver<DuplexStream>;

fn edge_side(mut at_edge: Edges, started: Instant) -> tokio::task::JoinHandle<EdgeSide> {
    tokio::spawn(async move {
        let io = timeout(LIMIT, at_edge.recv()).await.expect("a road in time").expect("a road");
        let dialed = started.elapsed();
        let (mut client, connection) = h2::client::handshake(io).await.unwrap();
        tokio::spawn(connection);
        let control = register_edge(&mut client).await;
        (client, control, dialed)
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_edge_gives_way_to_the_next_road_within_seconds() {
    let (edges, at_edge) = mpsc::unbounded_channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let ways = vec![silent(dropped.clone()), stand_in(roads::HTTP2, edges)];
    let (_stop, all) = watch::channel(false);
    let started = Instant::now();
    let edge = edge_side(at_edge, started);
    let race = timeout(LIMIT, roads::race(ways, Arc::new(connector()), 0, echo, all)).await.expect("in time");
    let took = started.elapsed();
    let (mut client, _control, dialed) = edge.await.unwrap();
    // The second road started once the silent one had had its stagger.
    assert!(dialed >= STAGGER - Duration::from_millis(50) && dialed < STAGGER + Duration::from_secs(1), "{dialed:?}");
    assert!(took < STAGGER + Duration::from_secs(3), "the race took {took:?}");
    let serving = race.kept.expect("the second road registered");
    assert_eq!((serving.road, serving.location.as_str()), (roads::HTTP2, "msp01"));
    assert_eq!(race.silent, [roads::QUIC]);
    assert!(race.failed.is_empty() && race.dismissed.is_empty());
    // The silent road was let go: its dial is dropped.
    let gone = async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    timeout(LIMIT, gone).await.expect("the silent road dropped");
    // The connection kept serves: a visitor's message comes back.
    let (mut out, mut back) = visitor(&mut client).await;
    out.send_data(masked(0x2, b"through the road that won"), false).unwrap();
    assert_eq!(read_frame(&mut back).await.payload, b"through the road that won");
    drop(serving);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_whose_probe_gets_no_answer_gives_way_at_once() {
    // A port that takes each datagram and answers none, as a network that
    // drops UDP further on.
    let dropping = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = dropping.local_addr().unwrap().port();
    let found = Edge { regions: vec!["127.0.0.1".into()], port, fixed: None };
    let (edges, at_edge) = mpsc::unbounded_channel();
    let ways = vec![roads::quic(found), stand_in(roads::HTTP2, edges)];
    let (_stop, all) = watch::channel(false);
    let started = Instant::now();
    let edge = edge_side(at_edge, started);
    let race = timeout(LIMIT, roads::race(ways, Arc::new(connector()), 0, echo, all)).await.expect("in time");
    let (_client, _control, dialed) = edge.await.unwrap();
    // HTTP/2 started at the probe's end, long before the stagger.
    let early = probe::WAIT - Duration::from_millis(50);
    assert!(dialed >= early && dialed < STAGGER - Duration::from_millis(500), "{dialed:?}");
    assert_eq!(race.kept.as_ref().map(|serving| serving.road), Some(roads::HTTP2));
    let [(road, why)] = &race.failed[..] else { panic!("{} roads failed", race.failed.len()) };
    assert_eq!(*road, roads::QUIC);
    assert!(why.to_string().contains("said nothing within 300 ms"), "{why}");
    // The probe's packet reached the port: 1200 bytes, the reserved version.
    dropping.set_nonblocking(true).unwrap();
    let mut packet = [0u8; 1500];
    let n = dropping.recv(&mut packet).expect("the probe's packet");
    assert_eq!((n, &packet[1..5]), (probe::PADDED, &probe::RESERVED[..]));
}

/// The node's roads for `keep`: one stand-in road for each race, whose dial
/// gives the test the race's plan and the edge's end of a pipe.
fn planned(edges: mpsc::UnboundedSender<(Plan, DuplexStream)>) -> Roads {
    Arc::new(move |plan: Plan| -> Made {
        let edges = edges.clone();
        let dial = async move {
            let (node_io, edge_io) = tokio::io::duplex(1 << 20);
            edges.send((plan, edge_io)).map_err(|_| "the test is gone".to_string())?;
            Ok::<Link, String>(Link::Http2(Box::new(node_io)))
        };
        Box::pin(async move { vec![Road { name: roads::HTTP2, dial: Box::pin(dial) }] })
    })
}

/// What [`kept`] gives: the node's keeper, the edge's side of each
/// connection that it plans, and its lines.
type Kept = (Keep<fn(DuplexStream) -> Echo>, Planned, Lines);

/// A node kept by `keep` with `connections`, each visitor echoed, its lines
/// in the list.
fn kept(connections: u8) -> Kept {
    let (edges, at_edge) = mpsc::unbounded_channel();
    let lines = Lines::default();
    let said = lines.clone();
    let say = Arc::new(move |line: String| said.lock().unwrap().push(line));
    let visit: fn(DuplexStream) -> Echo = |stream| Box::pin(echo(stream));
    let (connector, roads, ready) = (Arc::new(connector()), planned(edges), Box::new(|| {}));
    (Keep { connector, visit, roads, say, ready, connections }, at_edge, lines)
}

type Echo = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
type Lines = Arc<Mutex<Vec<String>>>;
type Planned = mpsc::UnboundedReceiver<(Plan, DuplexStream)>;
/// The edge's ends of a control stream.
type Control = (h2::SendStream<Bytes>, RecvStream);

/// The edge's side of a connection that the node dialed: HTTP/2's handshake
/// and the registration; the client, the ends of the control stream, and the
/// index that the registration named.
async fn edge_of(io: DuplexStream) -> (h2::client::SendRequest<Bytes>, Control, u8) {
    let (mut client, connection) = h2::client::handshake(io).await.unwrap();
    tokio::spawn(connection);
    let (to_node, from_node, sent) = register_edge(&mut client).await;
    (client, (to_node, from_node), conn_index_of(&sent))
}

/// A visitor's message on its stream `out`, and its echo on `back`.
async fn echoes(out: &mut h2::SendStream<Bytes>, back: &mut RecvStream, message: &[u8]) {
    out.send_data(masked(0x2, message), false).unwrap();
    assert_eq!(read_frame(back).await.payload, message);
}

/// The stop's unregistration of each connection, answered.
async fn unregistered(controls: [&mut Control; 2]) {
    for (to_node, from_node) in controls {
        assert_eq!(read_exactly(from_node, CALL_UNREGISTER.len()).await, CALL_UNREGISTER);
        to_node.send_data(Bytes::from(empty_return(2)), false).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_visitor_echoes_across_a_goaway() {
    let (node, mut at_edge, lines) = kept(1);
    let (stop, stopped) = watch::channel(false);
    let edge = async {
        // The first connection, of the index 0, and a visitor on it.
        let (plan, io) = timeout(LIMIT, at_edge.recv()).await.unwrap().unwrap();
        assert_eq!(plan, Plan { conn_index: 0, first: None });
        let first_io = Shared::new(io);
        let (mut first, connection) = h2::client::handshake(first_io.clone()).await.unwrap();
        let first_open = tokio::spawn(connection);
        let (to_node, from_node, sent) = register_edge(&mut first).await;
        let mut first_control = (to_node, from_node);
        assert_eq!(conn_index_of(&sent), 0);
        let (mut out, mut back) = visitor(&mut first).await;
        echoes(&mut out, &mut back, b"before the goaway").await;
        // The edge's GOAWAY, its last stream the visitor's.
        goaway(&first_io, 3).await;
        // The next connection comes at once, of the other index of the
        // pair, and registers while the first is open.
        let (plan, io) = timeout(LIMIT, at_edge.recv()).await.expect("the next connection at once").unwrap();
        assert_eq!(plan, Plan { conn_index: 2, first: Some(roads::HTTP2) });
        let (mut second, mut second_control, index) = edge_of(io).await;
        assert_eq!(index, 2);
        assert!(!first_open.is_finished(), "the first connection closed before the second registered");
        // The first connection's visitor still echoes, across the GOAWAY,
        // and a new visitor comes on the second.
        echoes(&mut out, &mut back, b"across the goaway").await;
        let (mut out2, mut back2) = visitor(&mut second).await;
        echoes(&mut out2, &mut back2, b"on the next connection").await;
        // The stop: each connection unregisters, the one that drains too.
        stop.send(true).unwrap();
        unregistered([&mut first_control, &mut second_control]).await;
    };
    let (ended, ()) = tokio::join!(timeout(LIMIT, keep::keep(node, stopped)), edge);
    ended.expect("the end in time").expect("a stop is no failure");
    let lines = lines.lock().unwrap();
    assert!(lines.iter().any(|line| line.starts_with("the edge sent GOAWAY: a new connection now")), "{lines:?}");
    let next = "connection 2: registered at Cloudflare's msp01, over HTTP/2";
    assert!(lines.iter().any(|line| line.starts_with(next)), "{lines:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_connection_registers_as_index_1_once_the_first_did() {
    let (node, mut at_edge, lines) = kept(2);
    let (stop, stopped) = watch::channel(false);
    let edge = async {
        let (plan, io) = timeout(LIMIT, at_edge.recv()).await.unwrap().unwrap();
        assert_eq!(plan, Plan { conn_index: 0, first: None });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(at_edge.try_recv().is_err(), "the second connection waits for the first's registration");
        let (mut first, mut first_control, index) = edge_of(io).await;
        assert_eq!(index, 0);
        // The second, with the road that won the first.
        let (plan, io) = timeout(LIMIT, at_edge.recv()).await.expect("the second connection").unwrap();
        assert_eq!(plan, Plan { conn_index: 1, first: Some(roads::HTTP2) });
        let (mut second, mut second_control, index) = edge_of(io).await;
        assert_eq!(index, 1);
        // Each serves a visitor.
        for client in [&mut first, &mut second] {
            let (mut out, mut back) = visitor(client).await;
            echoes(&mut out, &mut back, b"on either connection").await;
        }
        stop.send(true).unwrap();
        unregistered([&mut first_control, &mut second_control]).await;
    };
    let (ended, ()) = tokio::join!(timeout(LIMIT, keep::keep(node, stopped)), edge);
    ended.expect("the end in time").expect("a stop is no failure");
    let lines = lines.lock().unwrap();
    let second = "connection 1: registered at Cloudflare's msp01, over HTTP/2";
    assert!(lines.iter().any(|line| line.starts_with(second)), "{lines:?}");
}
