//! A quick tunnel's connection against a stand-in edge (T-300), written
//! from cloudflared's source at 2026.10.6 (`connection/http2.go`, and its
//! tests' edge in `connection/http2_test.go`): the client of HTTP/2 is the
//! `h2` crate's, and the edge's side of the RPC is bytes of the reference
//! encoder, `capnp encode` (`scripts/quick-fixtures.sh`). The edge opens the
//! control stream and takes the registration; a visitor's WebSocket gets
//! the serialized headers of a 101 and reaches the node's stream, both
//! ways; the end unregisters on the same capability. The planted node that
//! sends the 101's headers as they are, not serialized, fails the first
//! test.

#![cfg(feature = "quick")]

use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use http::Request;
use podssh_relay::quick::capnp::Builder;
use podssh_relay::quick::headers::{self, META_ORIGIN, RESPONSE_HEADERS, RESPONSE_META};
use podssh_relay::quick::register::{Registration, FEATURES};
use podssh_relay::quick::rpc;
use podssh_relay::quick::serve::{serve, Ended, Step};
use podssh_ws::frame::{self, Frame, Role};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, oneshot};

const BOOTSTRAP: &[u8] = include_bytes!("fixtures/quick/rpc-bootstrap.bin");
const CALL_REGISTER: &[u8] = include_bytes!("fixtures/quick/rpc-call-register.bin");
const CALL_UNREGISTER: &[u8] = include_bytes!("fixtures/quick/rpc-call-unregister.bin");
const FINISH: &[u8] = include_bytes!("fixtures/quick/rpc-finish.bin");
const RETURN_DETAILS: &[u8] = include_bytes!("fixtures/quick/rpc-return-details.bin");
const RETURN_REFUSED: &[u8] = include_bytes!("fixtures/quick/rpc-return-refused.bin");
const LIMIT: Duration = Duration::from_secs(20);

const SECRET: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31,
];

/// The values of `register-params.txt`.
fn registration() -> Registration<'static> {
    Registration {
        account_tag: "0123456789abcdef0123456789abcdef",
        secret: &SECRET,
        tunnel_id: [0x8e, 0x9d, 0x2f, 0x0c, 0x4b, 0x1a, 0x4f, 0x6e, 0x9c, 0x3d, 0x5a, 0x7b, 0x2e, 0x1f, 0x0d, 0x4c],
        conn_index: 0,
        client_id: [0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00],
        features: FEATURES,
        version: "podssh 1.0.0-beta.2",
        arch: "linux_amd64",
    }
}

/// The edge's `Return` of `answer` whose results' content is not set: a
/// bootstrap's capability, or a method with no results, as the node reads
/// them.
fn empty_return(answer: u32) -> Vec<u8> {
    let (mut b, root) = Builder::new(1, 1);
    b.set_u16(root, 0, 3);
    let ret = b.init_struct(root, 0, 2, 1);
    b.set_u32(ret, 0, answer);
    b.init_struct(ret, 0, 0, 2);
    b.frame()
}

/// `len` bytes of `from`, within the limit.
async fn read_exactly(from: &mut RecvStream, len: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < len {
        let chunk = tokio::time::timeout(LIMIT, from.data()).await.expect("bytes in time");
        let chunk = chunk.expect("more bytes").expect("no error");
        let _ = from.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got.len(), len, "more bytes than asked for: {got:?}");
    got
}

/// One frame of the node, unmasked as a server writes it.
async fn read_frame(from: &mut RecvStream) -> Frame {
    let mut got = Vec::new();
    loop {
        if let Some((frame, _)) = frame::decode(&got, Role::Server).unwrap() {
            return frame;
        }
        let chunk = tokio::time::timeout(LIMIT, from.data()).await.expect("a frame in time");
        let chunk = chunk.expect("more bytes").expect("no error");
        let _ = from.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
}

/// The node's side of a visitor: an echo.
async fn echo(stream: DuplexStream) {
    let (mut r, mut w) = tokio::io::split(stream);
    let _ = tokio::io::copy(&mut r, &mut w).await;
}

/// A node that serves `node_io` with the test's registration: its steps,
/// the word that stops it, and its end.
fn node(
    node_io: DuplexStream,
) -> (mpsc::UnboundedReceiver<Step>, oneshot::Sender<()>, tokio::task::JoinHandle<Result<(), Ended>>) {
    let (steps_tx, steps) = mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        let stop = async {
            let _ = stop_rx.await;
        };
        serve(node_io, &registration(), echo, steps_tx, stop).await
    });
    (steps, stop_tx, served)
}

fn request(kind: Option<&str>) -> http::request::Builder {
    let builder = Request::get("http://localhost:8080/");
    match kind {
        Some(kind) => builder.header(headers::UPGRADE, kind),
        None => builder,
    }
}

#[tokio::test]
async fn the_edge_registers_the_node_and_a_visitor_s_websocket_reaches_it_both_ways() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (mut steps, stop, served) = node(node_io);
    let (mut edge, conn) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(conn);

    // The control stream: the node's bootstrap and call, as the reference writes them.
    let control = request(Some(headers::CONTROL_STREAM)).body(()).unwrap();
    let (answer, mut to_node) = edge.send_request(control, false).unwrap();
    let answer = tokio::time::timeout(LIMIT, answer).await.unwrap().unwrap();
    assert_eq!(answer.status(), 200);
    let mut from_node = answer.into_body();
    assert_eq!(
        read_exactly(&mut from_node, BOOTSTRAP.len() + CALL_REGISTER.len()).await,
        [BOOTSTRAP, CALL_REGISTER].concat()
    );
    to_node.send_data(Bytes::from([empty_return(0), RETURN_DETAILS.to_vec()].concat()), false).unwrap();
    assert_eq!(steps.recv().await, Some(Step::Registered { location: "msp01".into() }));
    assert_eq!(read_exactly(&mut from_node, FINISH.len()).await, FINISH);

    // A visitor: the 101's headers, serialized, as cloudflared answers.
    let visitor = request(Some(headers::WEBSOCKET)).header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
    let (answer, mut visitor_out) = edge.send_request(visitor.body(()).unwrap(), false).unwrap();
    let answer = tokio::time::timeout(LIMIT, answer).await.unwrap().unwrap();
    assert_eq!(answer.status(), 200, "a 101 goes as 200 over HTTP/2");
    let serialized = answer.headers().get(RESPONSE_HEADERS).expect("the serialized headers").to_str().unwrap();
    let origin = headers::deserialize(serialized).expect("they read");
    assert!(origin.contains(&("Sec-Websocket-Accept".into(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".into())), "{origin:?}");
    assert!(answer.headers().get("upgrade").is_none(), "no header of HTTP/1 outside the serialized one");
    assert_eq!(answer.headers().get(RESPONSE_META).unwrap(), META_ORIGIN);
    assert_eq!(steps.recv().await, Some(Step::Visitor));
    let mut visitor_in = answer.into_body();
    // A message of the visitor, masked, comes back from the node unmasked.
    let message = Frame { fin: true, opcode: 0x2, payload: b"hello, node".to_vec() };
    visitor_out.send_data(Bytes::from(frame::encode(&message, Role::Client, [7, 1, 9, 4])), false).unwrap();
    let echoed = read_frame(&mut visitor_in).await;
    assert_eq!((echoed.opcode, echoed.payload.as_slice()), (0x2, &b"hello, node"[..]));

    // The end: the node unregisters on the bootstrap's capability, and closes.
    stop.send(()).unwrap();
    assert_eq!(read_exactly(&mut from_node, CALL_UNREGISTER.len()).await, CALL_UNREGISTER);
    to_node.send_data(Bytes::from(empty_return(2)), false).unwrap();
    assert_eq!(steps.recv().await, Some(Step::Unregistered));
    let finishes = [rpc::finish(2), rpc::finish(0)].concat();
    assert_eq!(read_exactly(&mut from_node, finishes.len()).await, finishes);
    // The visitor's stream is still open: the node closes after its grace.
    tokio::time::timeout(LIMIT, served).await.unwrap().unwrap().expect("the end was asked for");
    drop((edge, to_node, visitor_out));
}

#[tokio::test]
async fn a_refused_registration_ends_the_connection_with_its_cause() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (_steps, _stop, served) = node(node_io);
    let (mut edge, conn) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(conn);
    let (answer, mut to_node) =
        edge.send_request(request(Some(headers::CONTROL_STREAM)).body(()).unwrap(), false).unwrap();
    let mut from_node = tokio::time::timeout(LIMIT, answer).await.unwrap().unwrap().into_body();
    read_exactly(&mut from_node, BOOTSTRAP.len() + CALL_REGISTER.len()).await;
    to_node.send_data(Bytes::from([empty_return(0), RETURN_REFUSED.to_vec()].concat()), false).unwrap();
    let ended = tokio::time::timeout(LIMIT, served).await.unwrap().unwrap().unwrap_err();
    let Ended::Refused { cause, retry, after } = ended else { panic!("not a refusal: {ended}") };
    assert_eq!((cause.as_str(), retry, after), ("the tunnel is not known", true, Duration::from_secs(5)));
}

#[tokio::test]
async fn any_other_request_gets_404_with_no_body() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (_steps, stop, served) = node(node_io);
    let (mut edge, conn) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(conn);
    for kind in [None, Some(headers::CONFIGURATION_UPDATE)] {
        let (answer, _) = edge.send_request(request(kind).body(()).unwrap(), true).unwrap();
        let answer = tokio::time::timeout(LIMIT, answer).await.unwrap().unwrap();
        assert_eq!(answer.status(), 404);
        assert!(answer.into_body().is_end_stream(), "no body");
    }
    // An end with no control stream closes at once; the edge stays until then.
    stop.send(()).unwrap();
    tokio::time::timeout(LIMIT, served).await.unwrap().unwrap().expect("the end was asked for");
    drop(edge);
}
