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

mod quick_harness;

use std::time::Duration;

use bytes::Bytes;
use podssh_relay::quick::headers::{self, META_ORIGIN, RESPONSE_HEADERS, RESPONSE_META};
use podssh_relay::quick::rpc;
use podssh_relay::quick::serve::{Ended, Step};
use podssh_ws::frame::{self, Frame, Role};
use quick_harness::*;

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

/// The edge's SRV record through a proxy at a port of this host where
/// nothing listens: no resolver answers, and the edge is the fixed one, with
/// the reason (T-339).
#[tokio::test]
async fn a_record_that_cannot_be_read_gives_the_fixed_names_and_why() {
    use podssh_relay::quick::edge;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let proxy = podssh_ws::proxy::Proxy::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let found = edge::find(&podssh_ws::ProxyChoice::Via(proxy)).await;
    assert_eq!(found.regions, edge::REGIONS.map(String::from).to_vec());
    assert_eq!(found.port, edge::PORT);
    let why = found.fixed.expect("the reason of the fixed names");
    assert!(why.contains("the edge's SRV record was not read"), "{why}");
}
