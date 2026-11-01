//! The stand-in edge of a quick tunnel (T-300), shared by its tests: the
//! node's registration, the edge's answers as the reference encoder writes
//! them, and the node served on one end of a pipe.

#![allow(dead_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::Request;
use podssh_relay::quick::capnp::Builder;
use podssh_relay::quick::headers;
use podssh_relay::quick::register::{Connector, Registration, FEATURES};
use podssh_relay::quick::roads::{Link, Road};
use podssh_relay::quick::serve::{serve, Ended, Step};
use podssh_ws::frame::{self, Frame, Role};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot};

pub const BOOTSTRAP: &[u8] = include_bytes!("../fixtures/quick/rpc-bootstrap.bin");
pub const CALL_REGISTER: &[u8] = include_bytes!("../fixtures/quick/rpc-call-register.bin");
pub const CALL_UNREGISTER: &[u8] = include_bytes!("../fixtures/quick/rpc-call-unregister.bin");
pub const FINISH: &[u8] = include_bytes!("../fixtures/quick/rpc-finish.bin");
pub const RETURN_DETAILS: &[u8] = include_bytes!("../fixtures/quick/rpc-return-details.bin");
pub const RETURN_REFUSED: &[u8] = include_bytes!("../fixtures/quick/rpc-return-refused.bin");
pub const LIMIT: Duration = Duration::from_secs(20);

pub const SECRET: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31,
];

/// The values of `register-params.txt`.
pub fn registration() -> Registration<'static> {
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

/// The values of [`registration`], owned, as a node's races hold them
/// (T-400).
pub fn connector() -> Connector {
    let values = registration();
    Connector {
        account_tag: values.account_tag.to_string(),
        secret: zeroize::Zeroizing::new(values.secret.to_vec()),
        tunnel_id: values.tunnel_id,
        client_id: values.client_id,
        version: values.version.to_string(),
        arch: values.arch.to_string(),
    }
}

/// A road whose dial gives the node's end of a pipe at once, and the edge's
/// end to the test, which plays the edge on it (T-400).
pub fn stand_in(name: &'static str, edges: mpsc::UnboundedSender<DuplexStream>) -> Road {
    let dial = async move {
        let (node_io, edge_io) = tokio::io::duplex(1 << 20);
        edges.send(edge_io).map_err(|_| "the test is gone".to_string())?;
        Ok::<Link, String>(Link::Http2(Box::new(node_io)))
    };
    Road { name, dial: Box::pin(dial) }
}

/// The edge's `Return` of `answer` whose results' content is not set: a
/// bootstrap's capability, or a method with no results, as the node reads
/// them.
pub fn empty_return(answer: u32) -> Vec<u8> {
    let (mut b, root) = Builder::new(1, 1);
    b.set_u16(root, 0, 3);
    let ret = b.init_struct(root, 0, 2, 1);
    b.set_u32(ret, 0, answer);
    b.init_struct(ret, 0, 0, 2);
    b.frame()
}

/// `len` bytes of `from`, within the limit.
pub async fn read_exactly(from: &mut RecvStream, len: usize) -> Vec<u8> {
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
pub async fn read_frame(from: &mut RecvStream) -> Frame {
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
pub async fn echo(stream: DuplexStream) {
    let (mut r, mut w) = tokio::io::split(stream);
    let _ = tokio::io::copy(&mut r, &mut w).await;
}

/// A node that serves `node_io` with the test's registration: its steps,
/// the word that stops it, and its end.
pub fn node(
    node_io: DuplexStream,
) -> (mpsc::UnboundedReceiver<Step>, oneshot::Sender<()>, tokio::task::JoinHandle<Result<(), Ended>>) {
    node_with(node_io, echo)
}

/// [`node`] on any stream, whose visitors go to `visit`.
pub fn node_with<IO, V, F>(
    node_io: IO,
    visit: V,
) -> (mpsc::UnboundedReceiver<Step>, oneshot::Sender<()>, tokio::task::JoinHandle<Result<(), Ended>>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    V: FnMut(DuplexStream) -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let (steps_tx, steps) = mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        let stop = async {
            let _ = stop_rx.await;
        };
        serve(node_io, &registration(), visit, steps_tx, stop).await
    });
    (steps, stop_tx, served)
}

/// The control stream, opened by the edge and registered: the edge's ends
/// of it, the node's `Finish` read.
pub async fn register(
    edge: &mut h2::client::SendRequest<Bytes>,
    steps: &mut mpsc::UnboundedReceiver<Step>,
) -> (SendStream<Bytes>, RecvStream) {
    let (to_node, from_node, _) = register_edge(edge).await;
    assert_eq!(steps.recv().await, Some(Step::Registered { location: "msp01".into() }));
    (to_node, from_node)
}

/// The edge's side of [`register`], for a node whose steps the test does not
/// read (a race's): the edge's ends of the control stream, and the node's
/// bootstrap and call of `registerConnection`, as they came.
pub async fn register_edge(edge: &mut h2::client::SendRequest<Bytes>) -> (SendStream<Bytes>, RecvStream, Vec<u8>) {
    let control = request(Some(headers::CONTROL_STREAM)).body(()).unwrap();
    let (answer, mut to_node) = edge.send_request(control, false).unwrap();
    let mut from_node = tokio::time::timeout(LIMIT, answer).await.unwrap().unwrap().into_body();
    let sent = read_exactly(&mut from_node, BOOTSTRAP.len() + CALL_REGISTER.len()).await;
    to_node.send_data(Bytes::from([empty_return(0), RETURN_DETAILS.to_vec()].concat()), false).unwrap();
    read_exactly(&mut from_node, FINISH.len()).await;
    (to_node, from_node, sent)
}

/// The index of the connection that `sent`, a registration's first bytes,
/// names: the fixtures name 0, and a registration of the test's values
/// differs from them in that one byte alone (T-402).
pub fn conn_index_of(sent: &[u8]) -> u8 {
    let fixture = [BOOTSTRAP, CALL_REGISTER].concat();
    assert_eq!(sent.len(), fixture.len(), "a registration of another size");
    let differ: Vec<usize> = (0..sent.len()).filter(|&at| sent[at] != fixture[at]).collect();
    match differ[..] {
        [] => 0,
        [at] if fixture[at] == 0 => sent[at],
        _ => panic!("the registration differs from the fixture's at {differ:?}"),
    }
}

/// A visitor's WebSocket, answered: the edge's ends of its stream.
pub async fn visitor(edge: &mut h2::client::SendRequest<Bytes>) -> (SendStream<Bytes>, RecvStream) {
    let visitor = request(Some(headers::WEBSOCKET)).header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
    let (answer, to_node) = edge.send_request(visitor.body(()).unwrap(), false).unwrap();
    let answer = tokio::time::timeout(LIMIT, answer).await.unwrap().unwrap();
    assert_eq!(answer.status(), 200);
    (to_node, answer.into_body())
}

/// The edge's end of the connection, shared: the h2 client writes through
/// one copy, and a test through another, between the client's frames, a
/// frame that the client cannot send (a GOAWAY). A copy kept also keeps the
/// connection open when the client is gone.
#[derive(Clone)]
pub struct Shared(pub Arc<Mutex<DuplexStream>>);

impl Shared {
    pub fn new(io: DuplexStream) -> Shared {
        Shared(Arc::new(Mutex::new(io)))
    }
}

impl AsyncRead for Shared {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_read(cx, buf)
    }
}

impl AsyncWrite for Shared {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_shutdown(cx)
    }
}

pub fn request(kind: Option<&str>) -> http::request::Builder {
    let builder = Request::get("http://localhost:8080/");
    match kind {
        Some(kind) => builder.header(headers::UPGRADE, kind),
        None => builder,
    }
}
