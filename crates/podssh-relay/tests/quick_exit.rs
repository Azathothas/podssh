//! The quick tunnel's node as an exit (T-459), against the stand-in edge of
//! T-300: a visitor's WebSocket is one link of the resumable layer, with
//! the end-to-end channel above it, as `podssh node NAME --exit
//! --quick-tunnel` serves it; the operator's word names a target, and the
//! node's routes give it to the exit's dial. The dial here stands for the
//! binary's (`node_exit::dial`, whose checks of each address its own tests
//! hold): a target inside the range that it lends is reached, and one of no
//! range is refused with the exit's words, its port never dialled. The
//! planted node that serves its one TARGET in place of the routes, as the
//! node did before, fails the first test: the operator's exit word is then
//! no route of that node.

#![cfg(all(feature = "quick", feature = "pair"))]

mod e2e_harness;
mod quick_harness;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use e2e_harness::{identity, node as e2e_node, PIPE};
use podssh_relay::e2e::exit_word;
use podssh_relay::e2e::{ends, Error, Refusal};
use podssh_relay::identity::PublicKey;
use podssh_relay::reverse::framing::SessionId;
use podssh_relay::reverse::routes::{ExitDial, Grant, Routed, Routes};
use podssh_relay::reverse::{Handler, Layered};
use podssh_relay::session::client;
use podssh_relay::session::resume::{self, Next};
use podssh_relay::session::{Ask, Ended, OsEntropy, Settings};
use podssh_ws::frame::{self, Frame, Role};
use quick_harness::{node_with, register, visitor, LIMIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

const MIB: usize = 1 << 20;

/// A TCP service on the loopback that writes `word` and closes; the count
/// of its connections.
async fn service(word: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(word.as_bytes()).await;
        }
    });
    (port, count)
}

/// The exit's dial: the loopback's port `lent` alone, as a range of
/// `--routes` lends it; each other target refused before any dial.
fn exit_dial(lent: u16) -> Arc<ExitDial> {
    Arc::new(move |_peer: PublicKey, host: String, port: u16| {
        Box::pin(async move {
            if host != "127.0.0.1" || port != lent {
                return Err(Refusal::Other(format!("{host}:{port} is inside no range of this exit")));
            }
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| Refusal::NoTarget(e.to_string()))
        })
    })
}

/// The node's handler as `podssh node --exit --quick-tunnel` builds it: the
/// layer, the channel, and the routes with the exit's dial and no target
/// of its own.
fn exit_handler(lent: u16) -> Arc<Layered<Routed>> {
    let (node_end, _lines) = e2e_node(identity(2), |_| Ok(()));
    let grant: Arc<Grant> = Arc::new(|_: &PublicKey, _: &str| Ok(()));
    let routes = Routes {
        routes: Arc::new(Vec::new()),
        grant,
        timeout: LIMIT,
        sshd: false,
        exit: Some(exit_dial(lent)),
        shared: None,
    };
    Arc::new(Layered::new(Routed::new(routes, node_end), Settings::default(), 64 * MIB))
}

/// The edge's ends of a visitor's WebSocket as a byte stream: each write a
/// masked binary frame, each read the payload of the node's frames.
async fn link_of(edge: &mut h2::client::SendRequest<Bytes>) -> DuplexStream {
    let (mut to_node, mut from_node) = visitor(edge).await;
    let (link, mut ours) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let (mut r, mut w) = tokio::io::split(&mut ours);
        let up = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match r.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let message = Frame { fin: true, opcode: 0x2, payload: buf[..n].to_vec() };
                let bytes = frame::encode(&message, Role::Client, rand::random::<[u8; 4]>());
                if to_node.send_data(Bytes::from(bytes), false).is_err() {
                    return;
                }
            }
        };
        let down = async {
            let mut got = Vec::new();
            loop {
                while let Ok(Some((message, used))) = frame::decode(&got, Role::Server) {
                    got.drain(..used);
                    if message.opcode == 0x8 || w.write_all(&message.payload).await.is_err() {
                        return;
                    }
                }
                let Some(Ok(chunk)) = from_node.data().await else { return };
                let _ = from_node.flow_control().release_capacity(chunk.len());
                got.extend_from_slice(&chunk);
            }
        };
        tokio::select! {
            () = up => {}
            () = down => {}
        }
    });
    link
}

/// One session through the quick tunnel's node to `host:port` through its
/// exit: what the operator read, or why the channel ended.
async fn through_the_exit(handler: Arc<Layered<Routed>>, host: &str, port: u16) -> Result<String, Error> {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let ids = Arc::new(AtomicU64::new(1));
    // The node's visitors as node_quick serves them: each one a session of
    // the handler, copied both ways.
    let visit = move |stream: DuplexStream| {
        let id = SessionId::parse(format!("{:032x}", ids.fetch_add(1, Ordering::Relaxed)).as_bytes());
        let handler = handler.clone();
        async move {
            let Ok(id) = id else { return };
            let Ok(mut session) = handler.open(id).await else { return };
            let mut stream = stream;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut session).await;
        }
    };
    let (mut steps, _stop, _served) = node_with(node_io, visit);
    let (mut edge, conn) = h2::client::handshake(edge_io).await.unwrap();
    tokio::spawn(conn);
    let _control = register(&mut edge, &mut steps).await;
    let link = link_of(&mut edge).await;
    let settings = Settings::default();
    let mut entropy = OsEntropy;
    let started = tokio::time::timeout(LIMIT, client::start(link, Ask::New, settings, &mut entropy));
    let client = started.await.expect("the layer in time").expect("the layer's handshake");
    let (app, app_end) = tokio::io::duplex(PIPE);
    let word = Some(exit_word(host, port));
    let (cipher, channel) = ends::operator_to(app_end, identity(1), |_| Ok(()), word);
    let channel = tokio::spawn(channel);
    let connect = |_: &Ended| async { Next::<DuplexStream>::Stop("one link in this test".into()) };
    let _layer = tokio::spawn(async move { resume::run(client, cipher, connect, |_| {}, &mut OsEntropy).await });
    let (mut r, mut w) = tokio::io::split(app);
    w.shutdown().await.unwrap();
    let mut read = String::new();
    let _ = tokio::time::timeout(LIMIT, r.read_to_string(&mut read)).await;
    let ended = tokio::time::timeout(LIMIT, channel).await.expect("the channel's end in time").unwrap();
    ended.map(|_| read)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_reaches_a_target_inside_the_exit_s_range_through_the_quick_tunnel() {
    let (port, count) = service("inside the range").await;
    let read = through_the_exit(exit_handler(port), "127.0.0.1", port).await;
    assert_eq!(read.expect("the exit reached its target"), "inside the range");
    assert_eq!(count.load(Ordering::SeqCst), 1, "one dial of the target");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_of_no_range_is_refused_with_the_exit_s_words_and_never_dialled() {
    let (lent, _) = service("lent").await;
    let (other, count) = service("never").await;
    match through_the_exit(exit_handler(lent), "127.0.0.1", other).await {
        Err(Error::Refused(Refusal::Other(why))) => assert!(why.contains("inside no range"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(count.load(Ordering::SeqCst), 0, "the refused target was not dialled");
}
