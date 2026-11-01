//! A quick tunnel's connection under small frames (T-408). h2 counts each
//! DATA frame under 256 bytes that waits unread against a budget, and past
//! it ends the connection with ENHANCE_YOUR_CALM, every visitor's stream with
//! it. Here h2's client plays the edge, over a pipe in memory: frames of 60
//! bytes, one masked WebSocket frame each, on 64 visitors whose users read
//! nothing, until the windows stop the edge. With the node's own HTTP/2 the
//! connection then serves a new visitor; as the control, with h2's own
//! budget, half the connection's window, the same frames end it.

#![cfg(feature = "quick")]

mod quick_harness;

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use podssh_relay::quick::serve::{serve_with, Ended, Step};
use podssh_relay::quick::settings::{self, CONNECTION_WINDOW, MAX_STREAMS, STREAM_WINDOW};
use podssh_ws::frame::{self, Frame, Role};
use quick_harness::*;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot};

/// The visitors whose users read nothing, and the frames that the edge
/// queues on each: more than the stream's window and the node's pipe take.
const VISITORS: usize = 64;
const FRAMES: usize = 3_000;
/// Each DATA frame: a WebSocket frame of 54 bytes, masked, as a client
/// writes it.
const FRAME: usize = 60;
/// A DATA frame's header.
const HEADER: usize = 9;
/// How long the edge's writes stand still before they count as stopped.
const STILL: Duration = Duration::from_millis(300);

/// What each stalled visitor's frames weigh in h2's count once the edge
/// stops: at most its stream's window of them; at least two thirds of it,
/// as h2 gives back a window that the reader released only once it is half
/// of what the edge has left, so up to a third stays with h2.
const MOST: usize = STREAM_WINDOW as usize / FRAME * (256 - FRAME);
const LEAST: usize = (STREAM_WINDOW as usize - STREAM_WINDOW as usize / 3) / FRAME * (256 - FRAME);
// More than h2's own budget, half the connection's window; within the node's.
const _: () = assert!(VISITORS * LEAST > CONNECTION_WINDOW as usize / 2);
const _: () = assert!(VISITORS * MOST <= settings::FRAME_BUDGET);

/// The edge's end of the pipe, which counts the bytes that it wrote.
struct Counted {
    io: DuplexStream,
    wrote: Arc<AtomicUsize>,
}

impl AsyncRead for Counted {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &polled {
            this.wrote.fetch_add(*n, Ordering::SeqCst);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

type Served = tokio::task::JoinHandle<Result<(), Ended>>;

/// The node on `io`, with the HTTP/2 of `builder`: the users of the first
/// VISITORS visitors hold their streams and read nothing; each later one
/// echoes.
fn node(
    io: DuplexStream,
    builder: h2::server::Builder,
) -> (mpsc::UnboundedReceiver<Step>, oneshot::Sender<()>, Served) {
    let count = Arc::new(AtomicUsize::new(0));
    let visit = move |stream: DuplexStream| {
        let stalled = count.fetch_add(1, Ordering::SeqCst) < VISITORS;
        async move {
            if stalled {
                let _held = stream;
                std::future::pending::<()>().await;
            } else {
                echo(stream).await;
            }
        }
    };
    let (steps_tx, steps) = mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        let stop = async {
            let _ = stop_rx.await;
        };
        serve_with(builder, io, &registration(), visit, steps_tx, stop).await
    });
    (steps, stop_tx, served)
}

/// What the edge holds: the bytes that it wrote, its handle of requests,
/// and the ends of each stream that it opened, kept so that none is reset.
struct Edge {
    wrote: Arc<AtomicUsize>,
    requests: h2::client::SendRequest<Bytes>,
    _streams: Vec<(SendStream<Bytes>, RecvStream)>,
}

/// The edge on `io`: the control stream registered, then VISITORS visitors
/// answered, then FRAMES frames of FRAME bytes queued on each, which h2
/// sends as the node's windows let them go.
async fn edge(io: DuplexStream, steps: &mut mpsc::UnboundedReceiver<Step>) -> Edge {
    let wrote = Arc::new(AtomicUsize::new(0));
    let (mut requests, conn) = h2::client::handshake(Counted { io, wrote: wrote.clone() }).await.unwrap();
    tokio::spawn(conn);
    let mut streams = vec![register(&mut requests, steps).await];
    for _ in 0..VISITORS {
        streams.push(visitor(&mut requests).await);
    }
    let message = Frame { fin: true, opcode: 0x2, payload: vec![0x5a; FRAME - 6] };
    let small = Bytes::from(frame::encode(&message, Role::Client, [3, 1, 4, 1]));
    assert_eq!(small.len(), FRAME);
    for (to_node, _) in streams.iter_mut().skip(1) {
        // The control's node may end the connection while they are queued.
        for _ in 0..FRAMES {
            if to_node.send_data(small.clone(), false).is_err() {
                break;
            }
        }
    }
    Edge { wrote, requests, _streams: streams }
}

/// The windows stop the edge with each stalled visitor's window of small
/// frames unread in h2, more than h2's own budget lets wait; the connection
/// stays, and a new visitor's message comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn small_frames_that_visitors_leave_unread_keep_the_connection() {
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (mut steps, _stop, served) = node(node_io, settings::server_builder());
    let mut edge = edge(edge_io, &mut steps).await;
    let all = VISITORS * FRAMES * (FRAME + HEADER);
    let (started, mut last) = (Instant::now(), 0);
    loop {
        tokio::time::sleep(STILL).await;
        let now = edge.wrote.load(Ordering::SeqCst);
        if served.is_finished() {
            let ended = served.await.unwrap();
            panic!("the node ended the connection after the edge wrote {now} bytes: {ended:?}");
        }
        if now == last && now >= VISITORS * STREAM_WINDOW as usize {
            break;
        }
        assert!(started.elapsed() < LIMIT, "the edge still writes after {LIMIT:?}: {now} bytes");
        last = now;
    }
    assert!(last < all, "the windows did not stop the edge: it wrote {last} of {all} bytes");
    let (mut out, mut back) = visitor(&mut edge.requests).await;
    let message = Frame { fin: true, opcode: 0x2, payload: b"beside the small frames".to_vec() };
    out.send_data(Bytes::from(frame::encode(&message, Role::Client, [2, 7, 1, 8])), false).unwrap();
    let echoed = read_frame(&mut back).await;
    assert_eq!((echoed.opcode, echoed.payload.as_slice()), (0x2, &b"beside the small frames"[..]));
    assert!(!served.is_finished(), "the connection is still served");
}

/// The control: the same frames with h2's own budget, half the connection's
/// window, end the connection with ENHANCE_YOUR_CALM while the visitors read
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_s_own_budget_ends_the_connection_of_visitors_that_read_nothing() {
    let mut own = h2::server::Builder::new();
    own.max_concurrent_streams(MAX_STREAMS)
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW);
    let (node_io, edge_io) = tokio::io::duplex(1 << 20);
    let (mut steps, _stop, served) = node(node_io, own);
    let _edge = edge(edge_io, &mut steps).await;
    let ended = tokio::time::timeout(LIMIT, served).await;
    let ended = ended.expect("h2's own budget let the small frames wait").unwrap();
    let Err(Ended::Http2(e)) = &ended else { panic!("not HTTP/2's end: {ended:?}") };
    assert_eq!(e.reason(), Some(h2::Reason::ENHANCE_YOUR_CALM), "{e}");
}
