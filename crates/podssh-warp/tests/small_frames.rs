//! WARP's tunnel under volume (T-398). The edge sends one DATA frame of
//! HTTP/2 for each packet, so the acknowledgements of an upload are a stream
//! of small frames, and h2 counts each one that waits unread against a
//! budget, past which it ends the connection with ENHANCE_YOUR_CALM: cfrs's
//! WARP road died so (cfrs #32). Here h2's server plays the edge, over a
//! pipe in memory: 40,000 frames of 60 bytes to a reader that pauses, with
//! the tunnel's own client, and, as the control, with h2's own budget. And
//! the stack's driver, which reads the tunnel while a packet of its own
//! waits for room in it, as an upload waits for HTTP/2's window.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use podssh_warp::stack::{Link, Stack, Why};
use podssh_warp::{capsule, tunnel};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot};

/// The frames that the front door sends, and the size of each: the capsule
/// of a packet of 58 bytes, near an acknowledgement of TCP with timestamps
/// (52 bytes), the size of cfrs's test.
const FRAMES: u32 = 40_000;
const FRAME: usize = 60;
/// A DATA frame's header.
const HEADER: usize = 9;
/// How long the reader pauses once each frame was written.
const PAUSE: Duration = Duration::from_millis(300);
/// The bound on each wait of a test.
const LIMIT: Duration = Duration::from_secs(30);

/// The front door's end of the pipe, which counts the bytes that it wrote.
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

/// What the front door saw: the bytes that it wrote, and the client's first
/// packet.
struct FrontDoor {
    wrote: Arc<AtomicUsize>,
    first: oneshot::Receiver<Vec<u8>>,
}

/// h2's server as WARP's edge on `io`: 200 to the CONNECT, then FRAMES
/// frames of FRAME bytes, one capsule each, a packet's number in its first
/// four bytes; and the first packet of the client's body, read.
fn front_door(io: DuplexStream) -> FrontDoor {
    let wrote = Arc::new(AtomicUsize::new(0));
    let counted = Counted { io, wrote: wrote.clone() };
    let (tell, first) = oneshot::channel();
    tokio::spawn(async move {
        let Ok(mut connection) = h2::server::handshake(counted).await else { return };
        let Some(Ok((request, mut respond))) = connection.accept().await else { return };
        let Ok(mut send) = respond.send_response(http::Response::new(()), false) else { return };
        tokio::spawn(async move {
            for i in 0..FRAMES {
                let mut packet = vec![0x45u8; FRAME - 2];
                packet[..4].copy_from_slice(&i.to_be_bytes());
                if send.send_data(Bytes::from(capsule::datagram(&packet)), false).is_err() {
                    return;
                }
            }
            // The stream stays open, as the edge's does.
            std::future::pending::<()>().await;
        });
        tokio::spawn(read_first(request.into_body(), tell));
        // Driven while its streams run.
        while let Some(Ok(_)) = connection.accept().await {}
    });
    FrontDoor { wrote, first }
}

/// The first packet of a body of capsules.
async fn read_first(mut body: h2::RecvStream, tell: oneshot::Sender<Vec<u8>>) {
    let mut reader = capsule::Reader::default();
    while let Some(Ok(chunk)) = body.data().await {
        let _ = body.flow_control().release_capacity(chunk.len());
        reader.push(&chunk);
        if let Ok(Some(packet)) = reader.next_packet() {
            let _ = tell.send(packet);
            return;
        }
    }
}

/// The client on `io` with `builder`: the CONNECT as the tunnel asks it, and
/// the pump of its packets; the connection's end is said in the link's
/// `why`, and the handle of requests stays with the caller.
async fn client(io: DuplexStream, builder: h2::client::Builder) -> (Link, h2::client::SendRequest<Bytes>) {
    let (requests, connection) = builder.handshake::<_, Bytes>(io).await.expect("HTTP/2's handshake");
    let why = Why::default();
    let ended = why.clone();
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            ended.set(format!("HTTP/2: {e}"));
        }
    });
    let mut requests = requests.ready().await.expect("HTTP/2 takes a request");
    let (response, send) = requests.send_request(tunnel::request().unwrap(), false).expect("the CONNECT");
    let response = response.await.expect("the front door's answer");
    assert_eq!(response.status(), 200);
    (tunnel::pump(response.into_body(), send, why), requests)
}

/// 40,000 frames of 60 bytes wait in h2 while the reader pauses, past the
/// pump's queue: with the tunnel's budget each one comes, in order, and the
/// connection then carries a packet out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn small_frames_that_wait_for_a_paused_reader_keep_the_tunnel() {
    let (near, far) = tokio::io::duplex(64 * 1024);
    let door = front_door(far);
    let (mut link, _requests) = client(near, tunnel::client_builder()).await;
    let all = FRAMES as usize * (FRAME + HEADER);
    let start = Instant::now();
    while door.wrote.load(Ordering::SeqCst) < all {
        let wrote = door.wrote.load(Ordering::SeqCst);
        assert!(start.elapsed() < LIMIT, "the front door wrote {wrote} of {all} bytes: {:?}", link.why.get());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(PAUSE).await;
    for i in 0..FRAMES {
        let packet = tokio::time::timeout(LIMIT, link.inbound.recv()).await.expect("a packet in time");
        let Some(packet) = packet else { panic!("the tunnel ended after {i} packets: {:?}", link.why.get()) };
        assert_eq!(packet[..4], i.to_be_bytes(), "packet {i}");
    }
    assert_eq!(link.why.get(), None);
    link.out.send(b"after the frames".to_vec()).await.expect("the tunnel takes a packet");
    let first = tokio::time::timeout(LIMIT, door.first).await.expect("the packet out in time");
    assert_eq!(first.expect("the front door read it"), b"after the frames");
}

/// The control: the same frames with h2's own budget, half the
/// connection's window, end the connection with ENHANCE_YOUR_CALM while the
/// reader pauses, as cfrs's road ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_s_own_budget_ends_the_tunnel_of_a_paused_reader() {
    let (near, far) = tokio::io::duplex(64 * 1024);
    let _door = front_door(far);
    let mut own = h2::client::Builder::new();
    own.initial_window_size(tunnel::STREAM_WINDOW).initial_connection_window_size(tunnel::CONNECTION_WINDOW);
    let (link, _requests) = client(near, own).await;
    let ended = tokio::time::timeout(LIMIT, link.why.ended()).await;
    assert!(ended.is_ok(), "h2's own budget let {FRAMES} frames wait unread");
    let said = link.why.get().unwrap_or_default();
    assert!(said.contains("too_many_data_frames") || said.contains("excessive load"), "{said}");
}

/// The stack reads the tunnel while packets of its own wait for room in it:
/// 2,000 packets in are taken while four SYNs wait, and once the tunnel
/// takes packets again, each SYN goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stack_reads_the_tunnel_while_a_packet_waits_to_go_out() {
    // The tunnel's side takes one packet, then none, as a writer that waits
    // on the edge's window.
    let (out, mut taken) = mpsc::channel(1);
    let (to_stack, inbound) = mpsc::channel(8);
    let link = Link { out, inbound, why: Why::default(), tasks: Vec::new() };
    let stack = Stack::start(&[IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2))], link).unwrap();
    for last in 1..=4u8 {
        let stack = stack.clone();
        let to = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 22);
        tokio::spawn(async move {
            let _ = stack.connect(to, LIMIT).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Packets that smoltcp drops as malformed, many times its queue's length
    // and the channel's: each must be read while the SYNs wait.
    let fed = tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..2_000 {
            to_stack.send(vec![0x45; 60]).await.expect("the stack reads the tunnel");
        }
    })
    .await;
    assert!(fed.is_ok(), "the stack stopped reading the tunnel while a packet waited to go out");
    let mut syns = HashSet::new();
    while syns.len() < 4 {
        let packet = tokio::time::timeout(LIMIT, taken.recv()).await.expect("a SYN in time");
        let packet = packet.expect("the stack's packets");
        // IPv4; the destination's last byte ends the header of 20 bytes.
        assert_eq!(packet[0] >> 4, 4);
        syns.insert(packet[19]);
    }
    assert_eq!(syns, (1..=4u8).collect::<HashSet<u8>>());
    assert_eq!(stack.ended(), None);
}
