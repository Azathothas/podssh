//! A connection that the far end closes first, with bytes that this end's
//! window holds back (T-599): its FIN waits for them, and they come once
//! this end reads, as soon as its window opens. smoltcp's LAST-ACK reads no
//! window from an acknowledgement of nothing new, so a close that went to
//! it with those bytes waiting left them for its backed-off probe, past the
//! echo test's minute under load.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;

use super::LIMIT;
use crate::stack::{Link, Stack, Why, BUFFER};
use crate::stream::Stream;

const NEAR: Ipv4Addr = Ipv4Addr::new(172, 16, 0, 2);
const FAR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 22);
/// More than this end's window, less than its window and the far end's
/// buffer: the rest waits in the far end's buffer, behind the window.
const SENT: usize = BUFFER + BUFFER / 2;
/// Long enough for the far end's probe of the closed window to back off.
const UNREAD: Duration = Duration::from_millis(3500);
/// The bytes come within this of the first read.
const PROMPT: Duration = Duration::from_secs(2);

/// Two stacks whose links are each other's, with no tunnel between.
fn pair() -> (Stack, Stack) {
    let (to_far, far_in) = mpsc::channel(1024);
    let (to_near, near_in) = mpsc::channel(1024);
    let link = |out, inbound| Link { out, inbound, why: Why::default(), tasks: Vec::new(), flow: Default::default() };
    let near = Stack::start(&[IpAddr::V4(NEAR)], link(to_far, near_in)).unwrap();
    let far = Stack::start(&[FAR.ip()], link(to_near, far_in)).unwrap();
    (near, far)
}

/// How the far end ends its side.
#[derive(Clone, Copy, Debug)]
enum End {
    Shutdown,
    Drop,
}

/// The far end writes [`SENT`] bytes, which this end does not read; this
/// end closes its side; the far end reads the end and ends its own; then
/// this end reads each byte and the end.
async fn close_with_bytes_held(end: End) {
    let (near, far) = pair();
    let mut listener = far.listen(FAR).unwrap();
    let (client, server) = tokio::join!(near.connect(FAR, LIMIT), listener.accept());
    let (mut client, mut server): (Stream, Stream) = (client.unwrap(), server.unwrap());
    let sent: Vec<u8> = (0..SENT).map(|i| (i % 251) as u8).collect();
    tokio::time::timeout(LIMIT, server.write_all(&sent)).await.expect("the far end's buffer takes the rest").unwrap();
    client.shutdown().await.unwrap();
    let mut none = [0u8; 1];
    let read = tokio::time::timeout(LIMIT, server.read(&mut none)).await.expect("the far end reads the end");
    assert_eq!(read.unwrap(), 0, "{end:?}");
    let ending = tokio::spawn(async move {
        match end {
            End::Shutdown => {
                // The FIN waits for the bytes that the window holds back.
                let early = tokio::time::timeout(Duration::from_millis(300), server.shutdown()).await;
                assert!(early.is_err(), "the far end closed with bytes behind a closed window");
                tokio::time::timeout(LIMIT, server.shutdown()).await.expect("the far end closes").unwrap();
            }
            End::Drop => drop(server),
        }
    });
    tokio::time::sleep(UNREAD).await;
    let started = Instant::now();
    let mut got = Vec::new();
    let read = tokio::time::timeout(LIMIT, client.read_to_end(&mut got)).await;
    let took = started.elapsed();
    read.expect("each byte and the end").unwrap();
    assert!(got == sent, "{end:?}: {} of {SENT} bytes, or changed", got.len());
    assert!(took < PROMPT, "{end:?}: the bytes came {took:?} after the first read");
    tokio::time::timeout(LIMIT, ending).await.expect("the far end ends").unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_in_close_wait_sends_its_fin_after_the_bytes_held_back() {
    close_with_bytes_held(End::Shutdown).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_drop_in_close_wait_sends_its_fin_after_the_bytes_held_back() {
    close_with_bytes_held(End::Drop).await;
}
