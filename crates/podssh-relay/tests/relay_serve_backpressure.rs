//! T-336: podssh's relay role holds no unbounded queue for a slow forward
//! client. A target on the loopback has 48 MiB to send, as fast as its
//! socket takes them, and counts what its socket took; the client reads
//! 16 KiB/s through the role. Each write of the role waits for its reader,
//! so the target stalls: what the target gave and the client has not read
//! stays under 2 MiB, the contract's queue for a `1013`, or the role closes
//! with that `1013`. The reverse road's bound, `1011 relay backpressure` at
//! 1 MiB, is `relay_serve_reverse.rs`'s slow operator. The control reads at
//! full speed and gets each byte, then the target's end.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{sockets, tokens, Mint};
use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use role_harness::Role;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Instant;

const MIB: usize = 1 << 20;
/// Far past the 2 MiB of the contract's queue.
const SIZE: usize = 48 * MIB;
/// How fast the slow client reads, and for how long.
const RATE: usize = 16 * 1024;
const SLOW_FOR: Duration = Duration::from_secs(12);
/// The contract's queue for a slow client (`1013 client receive backlog`).
const BOUND: usize = 2 * MIB;
/// The control's whole run.
const CONTROL_LIMIT: Duration = Duration::from_secs(60);

/// A target on the loopback that sends `size` bytes to its one client as
/// fast as its socket takes them, then ends; what its socket took so far.
/// Its send buffer is fixed, so that the kernel's growth of it counts for
/// nothing: what waits past it waits in the role or on its way.
async fn fast_target(size: usize) -> (u16, Arc<AtomicUsize>) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(64 * 1024).unwrap();
    socket.bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let listener = socket.listen(1).unwrap();
    let port = listener.local_addr().unwrap().port();
    let taken = Arc::new(AtomicUsize::new(0));
    let counted = taken.clone();
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else { return };
        let chunk = vec![0x5au8; 16 * 1024];
        let mut left = size;
        while left > 0 {
            let n = left.min(chunk.len());
            if tcp.write_all(&chunk[..n]).await.is_err() {
                return;
            }
            counted.fetch_add(n, Ordering::SeqCst);
            left -= n;
        }
        let _ = tcp.shutdown().await;
    });
    (port, taken)
}

/// The role, which dials the loopback, and a forward session through it to
/// a target of `size` bytes: the session and what the target took.
async fn session_to_target(size: usize) -> (Role, RelaySession<TcpStream>, Arc<AtomicUsize>) {
    let role = Role::configured(Mint::Anyone, Policy { private: true, ..Policy::default() }, Default::default()).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let (port, taken) = fast_target(size).await;
    let session = role.socket(&format!("/connect/127.0.0.1/{port}"), &token).await.expect("a forward session");
    (role, session, taken)
}

/// What the slow client saw: the most that waited past the target at any
/// time, the bytes read, and a Close if one came.
#[derive(Debug)]
struct Slow {
    most_waiting: usize,
    read: usize,
    taken: usize,
    close: Option<(Option<u16>, String)>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_forward_client_makes_the_target_wait_and_nothing_piles_up_in_the_role() {
    let (_role, session, taken) = session_to_target(SIZE).await;
    let started = Instant::now();
    let mut seen = Slow { most_waiting: 0, read: 0, taken: 0, close: None };
    while started.elapsed() < SLOW_FOR {
        let frame = match tokio::time::timeout(Duration::from_secs(5), session.read_frame()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(e)) => panic!("the session ended with no Close: {e}"),
            // Nothing in 5 s: a stall is what a full queue may give; read on.
            Err(_) => continue,
        };
        match frame.opcode {
            OPCODE_BINARY => seen.read += frame.payload.len(),
            OPCODE_CLOSE => {
                seen.close = Some(close_code_and_reason(&frame.payload));
                break;
            }
            _ => {}
        }
        let waiting = taken.load(Ordering::SeqCst).saturating_sub(seen.read);
        seen.most_waiting = seen.most_waiting.max(waiting);
        // The reader's pace: each frame's bytes at RATE.
        tokio::time::sleep(Duration::from_secs_f64(frame.payload.len() as f64 / RATE as f64)).await;
    }
    seen.taken = taken.load(Ordering::SeqCst);
    eprintln!("slow client: {seen:?}");
    match &seen.close {
        Some((code, reason)) => {
            assert_eq!(*code, Some(1013), "a Close of a slow client is the contract's 1013: {seen:?}");
            assert_eq!(reason, "client receive backlog", "{seen:?}");
        }
        None => {
            assert!(seen.read > 0, "the slow client read nothing: {seen:?}");
            assert!(seen.most_waiting < BOUND, "more than 2 MiB waited past the target: {seen:?}");
            assert!(seen.taken < SIZE / 4, "the target was never made to wait: {seen:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_control_at_full_speed_carries_each_byte_and_ends_as_the_target_ends() {
    let (_role, session, taken) = session_to_target(SIZE).await;
    let deadline = Instant::now() + CONTROL_LIMIT;
    let mut read = 0usize;
    let close = loop {
        assert!(Instant::now() < deadline, "the control did not end in {CONTROL_LIMIT:?}: {read} bytes read");
        let frame = tokio::time::timeout(Duration::from_secs(20), session.read_frame())
            .await
            .expect("a frame within 20 s")
            .expect("the session ends with a Close");
        match frame.opcode {
            OPCODE_BINARY => read += frame.payload.len(),
            OPCODE_CLOSE => break close_code_and_reason(&frame.payload),
            _ => {}
        }
    };
    assert_eq!((read, taken.load(Ordering::SeqCst)), (SIZE, SIZE), "each byte, both counted");
    assert_eq!(close, (Some(1000), "target closed".to_string()));
}

#[tokio::test]
async fn a_socket_of_the_role_holds_at_most_its_bound_unsent() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    sockets::bound_unsent(&tcp);
    let want = cfg!(any(target_os = "linux", target_os = "android")).then_some(sockets::UNSENT);
    assert_eq!(sockets::unsent_bound(&tcp), want);
}
