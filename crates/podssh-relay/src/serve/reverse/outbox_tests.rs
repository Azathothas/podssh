//! The tests of a reverse socket's writer, in a file of their own so that
//! `outbox.rs` stays short: the contract's bound for a slow receiver
//! (T-336), and a line for each session to a node (T-648).

use std::time::Instant;

use podssh_ws::session::{close_code_and_reason, RelaySession};
use tokio::io::DuplexStream;

use super::*;

const LIMIT: Duration = Duration::from_secs(10);

/// A writer on a pipe of 1 KiB, so that what it is given waits in its queue
/// until the far end reads; the far end, as a client reads it.
fn on_a_small_pipe() -> (Outbox, RelaySession<DuplexStream>) {
    let (ours, theirs) = tokio::io::duplex(1024);
    let outbox = Outbox::start(Arc::new(podssh_ws::server::session(ours, Vec::new(), None)), Arc::default());
    (outbox, RelaySession::new(theirs, Vec::new(), None, LIMIT))
}

/// The session id of `c`, 32 times the character.
fn id(c: u8) -> SessionId {
    SessionId::parse(&[c; 32]).unwrap()
}

/// The next frame of `client`: its opcode and payload.
async fn next(client: &RelaySession<DuplexStream>) -> (u8, Vec<u8>) {
    let frame = tokio::time::timeout(LIMIT, client.read_frame()).await.expect("a frame in time").expect("a frame");
    (frame.opcode, frame.payload)
}

#[test]
fn a_frame_takes_its_length_in_room_and_one_at_least() {
    assert_eq!(cost(0), 1);
    assert_eq!(cost(65568), 65568);
    assert_eq!(cost(usize::MAX), BOUND);
}

#[tokio::test]
async fn a_queue_for_a_slow_receiver_refuses_what_passes_the_bound() {
    // The writer's socket is never read: what is queued stays queued once
    // the pipe's own buffer is full.
    let (outbox, _client) = on_a_small_pipe();
    let mut queued = 0;
    while outbox.binary_or_full(vec![7u8; 64 * 1024]).is_ok() {
        queued += 64 * 1024;
        assert!(queued <= BOUND + 64 * 1024, "the bound held nothing back");
    }
    assert!(queued >= BOUND - 128 * 1024, "only {queued} bytes were queued");
    assert!(outbox.waiting() <= BOUND, "{} bytes wait", outbox.waiting());
}

/// T-648: session `a` fills its line to a node that reads nothing; session
/// `b`'s four bytes then wait for one more frame of `a` at most, not for each
/// frame that `a` queued. The wait for `a`'s line is a condition, not a time.
#[tokio::test]
async fn a_sessions_bytes_to_a_node_wait_for_one_frame_of_another_at_most() {
    let (outbox, client) = on_a_small_pipe();
    const FRAME: usize = 60_000;
    let busy = outbox.clone();
    let flood = tokio::spawn(async move {
        for _ in 0..64 {
            if busy.binary_waiting(id(b'a'), vec![b'a'; FRAME]).await.is_err() {
                return;
            }
        }
    });
    // Each frame that fits the bound waits, one of them on its way.
    let full = (BOUND / FRAME) * FRAME;
    let deadline = Instant::now() + LIMIT;
    while outbox.waiting() < full {
        assert!(Instant::now() < deadline, "a's line held {} bytes", outbox.waiting());
        tokio::task::yield_now().await;
    }
    let other = outbox.clone();
    let four = tokio::spawn(async move { other.binary_waiting(id(b'b'), b"to b".to_vec()).await });
    let mut before = 0;
    loop {
        let (opcode, payload) = next(&client).await;
        assert_eq!(opcode, frame::OPCODE_BINARY);
        if payload == b"to b" {
            break;
        }
        before += 1;
        assert!(before <= 2, "{before} frames of a came before b's four bytes");
    }
    assert_eq!(tokio::time::timeout(LIMIT, four).await.unwrap().unwrap(), Ok(()));
    flood.abort();
}

/// T-648: text goes before the sessions' bytes that wait; a session's
/// `close` goes after its own bytes; the frames of a session that its
/// receiver ended are dropped; and the Close goes last, after each line.
#[tokio::test]
async fn text_first_a_close_after_its_bytes_a_dropped_session_never_and_the_close_last() {
    let (outbox, client) = on_a_small_pipe();
    // Nothing yields before the reads below: the writer takes each of these
    // in its own order.
    for n in 0..3u8 {
        outbox.binary_waiting(id(b'a'), vec![b'a', n]).await.unwrap();
    }
    outbox.text_after(id(b'a'), "close a".into());
    outbox.binary_waiting(id(b'c'), b"gone".to_vec()).await.unwrap();
    outbox.drop_session(&id(b'c'));
    outbox.text("open b".into());
    outbox.close(1000, "done");
    assert_eq!(next(&client).await, (frame::OPCODE_TEXT, b"open b".to_vec()), "text first");
    for n in 0..3u8 {
        assert_eq!(next(&client).await, (frame::OPCODE_BINARY, vec![b'a', n]), "a's bytes in their order");
    }
    assert_eq!(next(&client).await, (frame::OPCODE_TEXT, b"close a".to_vec()), "a's close after its bytes");
    let (opcode, payload) = next(&client).await;
    assert_eq!(opcode, frame::OPCODE_CLOSE, "nothing of the dropped session, then the Close");
    assert_eq!(close_code_and_reason(&payload), (Some(1000), "done".to_string()));
    assert!(outbox.binary_or_full(b"late".to_vec()).is_ok(), "a frame after the Close is never written");
}
