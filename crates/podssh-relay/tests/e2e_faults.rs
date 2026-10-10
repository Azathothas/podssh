//! The relay can change, drop, repeat, reorder and cut frames
//! (`SECURITY.md`). Over the end-to-end channel (T-088), each such fault
//! ends the session with an error, and no byte of a bad frame, nor of one
//! after it, reaches the other side: nothing is skipped.
//!
//! The operator's frames: 0 and 1 its handshake, then its data from 2. The
//! node's: 0 its handshake, 1 its verdict, then its data from 2.

mod e2e_harness;

use e2e_harness::{echo_back, identity, node, run, Fault, Run, LIMIT};
use podssh_relay::e2e::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn session(up: Fault, down: Fault) -> Run {
    run(identity(1), |_| Ok(()), node(identity(2), |_| Ok(())), up, down)
}

/// After `r`'s first echo, `chunks` go out with no wait for an echo, each
/// once the relay has read the one before as a frame of its own; each byte
/// that comes back after them, until the stream ends.
async fn rest_after(r: &mut Run, chunks: &[&[u8]]) -> Vec<u8> {
    assert_eq!(echo_back(&mut r.app, b"chunk-A").await.unwrap(), b"chunk-A");
    for (i, chunk) in chunks.iter().enumerate() {
        let _ = r.app.write_all(chunk).await;
        // Frames 0 and 1 are the handshake's, 2 is chunk-A's.
        let read = async {
            while r.up_frames.load(std::sync::atomic::Ordering::SeqCst) < 4 + i {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(LIMIT, read).await.expect("the relay reads each chunk as a frame");
    }
    let mut back = Vec::new();
    let _ = tokio::time::timeout(LIMIT, r.app.read_to_end(&mut back)).await.expect("the stream ends");
    back
}

async fn node_lines(r: Run) -> (Result<podssh_relay::identity::PublicKey, Error>, String) {
    let outcome = tokio::time::timeout(LIMIT, r.session).await.unwrap().unwrap();
    let _ = tokio::time::timeout(LIMIT, r.node_task).await;
    let lines = r.lines.lock().unwrap().join("\n");
    (outcome, lines)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_bit_ends_the_session_and_its_bytes_go_nowhere() {
    let mut r = session(Fault::Flip(3), Fault::None);
    let back = rest_after(&mut r, &[b"chunk-B"]).await;
    assert!(back.is_empty(), "bytes of a changed frame reached the target: {back:?}");
    let (outcome, lines) = node_lines(r).await;
    assert!(lines.contains("failed its check"), "{lines}");
    assert!(matches!(outcome, Err(Error::Cut)), "the node's end is no clean end: {outcome:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_frame_ends_the_session_at_the_next() {
    let mut r = session(Fault::Drop(3), Fault::None);
    let back = rest_after(&mut r, &[b"chunk-B", b"chunk-C"]).await;
    assert!(back.is_empty(), "a frame after the dropped one reached the target: {back:?}");
    let (_, lines) = node_lines(r).await;
    assert!(lines.contains("failed its check"), "{lines}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_frame_ends_the_session_and_counts_once() {
    let mut r = session(Fault::Repeat(3), Fault::None);
    let back = rest_after(&mut r, &[b"chunk-B"]).await;
    assert!(back == b"chunk-B" || back.is_empty(), "the repeated frame reached the target twice: {back:?}");
    let (_, lines) = node_lines(r).await;
    assert!(lines.contains("failed its check"), "{lines}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_out_of_order_end_the_session() {
    let mut r = session(Fault::Swap(3), Fault::None);
    let back = rest_after(&mut r, &[b"chunk-B", b"chunk-C"]).await;
    assert!(back.is_empty(), "a frame out of order reached the target: {back:?}");
    let (_, lines) = node_lines(r).await;
    assert!(lines.contains("failed its check"), "{lines}");
}

/// A stream that the relay ends between two frames is a cut, not an end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_cut_between_frames_is_no_clean_end() {
    let mut r = session(Fault::CutBefore(3), Fault::None);
    let back = rest_after(&mut r, &[b"chunk-B"]).await;
    assert!(back.is_empty(), "{back:?}");
    let (outcome, lines) = node_lines(r).await;
    assert!(lines.contains("cut before its end"), "{lines}");
    assert!(matches!(outcome, Err(Error::Cut)), "{outcome:?}");
}

/// The node's direction is checked as the operator's is: a changed echo
/// ends the session at the operator, with none of it written out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_frame_from_the_node_ends_the_session_at_the_operator() {
    let mut r = session(Fault::None, Fault::Flip(2));
    r.app.write_all(b"chunk-A").await.unwrap();
    let mut back = Vec::new();
    let _ = tokio::time::timeout(LIMIT, r.app.read_to_end(&mut back)).await.expect("the stream ends");
    assert!(back.is_empty(), "bytes of a changed frame were written out: {back:?}");
    let (outcome, _) = node_lines(r).await;
    assert!(matches!(outcome, Err(Error::Tampered)), "{outcome:?}");
}

/// A changed verdict, and a changed handshake message, fail before a byte
/// of the session moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_verdict_or_handshake_fails_before_the_session() {
    let r = session(Fault::None, Fault::Flip(1));
    let (outcome, _) = node_lines(r).await;
    assert!(matches!(outcome, Err(Error::Tampered)), "the verdict: {outcome:?}");
    let r = session(Fault::None, Fault::Flip(0));
    let opened = r.opened.clone();
    let (outcome, _) = node_lines(r).await;
    assert!(matches!(outcome, Err(Error::Handshake(_))), "the node's handshake message: {outcome:?}");
    assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 0, "no target behind a failed handshake");
}
