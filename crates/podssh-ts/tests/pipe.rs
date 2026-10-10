//! Pipe tests: byte equality both ways, exact counts, EOF propagation, and
//! how the `-W` pipe ends.
//!
//! `tokio::io::duplex` stands in for stdin and the tailnet stream: the
//! bytes are what is pinned, not the transport.

use std::time::Duration;

use podssh_ts::pipe::copy_bidirectional;
use podssh_ts::pipe::{pipe_streams, End, PipeEnds, IDLE_AFTER_EOF};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

#[tokio::test]
async fn bytes_survive_both_directions_exactly() {
    // Each duplex end is split: the write half feeds finite bytes and is
    // dropped (EOF after the drain), the read half collects what the copy
    // delivers. Dropping a whole peer upfront would break the copy's writes
    // with BrokenPipe instead — that failure is the test's own bug, not the
    // pipe's, and this shape is what keeps EOF deterministic on both legs.
    let (mut a_side, a_peer) = tokio::io::duplex(64);
    let (mut b_side, b_peer) = tokio::io::duplex(64);
    let (mut a_pr, mut a_pw) = split(a_peer);
    let (mut b_pr, mut b_pw) = split(b_peer);
    // EOF comes from explicit `shutdown()`, not from dropping a split
    // half: `tokio::io::split` shares ownership, so a dropped WriteHalf
    // need not close anything while its ReadHalf lives — the copy would
    // hang waiting for an EOF that never arrives (measured: 30 s timeout,
    // exit 124). `shutdown()` sends the write-side close; the peer's reads
    // then see EOF after the drain, while its own writes keep working.
    a_pw.write_all(b"to-remote").await.unwrap();
    a_pw.shutdown().await.unwrap();
    b_pw.write_all(b"from-remote").await.unwrap();
    b_pw.shutdown().await.unwrap();
    let r1 = tokio::spawn(async move {
        let mut v = Vec::new();
        a_pr.read_to_end(&mut v).await.unwrap();
        v
    });
    let r2 = tokio::spawn(async move {
        let mut v = Vec::new();
        b_pr.read_to_end(&mut v).await.unwrap();
        v
    });

    let (up, down) = copy_bidirectional(&mut a_side, &mut b_side).await.unwrap();
    assert_eq!((up, down), (9, 11));
    // Closing the copy's ends is what lets the collectors see EOF: without
    // these drops the awaits below hang, and a hanging test is the defect.
    drop(a_side);
    drop(b_side);
    assert_eq!(r2.await.unwrap(), b"to-remote");
    assert_eq!(r1.await.unwrap(), b"from-remote");
}

#[tokio::test]
async fn empty_sides_copy_zero_bytes() {
    let (mut a_side, a_peer) = tokio::io::duplex(64);
    let (mut b_side, b_peer) = tokio::io::duplex(64);
    drop(a_peer);
    drop(b_peer);
    let (up, down) = copy_bidirectional(&mut a_side, &mut b_side).await.unwrap();
    assert_eq!((up, down), (0, 0));
}

/// A request on stdin, then its end; the reply comes after it (T-101). The
/// pipe reads on after the end of stdin, so the reply reaches stdout, and
/// both counts are exact.
#[tokio::test]
async fn a_reply_after_local_eof_reaches_stdout() {
    let (mut local_r, lr_peer) = tokio::io::duplex(64);
    let (_lr_pr, mut lr_pw) = split(lr_peer);
    lr_pw.write_all(b"hello").await.unwrap();
    lr_pw.shutdown().await.unwrap();
    let (mut local_w, lw_peer) = tokio::io::duplex(64);
    let (mut lw_pr, _lw_pw) = split(lw_peer);
    // The peer reads the whole request, sees its end, and only then answers
    // and closes: the reply comes after the local end, by construction.
    let (stream_side, s_peer) = tokio::io::duplex(64);
    let peer = tokio::spawn(async move {
        let (mut s_pr, mut s_pw) = split(s_peer);
        let mut request = Vec::new();
        s_pr.read_to_end(&mut request).await.unwrap();
        s_pw.write_all(b"world").await.unwrap();
        s_pw.shutdown().await.unwrap();
        request
    });

    let ends = pipe_streams(&mut local_r, &mut local_w, stream_side).await.unwrap();
    assert_eq!(ends, PipeEnds { up: 5, down: 5, local_eof: true, end: End::RemoteEof });
    assert_eq!(peer.await.unwrap(), b"hello");
    drop(local_w);
    let mut got = Vec::new();
    lw_pr.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"world");
}

#[tokio::test]
async fn both_sides_end_and_the_counts_are_exact() {
    let (mut local_r, lr_peer) = tokio::io::duplex(64);
    let (_lr_pr, mut lr_pw) = split(lr_peer);
    lr_pw.write_all(b"hello").await.unwrap();
    lr_pw.shutdown().await.unwrap();
    let (mut local_w, _lw_peer) = tokio::io::duplex(64);
    let (stream_side, s_peer) = tokio::io::duplex(64);
    let peer = tokio::spawn(async move {
        let (mut s_pr, mut s_pw) = split(s_peer);
        let mut request = [0u8; 5];
        s_pr.read_exact(&mut request).await.unwrap();
        s_pw.write_all(b"world").await.unwrap();
        s_pw.shutdown().await.unwrap();
        // Hold the read half: the stream's end is its write side alone.
        (s_pr, request)
    });

    let ends = pipe_streams(&mut local_r, &mut local_w, stream_side).await.unwrap();
    // Which end came first is scheduling; the stream's end ends the pipe.
    assert_eq!((ends.up, ends.down, ends.end), (5, 5, End::RemoteEof), "{ends:?}");
    assert_eq!(&peer.await.unwrap().1, b"hello");
}

#[tokio::test]
async fn remote_eof_first_ends_the_pipe() {
    // local stdin: open but silent — it never ends.
    let (mut local_r, _lr_peer) = tokio::io::duplex(64);
    let (mut local_w, lw_peer) = tokio::io::duplex(64);
    let (lw_pr, _lw_pw) = split(lw_peer);
    // stream: whole peer dropped upfront — reads see EOF at once, and the up
    // leg writes nothing because it never reads anything.
    let (stream_side, s_peer) = tokio::io::duplex(64);
    drop(s_peer);

    let ends = pipe_streams(&mut local_r, &mut local_w, stream_side).await.unwrap();
    assert_eq!(ends, PipeEnds { up: 0, down: 0, local_eof: false, end: End::RemoteEof });
    drop(lw_pr);
}

/// A peer that takes the request and never answers nor closes: the pipe ends
/// at the idle limit after the end of stdin, not never.
#[tokio::test(start_paused = true)]
async fn a_silent_peer_ends_the_pipe_after_the_idle_limit() {
    let (mut local_r, lr_peer) = tokio::io::duplex(64);
    let (_lr_pr, mut lr_pw) = split(lr_peer);
    lr_pw.write_all(b"req").await.unwrap();
    lr_pw.shutdown().await.unwrap();
    let (mut local_w, _lw_peer) = tokio::io::duplex(64);
    let (stream_side, _s_peer) = tokio::io::duplex(64);

    let started = Instant::now();
    let ends = tokio::time::timeout(Duration::from_secs(3600), pipe_streams(&mut local_r, &mut local_w, stream_side))
        .await
        .expect("the idle limit ends the pipe")
        .unwrap();
    assert_eq!(ends, PipeEnds { up: 3, down: 0, local_eof: true, end: End::Idle });
    assert_eq!(started.elapsed(), IDLE_AFTER_EOF);
}

/// Each byte from the stream restarts the idle limit: a reply that comes in
/// parts, 10 s apart, is read whole.
#[tokio::test(start_paused = true)]
async fn the_idle_limit_counts_from_the_last_byte_of_the_stream() {
    let (mut local_r, lr_peer) = tokio::io::duplex(64);
    let (_lr_pr, mut lr_pw) = split(lr_peer);
    lr_pw.shutdown().await.unwrap();
    let (mut local_w, _lw_peer) = tokio::io::duplex(64);
    let (stream_side, s_peer) = tokio::io::duplex(64);
    let peer = tokio::spawn(async move {
        let (s_pr, mut s_pw) = split(s_peer);
        for part in [b"a", b"b"] {
            tokio::time::sleep(Duration::from_secs(10)).await;
            s_pw.write_all(part).await.unwrap();
        }
        (s_pr, s_pw)
    });

    let started = Instant::now();
    let ends = pipe_streams(&mut local_r, &mut local_w, stream_side).await.unwrap();
    assert_eq!(ends, PipeEnds { up: 0, down: 2, local_eof: true, end: End::Idle });
    assert_eq!(started.elapsed(), Duration::from_secs(20) + IDLE_AFTER_EOF);
    drop(peer);
}

/// stdout's reader left: the pipe ends cleanly, and the bytes that could not
/// be written are not counted.
#[tokio::test]
async fn a_closed_stdout_is_a_clean_end() {
    let (mut local_r, _lr_peer) = tokio::io::duplex(64);
    let (mut local_w, lw_peer) = tokio::io::duplex(64);
    drop(lw_peer);
    let (stream_side, s_peer) = tokio::io::duplex(64);
    let (_s_pr, mut s_pw) = split(s_peer);
    s_pw.write_all(b"world").await.unwrap();

    let ends = pipe_streams(&mut local_r, &mut local_w, stream_side).await.unwrap();
    assert_eq!(ends, PipeEnds { up: 0, down: 0, local_eof: false, end: End::StdoutClosed });
}
