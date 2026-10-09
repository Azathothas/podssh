//! Pipe tests: byte equality both ways, exact counts, EOF propagation.
//!
//! ⛔ `tokio::io::duplex` stands in for stdin and the tailnet stream: the
//! bytes are what is pinned, not the transport.

use podssh_ts::pipe::copy_bidirectional;
use podssh_ts::pipe::{pipe_streams, FirstEnd};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn bytes_survive_both_directions_exactly() {
    // ⛔ Each duplex end is split: the write half feeds finite bytes and is
    // dropped (EOF after the drain), the read half collects what the copy
    // delivers. Dropping a whole peer upfront would break the copy's writes
    // with BrokenPipe instead — that failure is the test's own bug, not the
    // pipe's, and this shape is what keeps EOF deterministic on both legs.
    let (mut a_side, a_peer) = tokio::io::duplex(64);
    let (mut b_side, b_peer) = tokio::io::duplex(64);
    let (mut a_pr, mut a_pw) = split(a_peer);
    let (mut b_pr, mut b_pw) = split(b_peer);
    // ⛔ EOF comes from explicit `shutdown()`, not from dropping a split
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
    // ⛔ Closing the copy's ends is what lets the collectors see EOF: without
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

#[tokio::test]
async fn local_eof_first_cuts_the_down_leg() {
    // local stdin: 5 bytes, then write-side shutdown (EOF after the drain).
    let (mut local_r, lr_peer) = tokio::io::duplex(64);
    let (_lr_pr, mut lr_pw) = split(lr_peer);
    lr_pw.write_all(b"hello").await.unwrap();
    lr_pw.shutdown().await.unwrap();
    // local stdout: the down leg may or may not have been polled before the
    // up leg won — `select!` starts polling at a random branch — so nothing
    // is asserted about local delivery here. The winner's counts and the
    // stream's bytes are the deterministic parts.
    let (mut local_w, _lw_peer) = tokio::io::duplex(64);
    // stream: 5 bytes waiting but NEVER EOFs during the pipe, so the down
    // leg is still pending when the up leg completes — LocalEof wins by
    // construction, not by scheduling luck.
    let (stream_side, s_peer) = tokio::io::duplex(64);
    let (mut s_pr, mut s_pw) = split(s_peer);
    s_pw.write_all(b"world").await.unwrap();

    let ends = pipe_streams(&mut local_r, &mut local_w, stream_side).await.unwrap();
    assert_eq!(ends.up, Some(5));
    assert_eq!(ends.down, None);
    assert_eq!(ends.first, FirstEnd::LocalEof);

    // The stream carried all local bytes: the up leg ran to EOF, so its
    // writes always happened — unlike the down leg, which may never have
    // been polled. Dropping the local ends first lets the collector see EOF.
    drop(local_r);
    drop(local_w);
    drop(s_pw);
    let mut got_stream = Vec::new();
    s_pr.read_to_end(&mut got_stream).await.unwrap();
    assert_eq!(got_stream, b"hello");
}

#[tokio::test]
async fn both_sides_eof_the_winner_is_complete_with_exact_counts() {
    // Both legs fed and shut: first completion is scheduling, so the test
    // matches on it — whichever direction won ran to EOF with exact counts,
    // and the loser is honestly `None`. No scheduling assumption either way.
    let (mut local_r, lr_peer) = tokio::io::duplex(64);
    let (_lr_pr2, mut lr_pw2) = split(lr_peer);
    lr_pw2.write_all(b"hello").await.unwrap();
    lr_pw2.shutdown().await.unwrap();
    let (mut local_w, _lw_peer) = tokio::io::duplex(64);
    let (stream_side, s_peer) = tokio::io::duplex(64);
    let (_s_pr2, mut s_pw2) = split(s_peer);
    s_pw2.write_all(b"world").await.unwrap();
    s_pw2.shutdown().await.unwrap();

    let ends = pipe_streams(&mut local_r, &mut local_w, stream_side).await.unwrap();
    match ends.first {
        FirstEnd::LocalEof => {
            assert_eq!(ends.up, Some(5));
            assert_eq!(ends.down, None);
        }
        FirstEnd::RemoteEof => {
            assert_eq!(ends.up, None);
            assert_eq!(ends.down, Some(5));
        }
    }
}

#[tokio::test]
async fn remote_eof_first_cuts_the_up_leg() {
    // local stdin: open but silent — the up leg never completes.
    let (mut local_r, _lr_peer) = tokio::io::duplex(64);
    let (mut local_w, lw_peer) = tokio::io::duplex(64);
    let (lw_pr, _lw_pw) = split(lw_peer);
    // stream: whole peer dropped upfront — reads see EOF at once, and the up
    // leg writes nothing because it never reads anything.
    let (stream_side, s_peer) = tokio::io::duplex(64);
    drop(s_peer);

    let ends = pipe_streams(&mut local_r, &mut local_w, stream_side).await.unwrap();
    assert_eq!(ends.up, None);
    assert_eq!(ends.down, Some(0));
    assert_eq!(ends.first, FirstEnd::RemoteEof);
    drop(lw_pr);
}
