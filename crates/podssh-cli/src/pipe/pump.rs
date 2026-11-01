//! The copy of `podssh pipe` between two ends (T-174), the one path of a
//! byte pipe: T-175 moves `podssh proxy` onto it.
//!
//! Each direction reads up to 32 KiB at a time, with what more is ready at
//! once, before it writes. When one side's input ends,
//! the other side's write half is shut down, and the other direction goes
//! on: a reply on its way still comes back (an end's write half closes only
//! itself, as a TCP half-close does). A writer whose reader is gone ends the
//! pipe, as a reader that left wants no more. An end with a child ends the
//! pipe when its output ended and the child exited, and an end whose output
//! is its last word (a relay's session that closed) ends it when its output
//! ends: the other side's input may never end (a terminal), and nobody
//! would read it.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Child;

/// The size of each read.
const CHUNK: usize = 32 * 1024;

pub type Reader = Box<dyn AsyncRead + Send + Unpin>;
pub type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// One side of a pipe: what it gives, what it takes, its child, if it
/// started one, and what is left to do after the pump.
pub struct End {
    pub read: Reader,
    pub write: Writer,
    pub child: Option<Child>,
    /// The end of this side's output ends the pipe: nothing more can come.
    pub last_word: bool,
    pub ending: Option<Box<dyn Ending>>,
}

impl End {
    /// A local end: its handles alone.
    pub fn plain(read: Reader, write: Writer) -> End {
        End { read, write, child: None, last_word: false, ending: None }
    }
}

/// How a road ended, once the pump is done with it: an exit code and the
/// lines that say why, or `None` for a clean end.
pub type Verdict = Option<(i32, Vec<String>)>;

/// What a remote end does after the pump: close what is still open, and say
/// how its road ended.
pub trait Ending: Send {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>>;
}

/// What the pump hands back of one side: its child, to be waited for, and
/// its ending.
pub struct Left {
    pub child: Option<Child>,
    pub ending: Option<Box<dyn Ending>>,
}

/// How one direction ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Its input ended, and the other side's write half was shut down.
    Ended,
    /// Its writer's reader is gone.
    Gone,
}

/// What the pump hands back of each side, and the bytes that went from A
/// to B and from B to A.
pub struct Pumped {
    pub a: Left,
    pub b: Left,
    pub carried: (u64, u64),
}

/// Copy `from` to `to` until `from` ends, then shut `to` down; `count`
/// holds the bytes written.
pub async fn copy(mut from: Reader, mut to: Writer, count: &AtomicU64) -> Flow {
    let mut buf = vec![0u8; CHUNK];
    loop {
        // A read that fails is an end of input, as `podssh proxy` reads stdin.
        let mut n = from.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            drop(from);
            let _ = to.shutdown().await;
            return Flow::Ended;
        }
        n += ready_now(&mut from, &mut buf[n..]);
        if to.write_all(&buf[..n]).await.is_err() || to.flush().await.is_err() {
            return Flow::Gone;
        }
        count.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Copy both ways until each input ended, a reader is gone, or a side whose
/// output ended has no more to say. The ends' handles go when this returns,
/// so a child that still runs gets the end of its input.
pub async fn pump(a: End, b: End) -> Pumped {
    let End { read: a_read, write: a_write, child: mut a_child, last_word: a_last, ending: a_ending } = a;
    let End { read: b_read, write: b_write, child: mut b_child, last_word: b_last, ending: b_ending } = b;
    let counts = [AtomicU64::new(0), AtomicU64::new(0)];
    let a_to_b = copy(a_read, b_write, &counts[0]);
    let b_to_a = copy(b_read, a_write, &counts[1]);
    tokio::pin!(a_to_b);
    tokio::pin!(b_to_a);
    // Whether A's output, and B's, has ended.
    let (mut a_done, mut b_done) = (false, false);
    loop {
        tokio::select! {
            flow = &mut a_to_b, if !a_done => {
                if flow == Flow::Gone {
                    break;
                }
                a_done = true;
            }
            flow = &mut b_to_a, if !b_done => {
                if flow == Flow::Gone {
                    break;
                }
                b_done = true;
            }
            () = said(&mut a_child, a_last), if a_done && !b_done => break,
            () = said(&mut b_child, b_last), if b_done && !a_done => break,
        }
        if a_done && b_done {
            break;
        }
    }
    let carried = (counts[0].load(Ordering::Relaxed), counts[1].load(Ordering::Relaxed));
    Pumped { a: Left { child: a_child, ending: a_ending }, b: Left { child: b_child, ending: b_ending }, carried }
}

/// The bytes that `from` has ready at once, into `buf`, waiting for none: a
/// source of small reads (a Tor stream gives one cell, 498 bytes, at each)
/// is then written in few writes, as each write to stdout is a handoff to a
/// thread of tokio's. An end or an error is left for the next read.
fn ready_now(from: &mut Reader, buf: &mut [u8]) -> usize {
    use futures_util::FutureExt as _;
    let mut n = 0;
    while n < buf.len() {
        match from.read(&mut buf[n..]).now_or_never() {
            Some(Ok(m)) if m > 0 => n += m,
            _ => break,
        }
    }
    n
}

/// When a side whose output ended has said all that it will: at once when
/// its output was its last word, when its child exits, else never. tokio
/// keeps a child's status, so a later wait gets it again.
async fn said(child: &mut Option<Child>, last_word: bool) {
    if last_word {
        return;
    }
    match child {
        Some(child) => {
            let _ = child.wait().await;
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn end(stream: tokio::io::DuplexStream) -> End {
        let (read, write) = tokio::io::split(stream);
        End::plain(Box::new(read), Box::new(write))
    }

    /// The end of one side's input reaches the other side, and the reply
    /// still comes back the other way.
    #[tokio::test]
    async fn an_end_of_input_half_closes_the_other_side_and_the_reply_comes_back() {
        let (a_ours, mut a_far) = tokio::io::duplex(1024);
        let (b_ours, mut b_far) = tokio::io::duplex(1024);
        let pumped = tokio::spawn(pump(end(a_ours), end(b_ours)));
        a_far.write_all(b"question").await.unwrap();
        a_far.shutdown().await.unwrap();
        // B reads the question, then the end of its input.
        let mut got = Vec::new();
        b_far.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"question");
        // Its reply, after that, still reaches A.
        b_far.write_all(b"answer").await.unwrap();
        b_far.shutdown().await.unwrap();
        let mut back = Vec::new();
        a_far.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"answer");
        tokio::time::timeout(Duration::from_secs(5), pumped).await.expect("the pump ends").unwrap();
    }

    /// A source that gives a cell at a time, each ready at once.
    struct Cells {
        left: usize,
    }

    impl AsyncRead for Cells {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let n = self.left.min(498).min(buf.remaining());
            buf.put_slice(&vec![7u8; n]);
            self.left -= n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A writer that keeps the size of each write.
    #[derive(Default)]
    struct Writes(std::sync::Arc<std::sync::Mutex<Vec<usize>>>);

    impl AsyncWrite for Writes {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.lock().unwrap().push(buf.len());
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Small reads that are ready at once leave in writes of the chunk's
    /// size, not one write for each read.
    #[tokio::test]
    async fn small_reads_that_are_ready_are_written_together() {
        let writes = Writes::default();
        let sizes = writes.0.clone();
        let total = 256 * 1024;
        let count = AtomicU64::new(0);
        let flow = copy(Box::new(Cells { left: total }), Box::new(writes), &count).await;
        assert_eq!(flow, Flow::Ended);
        assert_eq!(count.load(Ordering::Relaxed), total as u64);
        let sizes = sizes.lock().unwrap().clone();
        assert_eq!(sizes.iter().sum::<usize>(), total);
        assert!(sizes.len() <= total / CHUNK + 1, "{} writes for {} reads of 498 bytes", sizes.len(), total / 498);
    }

    /// A side whose reader left ends the pipe, though the other input goes on.
    #[tokio::test]
    async fn a_reader_that_is_gone_ends_the_pipe() {
        let (a_ours, mut a_far) = tokio::io::duplex(1024);
        let (b_ours, b_far) = tokio::io::duplex(1024);
        let pumped = tokio::spawn(pump(end(a_ours), end(b_ours)));
        drop(b_far);
        // A keeps sending; its bytes have no reader at B.
        for _ in 0..4 {
            let _ = a_far.write_all(&[7u8; 512]).await;
        }
        tokio::time::timeout(Duration::from_secs(5), pumped).await.expect("the pump ends").unwrap();
    }
}
