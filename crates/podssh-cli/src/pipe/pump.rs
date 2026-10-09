//! The copy of `podssh pipe` between two ends (T-174), the one path of a
//! byte pipe: T-175 moves `podssh proxy` onto it.
//!
//! Each direction reads up to 32 KiB at a time. When one side's input ends,
//! the other side's write half is shut down, and the other direction goes
//! on: a reply on its way still comes back (an end's write half closes only
//! itself, as a TCP half-close does). A writer whose reader is gone ends the
//! pipe, as a reader that left wants no more. An end with a child ends the
//! pipe when its output ended and the child exited: the other side's input
//! may never end (a terminal), and nobody would read it.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Child;

/// The size of each read.
const CHUNK: usize = 32 * 1024;

pub type Reader = Box<dyn AsyncRead + Send + Unpin>;
pub type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// One side of a pipe: what it gives, what it takes, and its child, if it
/// started one.
pub struct End {
    pub read: Reader,
    pub write: Writer,
    pub child: Option<Child>,
}

/// How one direction ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Its input ended, and the other side's write half was shut down.
    Ended,
    /// Its writer's reader is gone.
    Gone,
}

/// The children that the pump hands back, to be waited for.
pub struct Pumped {
    pub a: Option<Child>,
    pub b: Option<Child>,
}

/// Copy `from` to `to` until `from` ends, then shut `to` down.
pub async fn copy(mut from: Reader, mut to: Writer) -> Flow {
    let mut buf = vec![0u8; CHUNK];
    loop {
        // A read that fails is an end of input, as `podssh proxy` reads stdin.
        let n = from.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            drop(from);
            let _ = to.shutdown().await;
            return Flow::Ended;
        }
        if to.write_all(&buf[..n]).await.is_err() || to.flush().await.is_err() {
            return Flow::Gone;
        }
    }
}

/// Copy both ways until each input ended, a reader is gone, or a child
/// exited after its output ended. The ends' handles go when this returns, so
/// a child that still runs gets the end of its input.
pub async fn pump(a: End, b: End) -> Pumped {
    let End { read: a_read, write: a_write, child: mut a_child } = a;
    let End { read: b_read, write: b_write, child: mut b_child } = b;
    let a_to_b = copy(a_read, b_write);
    let b_to_a = copy(b_read, a_write);
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
            () = exited(&mut a_child), if a_done && !b_done => break,
            () = exited(&mut b_child), if b_done && !a_done => break,
        }
        if a_done && b_done {
            break;
        }
    }
    Pumped { a: a_child, b: b_child }
}

/// When the child exits; never, with no child. tokio keeps the status, so a
/// later wait gets it again.
async fn exited(child: &mut Option<Child>) {
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
        End { read: Box::new(read), write: Box::new(write), child: None }
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
