//! A link of the road: a byte stream for the resumable layer, made of an
//! end's two ways, its POST and its GET. Each way begins with its mark
//! ([`super::paths::Ends`]), which the receiver checks before the layer
//! reads a byte. The streamed form here sends each way as one request whose
//! body has no end until the link's; [`super::numbered`] sends a request
//! for each piece. When a way ends or fails, the link ends, and the layer
//! goes on with a new one: a Piping Server neither drops nor reorders bytes,
//! so the link needs no acknowledgement of its own.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::task::AbortHandle;

use super::exchange::{Body, Failed, Http, Upload};
use super::paths::{same, Ends, MARK_BYTES};

/// How long a link may take to open: each end's two requests, and the far
/// end's mark. A streamed POST that gets no answer this long is held on the
/// way, which the numbered form passes.
pub const HELLO_LIMIT: Duration = Duration::from_secs(15);
/// Each direction of the pipe between the layer and a link's ways.
pub const PIPE: usize = 256 * 1024;
/// The most bytes that one write of a way takes from the layer.
const PIECE: usize = 32 * 1024;

/// Why a link did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    /// No byte flowed within [`HELLO_LIMIT`]: a proxy may hold a streamed
    /// body until its end.
    Held(String),
    Failed(String),
}

impl std::fmt::Display for Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Opening::Held(why) | Opening::Failed(why) => f.write_str(why),
        }
    }
}

impl From<Failed> for Opening {
    fn from(failed: Failed) -> Opening {
        if failed.waited {
            Opening::Held(format!("{failed}: a proxy on the way may hold a streamed body until its end"))
        } else {
            Opening::Failed(failed.to_string())
        }
    }
}

/// A link: the layer's end of a pipe whose far end a task carries over the
/// link's two ways. Dropping it ends the task, and the ways with it.
pub struct Link {
    io: DuplexStream,
    task: AbortHandle,
}

impl Link {
    pub(super) fn new(io: DuplexStream, task: AbortHandle) -> Link {
        Link { io, task }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AsyncRead for Link {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Link {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Whether `got`, the first bytes of the far end's way, is its mark.
pub(super) fn check_mark(got: &[u8], ends: &Ends) -> Result<(), Opening> {
    if same(got, &ends.theirs) {
        return Ok(());
    }
    let why = "the far end's way began with another mark: not this link's far end, or one that took the wrong way";
    Err(Opening::Failed(why.into()))
}

/// A streamed link of `ends` on `http`'s server: the POST of this end's way,
/// which begins with its mark, and the GET of the far end's, whose mark is
/// read and checked, within [`HELLO_LIMIT`].
pub async fn streamed(http: Arc<Http>, ends: &Ends) -> Result<Link, Opening> {
    let (send, recv) = (http.server().path(&ends.send), http.server().path(&ends.recv));
    let opening = async {
        // The mark goes with the POST's head: a server may answer neither
        // way before a byte of the body came.
        let posting = async { http.post_stream(&send, HELLO_LIMIT, &ends.mine).await.map_err(Opening::from) };
        let getting = async { http.get(&recv, Some(HELLO_LIMIT)).await.map_err(Opening::from) };
        let (upload, mut body) = tokio::try_join!(posting, getting)?;
        let rest = read_mark(&mut body, ends).await?;
        Ok::<_, Opening>((upload, body, rest))
    };
    let (upload, body, rest) = match tokio::time::timeout(HELLO_LIMIT, opening).await {
        Ok(opened) => opened?,
        Err(_) => {
            let why = format!("no byte of the far end's way within {} s", HELLO_LIMIT.as_secs());
            return Err(Opening::Held(format!("{why}: a proxy on the way may hold a streamed body until its end")));
        }
    };
    Ok(carry(upload, body, rest))
}

/// The far end's mark, the first bytes of `body`, checked; and the bytes that
/// came after it.
async fn read_mark(body: &mut Body, ends: &Ends) -> Result<Vec<u8>, Opening> {
    let mut got = Vec::with_capacity(MARK_BYTES);
    while got.len() < MARK_BYTES {
        match body.next().await {
            Ok(Some(bytes)) => got.extend_from_slice(&bytes),
            Ok(None) => return Err(Opening::Failed("the far end's way ended before its mark".into())),
            Err(why) => return Err(Opening::Failed(format!("the far end's way: {why}"))),
        }
    }
    let rest = got.split_off(MARK_BYTES);
    check_mark(&got, ends)?;
    Ok(rest)
}

/// A task that carries the pipe's far end over the two ways: the layer's
/// bytes into the upload, and the body's into the layer, `rest` first.
fn carry(mut upload: Upload, mut body: Body, rest: Vec<u8>) -> Link {
    let (ours, far) = tokio::io::duplex(PIPE);
    let task = tokio::spawn(async move {
        let (mut from_layer, mut to_layer) = tokio::io::split(far);
        // True when the layer ended its bytes, which ends this way cleanly.
        let up = async {
            let mut buf = vec![0u8; PIECE];
            loop {
                match from_layer.read(&mut buf).await {
                    Ok(0) => return upload.finish().await.is_ok(),
                    Ok(n) => {
                        if upload.send(&buf[..n]).await.is_err() {
                            return false;
                        }
                    }
                    Err(_) => return false,
                }
            }
        };
        let down = async {
            if !rest.is_empty() && to_layer.write_all(&rest).await.is_err() {
                return;
            }
            while let Ok(Some(bytes)) = body.next().await {
                if to_layer.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            let _ = to_layer.shutdown().await;
        };
        tokio::pin!(down);
        // A way that failed ends the link; the layer's own end leaves the far
        // end's last bytes to come.
        let clean = tokio::select! {
            clean = up => clean,
            () = &mut down => return,
        };
        if clean {
            down.await;
        }
    });
    Link::new(ours, task.abort_handle())
}
