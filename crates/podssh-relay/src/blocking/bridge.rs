//! The sessions of a blocking caller: a reader and a writer, carried to and
//! from the async runners by two threads each. Blocking reads and writes
//! never run on the runtime's thread, so one slow session cannot stall the
//! others.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::pin::Pin;
use std::sync::{mpsc, Arc};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_transport::SessionId;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::runtime::Handle;

use crate::reverse::{Handler, Opening};

/// The bytes that each direction of a session holds in memory.
const PIPE_BYTES: usize = 64 * 1024;

/// The local side of one session: what `reader` gives goes to the relay, and
/// what the relay sends goes to `writer`.
pub struct Local {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    finish: Option<Box<dyn FnOnce() + Send>>,
}

impl Local {
    /// A reader and a writer, such as a child's stdout and stdin. The writer
    /// is dropped after the relay's last byte, which closes a pipe.
    pub fn new(reader: impl Read + Send + 'static, writer: impl Write + Send + 'static) -> Local {
        Local { reader: Box::new(reader), writer: Box::new(writer), finish: None }
    }

    /// A TCP connection: a clone of it is read. After the relay's last byte
    /// its write side is shut, so the peer reads the end; a dropped clone
    /// would not close it.
    pub fn tcp(stream: TcpStream) -> io::Result<Local> {
        let reader = stream.try_clone()?;
        let closer = stream.try_clone()?;
        Ok(Local::new(reader, stream).on_finish(move || {
            let _ = closer.shutdown(Shutdown::Write);
        }))
    }

    /// Run `finish` after the relay's last byte is written and flushed.
    pub fn on_finish(mut self, finish: impl FnOnce() + Send + 'static) -> Local {
        self.finish = Some(Box::new(finish));
        self
    }
}

impl std::fmt::Debug for Local {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Local").field("finish", &self.finish.is_some()).finish_non_exhaustive()
    }
}

/// What a blocking node does with each session: open its local side, or
/// refuse it with a reason, which the operator gets whole.
pub trait BlockingHandler: Send + Sync + 'static {
    /// `id` is the session's 32 lowercase hex characters. Called on a thread
    /// of its own; the node waits for the answer up to `Settings::open_limit`
    /// (10 s by default), under the relay's 15 s.
    fn open(&self, id: &str) -> Result<Local, String>;
}

impl<F> BlockingHandler for F
where
    F: Fn(&str) -> Result<Local, String> + Send + Sync + 'static,
{
    fn open(&self, id: &str) -> Result<Local, String> {
        self(id)
    }
}

/// A [`BlockingHandler`] as a handler of the async node.
pub(crate) struct Bridged<H>(pub(crate) Arc<H>);

impl<H: BlockingHandler> Handler for Bridged<H> {
    type Stream = Joined;

    fn open(&self, id: SessionId) -> Opening<Joined> {
        let handler = self.0.clone();
        Box::pin(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let id = id.as_str().to_string();
            // Its own thread, with no runtime: the handler may block, and may
            // call the client. If it panics, `tx` drops, and the session is
            // refused.
            spawn("podssh-relay open", move || {
                let _ = tx.send(handler.open(&id));
            })?;
            let local = rx.await.map_err(|_| "the handler of the session failed".to_string())??;
            Ok(bridge(local, Handle::current())?.stream)
        })
    }
}

/// A session's stream for the runners, and the sign that its output ended.
pub(crate) struct Bridge {
    pub(crate) stream: Joined,
    pub(crate) output_done: OutputDone,
}

/// Sent when the output thread has written, flushed and finished.
pub(crate) struct OutputDone(mpsc::Receiver<()>);

impl OutputDone {
    /// Wait up to `limit` for the last bytes to reach the writer: a writer
    /// that never takes them must not hold the caller forever.
    pub(crate) fn wait(&self, limit: Duration) {
        let _ = self.0.recv_timeout(limit);
    }
}

/// Carry `local` to and from a stream for the runners. One thread reads the
/// reader into one pipe; one thread writes what comes out of the other pipe.
/// The end of either side reaches the other: the end of the reader ends the
/// input, and the end of the runner's writes ends the writer.
pub(crate) fn bridge(local: Local, runtime: Handle) -> Result<Bridge, String> {
    let Local { mut reader, mut writer, finish } = local;
    let (input, mut input_end) = tokio::io::duplex(PIPE_BYTES);
    let (output, mut output_end) = tokio::io::duplex(PIPE_BYTES);
    let (done, output_done) = mpsc::channel();
    let input_runtime = runtime.clone();
    spawn("podssh-relay input", move || {
        let mut buf = vec![0u8; PIPE_BYTES];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            // A failed write: the session ended, and nobody reads.
            if input_runtime.block_on(input_end.write_all(&buf[..n])).is_err() {
                return;
            }
        }
        let _ = input_runtime.block_on(input_end.shutdown());
    })?;
    spawn("podssh-relay output", move || {
        let mut buf = vec![0u8; PIPE_BYTES];
        loop {
            match runtime.block_on(output_end.read(&mut buf)) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // A writer that fails ends the output: dropping the pipe
                    // tells the runner that the local side is gone.
                    if writer.write_all(&buf[..n]).and_then(|()| writer.flush()).is_err() {
                        break;
                    }
                }
            }
        }
        drop(output_end);
        let _ = writer.flush();
        drop(writer);
        if let Some(finish) = finish {
            finish();
        }
        let _ = done.send(());
    })?;
    Ok(Bridge { stream: Joined { read: input, write: output }, output_done: OutputDone(output_done) })
}

fn spawn(name: &str, work: impl FnOnce() + Send + 'static) -> Result<(), String> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(work)
        .map(|_| ())
        .map_err(|e| format!("a thread for the session could not start: {e}"))
}

/// One stream from two pipes: it reads the input pipe and writes the output
/// pipe. Dropping it closes both, so each thread sees the end.
pub(crate) struct Joined {
    read: DuplexStream,
    write: DuplexStream,
}

impl AsyncRead for Joined {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for Joined {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}
