//! A stream through a Shadowsocks server as a byte stream: two tasks copy
//! between the server's connection and one end of a pipe in memory, sealing
//! what goes out and opening what comes back, as the forwarders' road does.
//! The end of this side's bytes is TCP's half-close, which the server
//! passes on to the target; the server's end is the stream's. A chunk that
//! does not open, or a connection that fails, is kept in a [`Status`],
//! because the stream's reader can only see its end.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

use super::codec::{Decoder, Encoder, MAX_PAYLOAD};

/// The pipe in memory, each way.
const PIPE: usize = 256 * 1024;
/// The most bytes read from the server at once.
const READ: usize = 32 * 1024;

/// How a stream ended, when it was not the server's ordinary end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// A chunk of the server's did not open, or its stream ended inside one.
    Chunk(String),
    /// The connection to the server failed.
    Failed(String),
}

/// The end of a stream, once it came; the first word wins.
#[derive(Debug, Clone, Default)]
pub struct Status(Arc<Mutex<Option<Ended>>>);

impl Status {
    pub fn get(&self) -> Option<Ended> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_once(&self, ended: Ended) {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(ended);
        }
    }
}

/// An open stream: the target's bytes, and its end.
pub struct Carried {
    pub stream: DuplexStream,
    pub status: Status,
    tasks: [JoinHandle<()>; 2],
}

impl std::fmt::Debug for Carried {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Carried").field("status", &self.status).finish()
    }
}

impl Carried {
    /// Stop both tasks, for a stream that is given up before its use.
    pub fn abort(&self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Start copying over `server`, whose salt and first chunk `encoder` has
/// sent, and whose first chunk's plaintext, when it was waited for, is
/// `early`.
pub(super) fn spawn<S>(server: S, encoder: Encoder, decoder: Decoder, early: Vec<u8>) -> Carried
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let status = Status::default();
    let (mut from_local, mut to_local) = tokio::io::split(theirs);
    let (mut from_server, mut to_server) = tokio::io::split(server);

    let up_status = status.clone();
    let up = tokio::spawn(async move {
        let mut encoder = encoder;
        let mut buf = vec![0u8; MAX_PAYLOAD];
        let mut out = Vec::with_capacity(MAX_PAYLOAD + 64);
        loop {
            let n = match from_local.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    // TCP's half-close: the server passes it on to the target,
                    // whose answer may still come.
                    let _ = to_server.shutdown().await;
                    return;
                }
                Ok(n) => n,
            };
            out.clear();
            if let Err(e) = encoder.seal(&buf[..n], &mut out) {
                up_status.set_once(Ended::Failed(format!("sealing a chunk failed: {e}")));
                let _ = to_server.shutdown().await;
                return;
            }
            if let Err(e) = to_server.write_all(&out).await {
                up_status.set_once(Ended::Failed(format!("sending to the server failed: {e}")));
                return;
            }
        }
    });

    let down_status = status.clone();
    let down = tokio::spawn(async move {
        let mut decoder = decoder;
        let mut buf = vec![0u8; READ];
        let mut open = early.is_empty() || to_local.write_all(&early).await.is_ok();
        while open {
            let n = match from_server.read(&mut buf).await {
                Ok(0) => {
                    if decoder.buffered() > 0 {
                        down_status.set_once(Ended::Chunk("its stream ended inside a chunk".into()));
                    }
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    down_status.set_once(Ended::Failed(format!("the connection to the server failed: {e}")));
                    break;
                }
            };
            decoder.feed(&buf[..n]);
            loop {
                match decoder.chunk() {
                    Ok(Some(plain)) => {
                        if to_local.write_all(&plain).await.is_err() {
                            // This side is gone: nothing reads the target's bytes.
                            open = false;
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        down_status.set_once(Ended::Chunk(format!("a chunk of the server's did not open: {e}")));
                        open = false;
                        break;
                    }
                }
            }
        }
        // The end of the stream for its reader.
        let _ = to_local.shutdown().await;
    });

    Carried { stream: ours, status, tasks: [up, down] }
}
