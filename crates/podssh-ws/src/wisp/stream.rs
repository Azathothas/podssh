//! A Wisp stream as its caller holds it: a byte stream (a pipe in memory,
//! whose other end two tasks copy to and from the connection), the word of
//! its state, and its end.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::mux::{Opening, Shared, Word};
use super::{End, Reason, WispError};

/// One stream of a Wisp connection.
pub struct WispStream {
    id: u32,
    pipe: DuplexStream,
    word: watch::Receiver<Word>,
    confirm: bool,
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for WispStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WispStream").field("id", &self.id).field("word", &*self.word.borrow()).finish()
    }
}

impl WispStream {
    pub(super) fn new(opening: Opening, shared: Arc<Shared>) -> WispStream {
        let confirm = shared.opened.confirm;
        WispStream { id: opening.id, pipe: opening.pipe, word: opening.word, confirm, shared, tasks: opening.tasks }
    }

    /// The stream's id on the connection.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Until the server's first word for the stream: its DATA or its
    /// CONTINUE (open), or its CLOSE, whose reason is the error. Where the
    /// server confirms streams, no word within `wait` is a failure. Where
    /// it does not (version 1, as wisp-server-python), it says nothing of a
    /// stream that opened, and only a target that it could not reach is a
    /// CLOSE: the end of `wait` is taken as open, as a Worker's silence is
    /// by the query form of a forwarder.
    pub async fn opened(&mut self, wait: Duration) -> Result<(), WispError> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let now = self.word.borrow_and_update().clone();
            match now {
                Word::Open => return Ok(()),
                Word::Ended(end) => return Err(end.into_error()),
                Word::Waiting => {}
            }
            match tokio::time::timeout_at(deadline, self.word.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(WispError::Failed("the stream ended with no word of the server".into())),
                Err(_) if self.confirm => {
                    let secs = wait.as_secs();
                    let why = format!("the Wisp server did not confirm the stream within {secs} s");
                    return Err(WispError::Opening(why));
                }
                Err(_) => return Ok(()),
            }
        }
    }

    /// How the stream ended, once it did.
    pub fn end(&self) -> Option<End> {
        match &*self.word.borrow() {
            Word::Ended(end) => Some(end.clone()),
            _ => None,
        }
    }

    /// This side's CLOSE, unless the stream already ended.
    pub async fn close(&self) {
        self.shared.close_here(self.id, Reason::VOLUNTARY).await;
    }

    /// The pipe, and the stream's two tasks, for a road that keeps its own
    /// status ([`super::forward`]).
    pub(crate) fn into_parts(self) -> (DuplexStream, Vec<JoinHandle<()>>) {
        (self.pipe, self.tasks)
    }
}

impl AsyncRead for WispStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().pipe).poll_read(cx, buf)
    }
}

impl AsyncWrite for WispStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().pipe).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().pipe).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().pipe).poll_shutdown(cx)
    }
}
