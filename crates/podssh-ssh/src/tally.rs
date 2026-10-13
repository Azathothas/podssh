//! The forwards of a run and what each carried (T-041): for each forward,
//! its connections opened, open and failed, and the bytes each way, for the
//! escape `~#` and, with `-v`, the end of the run. The bytes are counted as
//! they are read, on atomics: no lock on the data path. A process runs one
//! chain of connections, so the table is the process's; a forward asked for
//! again on a new connection (`--persist`) keeps its counts. A forward that
//! `~C` stopped stays in the list, said closed (T-291).

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What one forward carried.
#[derive(Debug, Default)]
pub struct Counts {
    opened: AtomicU64,
    ended: AtomicU64,
    failed: AtomicU64,
    /// The bytes toward the server, and from it.
    up: AtomicU64,
    down: AtomicU64,
    /// `~C -KL`, `-KD` or `-KR` stopped it (T-291).
    closed: AtomicBool,
}

impl Counts {
    /// A connection that could not be made.
    pub fn failed(&self) {
        self.failed.fetch_add(1, Relaxed);
    }

    pub fn add_up(&self, bytes: u64) {
        self.up.fetch_add(bytes, Relaxed);
    }

    pub fn add_down(&self, bytes: u64) {
        self.down.fetch_add(bytes, Relaxed);
    }

    /// One connection, from its start to its end.
    pub fn connection(self: &Arc<Self>) -> Connection {
        self.opened.fetch_add(1, Relaxed);
        Connection(self.clone())
    }

    /// The counts in words: the connections, those open and failed, and the
    /// bytes each way.
    pub fn line(&self) -> String {
        let opened = self.opened.load(Relaxed);
        let open = opened.saturating_sub(self.ended.load(Relaxed));
        let failed = self.failed.load(Relaxed);
        let s = |n: u64| if n == 1 { "" } else { "s" };
        let closed = if self.closed.load(Relaxed) { "; closed" } else { "" };
        format!(
            "{opened} connection{} ({open} open, {failed} failed), {} bytes up, {} bytes down{closed}",
            s(opened),
            self.up.load(Relaxed),
            self.down.load(Relaxed)
        )
    }
}

/// A connection of a forward: it ends when dropped.
pub struct Connection(Arc<Counts>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.ended.fetch_add(1, Relaxed);
    }
}

static TABLE: Mutex<Vec<(String, Arc<Counts>)>> = Mutex::new(Vec::new());

/// The counts of the forward named `name`, as the user wrote it (`-R
/// 8080:web:80`), made at its first use.
pub fn of(name: &str) -> Arc<Counts> {
    let mut table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, counts)) = table.iter().find(|(n, _)| n == name) {
        return counts.clone();
    }
    let counts = Arc::new(Counts::default());
    table.push((name.to_string(), counts.clone()));
    counts
}

/// The counts of `name`, as [`of`], for a forward that serves or that the
/// server took from now on: open, even if `~C` had closed it (T-291).
pub fn opened(name: &str) -> Arc<Counts> {
    let counts = of(name);
    counts.closed.store(false, Relaxed);
    counts
}

/// `~C` stopped the forward named `name` (T-291): `~#` says so.
pub fn closed(name: &str) {
    of(name).closed.store(true, Relaxed);
}

/// Whether `~C` stopped the forward named `name`, and nothing opened it
/// again since (T-291): a new connection of `--persist` does not ask for it.
pub fn is_closed(name: &str) -> bool {
    let table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    table.iter().any(|(n, counts)| n == name && counts.closed.load(Relaxed))
}

/// A line for each forward, in the order of their first use.
pub fn lines() -> Vec<String> {
    let table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    table.iter().map(|(name, counts)| format!("{name}: {}", counts.line())).collect()
}

/// What `~#` prints.
pub fn listing() -> String {
    let lines = lines();
    if lines.is_empty() {
        return "This session has no forwards.\n".into();
    }
    let mut out = String::from("The forwards of this session:\n");
    for line in lines {
        out.push_str("  ");
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// A stream whose reads are counted: up for the local side of a forward,
/// down for its channel.
pub struct Counted<S> {
    inner: S,
    counts: Arc<Counts>,
    up: bool,
}

impl<S> Counted<S> {
    pub fn up(inner: S, counts: &Arc<Counts>) -> Self {
        Counted { inner, counts: counts.clone(), up: true }
    }

    pub fn down(inner: S, counts: &Arc<Counts>) -> Self {
        Counted { inner, counts: counts.clone(), up: false }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = (buf.filled().len() - before) as u64;
        if read > 0 {
            if self.up {
                self.counts.add_up(read);
            } else {
                self.counts.add_down(read);
            }
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Copy both ways between the local side of a forward and its channel, as
/// `copy_bidirectional` does, counting one connection and its bytes.
pub async fn copy<L, C>(local: L, channel: C, counts: &Arc<Counts>) -> std::io::Result<(u64, u64)>
where
    L: AsyncRead + AsyncWrite + Unpin,
    C: AsyncRead + AsyncWrite + Unpin,
{
    let _connection = counts.connection();
    let mut local = Counted::up(local, counts);
    let mut channel = Counted::down(channel, counts);
    tokio::io::copy_bidirectional(&mut local, &mut channel).await
}

#[cfg(test)]
#[path = "tally_tests.rs"]
mod tests;
