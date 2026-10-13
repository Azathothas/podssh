//! The local input of a run (`io::Input`): stdin, read on a task of its own
//! from the first session on, and what comes between two sessions, queued.
//! The command line of `~C` gives back the keys that came after its line
//! (T-291).

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use super::QUEUE;

/// The local input of a run. It is read on its own task from the first
/// session on, so that a session after a lost link reads on where the last
/// one stopped, and what came between them waits in a queue.
#[derive(Default)]
pub struct Input {
    /// `-n`: nothing is read, and the far side sees the end of input at once.
    null: bool,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// The input has ended: a later session sees its end after the queue.
    ended: bool,
    queued: Vec<u8>,
    /// Bytes that did not fit the queue.
    dropped: usize,
}

impl Input {
    /// The input of a run; none with `null` (`-n`).
    pub fn new(null: bool) -> Self {
        Input { null, ..Input::default() }
    }

    /// Whether a session has input to read.
    pub(super) fn open(&self) -> bool {
        !self.null && !(self.ended && self.queued.is_empty())
    }

    /// The next bytes: the queue first, then what is read; `None` at the
    /// end. The task that reads starts at the first call, after the login,
    /// so that it takes nothing that a prompt reads. The line of `~C` reads
    /// here too (T-291).
    pub(crate) async fn next(&mut self) -> Option<Vec<u8>> {
        if !self.queued.is_empty() {
            return Some(std::mem::take(&mut self.queued));
        }
        if self.ended {
            return None;
        }
        let read = self.rx.get_or_insert_with(spawn_stdin).recv().await;
        if read.is_none() {
            self.ended = true;
        }
        read
    }

    /// Give `bytes` back, to be read next, before the queue: the keys that
    /// came after a line of `~C` in their read belong to the session (T-291).
    pub(crate) fn unread(&mut self, mut bytes: Vec<u8>) {
        bytes.append(&mut self.queued);
        self.queued = bytes;
    }

    /// Between two sessions: keep what is read for the next one, [`QUEUE`]
    /// bytes at most. It never returns; the wait drops it when it ends.
    pub async fn queue(&mut self) {
        loop {
            match self.rx.as_mut() {
                Some(rx) if !self.ended => match rx.recv().await {
                    Some(bytes) => {
                        let kept = bytes.len().min(QUEUE.saturating_sub(self.queued.len()));
                        self.queued.extend_from_slice(&bytes[..kept]);
                        self.dropped += bytes.len() - kept;
                    }
                    None => self.ended = true,
                },
                _ => std::future::pending::<()>().await,
            }
        }
    }

    /// The bytes that did not fit the queue since the last call.
    pub fn take_dropped(&mut self) -> usize {
        std::mem::take(&mut self.dropped)
    }
}

/// Read stdin on its own task. The receiver yields `None` at end of input.
fn spawn_stdin() -> mpsc::Receiver<Vec<u8>> {
    // Asked before the task reads: on Windows the question would wait for
    // the pending read.
    let _ = crate::terminal::stdin_is_terminal();
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

/// The next bytes of `input` while `reading`; else never.
pub(super) async fn next(input: &mut Input, reading: bool) -> Option<Vec<u8>> {
    if !reading {
        return std::future::pending().await;
    }
    input.next().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keys given back are read first, then the queue (T-291); nothing
    /// is read from stdin while either holds bytes.
    #[tokio::test]
    async fn escape_command_keys_given_back_are_read_first() {
        let mut input = Input::new(false);
        input.queued = b"queued".to_vec();
        input.unread(b"ls\r".to_vec());
        assert!(input.open());
        assert_eq!(input.next().await, Some(b"ls\rqueued".to_vec()));
        assert!(input.rx.is_none(), "stdin was read");
        // Nothing given back leaves the queue as it was.
        input.queued = b"later".to_vec();
        input.unread(Vec::new());
        assert_eq!(input.next().await, Some(b"later".to_vec()));
    }
}
