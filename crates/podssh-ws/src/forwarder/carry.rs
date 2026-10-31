//! A forwarder's session as a byte stream (T-369). Two tasks copy between
//! the session and one end of a pipe in memory: bytes out in binary frames
//! of 32 KiB at most, as each Worker's socket takes them safely; binary
//! frames back in as bytes. A text frame is the forwarder's own word (a
//! Worker's `{"type":"game.connected"}`): it goes to the note of the caller,
//! never into the stream. The first frame of the frame form is the
//! forwarder's answer to the target, and is read here, not passed on. The
//! forwarder's Close, or a failure, is kept in a [`Status`], because the
//! stream's reader can only see its end.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{oneshot, Notify};
use tokio::task::JoinHandle;

use super::template::Form;
use super::Note;
use crate::frame;
use crate::session::{close_code_and_reason, RelaySession};

/// The pipe in memory, each way.
const PIPE: usize = 256 * 1024;
/// The largest frame sent: a frame above 64 KiB can break a Worker's
/// socket (workerd issue 7074), as on the relay's road.
const CHUNK: usize = frame::FORWARD_SEND_PAYLOAD;
/// The most characters of a forwarder's text frame that a note shows.
const NOTE_CHARS: usize = 200;

/// How a forwarder's session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// A Close, the forwarder's or this side's.
    Closed { code: Option<u16>, reason: String },
    /// A failure with no Close.
    Failed(String),
}

/// The end of a session, once it came; the first word wins.
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

/// An open session: the stream of the target's bytes, and its end.
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
    /// Stop both tasks, for a session that is given up before its use.
    pub(super) fn abort(&self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The forwarder's first word after the upgrade.
pub(super) enum First {
    /// A frame came: the target's bytes or a note, or the answer `ok`.
    Ready,
    Closed { code: Option<u16>, reason: String },
    Failed(String),
}

fn say(first: &mut Option<oneshot::Sender<First>>, word: First) {
    if let Some(tx) = first.take() {
        let _ = tx.send(word);
    }
}

/// A note of a text frame: one line, made safe for a terminal, and short.
fn note_text(payload: &[u8]) -> String {
    let line = crate::text::one_line(&String::from_utf8_lossy(payload));
    match line.char_indices().nth(NOTE_CHARS) {
        Some((at, _)) => format!("{}...", &line[..at]),
        None => line,
    }
}

/// Start copying; the receiver gets the forwarder's first word. With
/// `close_at_end`, the end of this side's bytes sends a Close at once (an
/// SSH session that is done); else the session waits for the forwarder's
/// end, as the target may still answer (a pipe).
pub(super) fn spawn<S>(
    session: RelaySession<S>,
    form: Form,
    close_at_end: bool,
    note: Note,
) -> (Carried, oneshot::Receiver<First>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let status = Status::default();
    let session = Arc::new(session);
    let (mut from_local, mut to_local) = tokio::io::split(theirs);
    // Each task's end stops the other, as on the relay's road: a write of
    // the reader's could wait on a pipe that only the sending task reads.
    let up_failed = Arc::new(Notify::new());
    let down_ended = Arc::new(Notify::new());
    let (first_tx, first_rx) = oneshot::channel();

    let (up_session, up_status, up_failed_tx, down_ended_rx) =
        (session.clone(), status.clone(), up_failed.clone(), down_ended.clone());
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let read = tokio::select! {
                read = from_local.read(&mut buf) => read,
                () = down_ended_rx.notified() => {
                    let _ = up_session.send_close(1000, "").await;
                    return;
                }
            };
            match read {
                Ok(0) | Err(_) => {
                    if !close_at_end {
                        down_ended_rx.notified().await;
                    }
                    let _ = up_session.send_close(1000, "").await;
                    return;
                }
                Ok(n) => {
                    if let Err(e) = up_session.send_binary(&buf[..n]).await {
                        up_status.set_once(Ended::Failed(format!("sending to the forwarder failed: {e}")));
                        up_failed_tx.notify_one();
                        return;
                    }
                }
            }
        }
    });

    let down_status = status.clone();
    let down = tokio::spawn(async move {
        let mut first = Some(first_tx);
        // The query form has no answer to wait for.
        let mut answered = form == Form::Query;
        let liveness = session.watch_liveness(crate::LIVENESS_EVERY, crate::LIVENESS_ALLOWED);
        tokio::pin!(liveness);
        loop {
            let read = tokio::select! {
                read = session.read_frame() => read,
                reason = &mut liveness => {
                    let why = reason.to_string();
                    down_status.set_once(Ended::Failed(why.clone()));
                    say(&mut first, First::Failed(why));
                    break;
                }
                () = up_failed.notified() => break,
            };
            let f = match read {
                Ok(f) => f,
                Err(e) => {
                    let why = e.to_string();
                    down_status.set_once(Ended::Failed(why.clone()));
                    say(&mut first, First::Failed(why));
                    break;
                }
            };
            match f.opcode {
                frame::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    down_status.set_once(Ended::Closed { code, reason: reason.clone() });
                    say(&mut first, First::Closed { code, reason });
                    break;
                }
                // ssheasy answers in a binary frame, another forwarder may in a
                // text one: either is the answer, and neither is the target's.
                frame::OPCODE_TEXT | frame::OPCODE_BINARY if !answered => match super::answer(&f.payload) {
                    Ok(()) => {
                        answered = true;
                        say(&mut first, First::Ready);
                    }
                    Err(why) => {
                        down_status.set_once(Ended::Failed(why.clone()));
                        say(&mut first, First::Failed(why));
                        let _ = session.send_close(1000, "").await;
                        break;
                    }
                },
                frame::OPCODE_TEXT => {
                    say(&mut first, First::Ready);
                    (*note)(&note_text(&f.payload));
                }
                frame::OPCODE_BINARY => {
                    say(&mut first, First::Ready);
                    if !f.payload.is_empty() {
                        let wrote = tokio::select! {
                            wrote = to_local.write_all(&f.payload) => wrote.is_ok(),
                            () = up_failed.notified() => false,
                        };
                        if !wrote {
                            break;
                        }
                    }
                }
                other => {
                    let why = format!("an unexpected frame (opcode {other:#x}) from the forwarder");
                    down_status.set_once(Ended::Failed(why.clone()));
                    say(&mut first, First::Failed(why));
                    let _ = session.send_close(1002, "").await;
                    break;
                }
            }
        }
        // The end of the stream for its reader; the sending task stops too.
        down_ended.notify_one();
        let _ = to_local.shutdown().await;
    });

    (Carried { stream: ours, status, tasks: [up, down] }, first_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_note_is_one_safe_short_line() {
        assert_eq!(note_text(b"{\"type\":\"game.connected\"}"), "{\"type\":\"game.connected\"}");
        assert_eq!(note_text(b"a\x1b[2J\r\nb"), "a[2J b");
        let long = note_text("x".repeat(500).as_bytes());
        assert_eq!(long.len(), NOTE_CHARS + 3, "{long}");
    }

    #[test]
    fn the_first_end_of_a_status_wins() {
        let status = Status::default();
        assert_eq!(status.get(), None);
        status.set_once(Ended::Closed { code: Some(1011), reason: "connect failed".into() });
        status.set_once(Ended::Failed("later".into()));
        assert_eq!(status.get(), Some(Ended::Closed { code: Some(1011), reason: "connect failed".into() }));
    }
}
