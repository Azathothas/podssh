//! A forward session as a blocking stream.

use std::io::{self, Read, Write};
use std::sync::Mutex;

use podssh_ws::frame;
use podssh_ws::session::close_code_and_reason;
use podssh_ws::SessionError;

use super::Client;
use crate::relay::Relay;
use crate::reverse::wire::Socket;

/// The largest payload of a frame that a forward session sends, as `podssh
/// proxy` sends them.
const FRAME_PAYLOAD: usize = 32 * 1024;

/// The relay ended a forward session with a code other than `1000`: the code
/// and the reason. A read gives it in an `io::Error` of the kind
/// `ConnectionAborted` (`io::Error::get_ref`, then `downcast_ref`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    pub code: u16,
    pub reason: String,
}

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the relay ended the session: {} {}", self.code, self.reason)
    }
}

impl std::error::Error for Closed {}

/// A forward session through the relay, as a blocking stream: a read gives
/// the target's bytes, and a write sends bytes to it. A read and a write may
/// run on two threads at once, as with a `TcpStream`: `&Forward` reads and
/// writes too. A read gives `Ok(0)` after a Close `1000`.
pub struct Forward<'c> {
    client: &'c Client,
    socket: Socket,
    relay: Relay,
    notes: Vec<String>,
    read: Mutex<ReadState>,
}

#[derive(Default)]
struct ReadState {
    /// The rest of the last frame, from `at`.
    pending: Vec<u8>,
    at: usize,
    /// The relay's Close, once it came.
    ended: Option<Result<(), Closed>>,
}

impl<'c> Forward<'c> {
    pub(super) fn new(client: &'c Client, socket: Socket, relay: Relay, notes: Vec<String>) -> Forward<'c> {
        Forward { client, socket, relay, notes, read: Mutex::default() }
    }

    /// The relay host that opened the session.
    pub fn relay(&self) -> &Relay {
        &self.relay
    }

    /// What the opener noted on the way: a host that failed, a token that
    /// could not be cached.
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Send no more: a Close `1000`. The relay then delivers nothing more to
    /// the target, but reads go on: the target's bytes still come until it
    /// closes, or until it is idle for 15 s, and then the relay's Close `1000`
    /// ends them (measured 2026-10-09, `python scripts/capture-close.py
    /// --client-close`). A write after it fails.
    pub fn shutdown_write(&self) -> io::Result<()> {
        // `send_close` sends one Close at most: an answer to the relay's own
        // Close counts.
        self.client.block_on(self.socket.send_close(1000, "")).map_err(outside)?.map_err(session_error)
    }

    /// End the session now: a Close `1000` unless one went already, then the
    /// connection is dropped, with no wait for the relay's answer, which
    /// would wait for the target. To read what the target still sends, call
    /// [`Forward::shutdown_write`] and read to the end instead. A session
    /// dropped without either ends with no Close.
    pub fn close(self) -> io::Result<()> {
        if self.socket.close_sent() {
            return Ok(());
        }
        self.shutdown_write()
    }
}

impl Read for &Forward<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.read.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if state.at < state.pending.len() {
                let n = (state.pending.len() - state.at).min(buf.len());
                buf[..n].copy_from_slice(&state.pending[state.at..state.at + n]);
                state.at += n;
                return Ok(n);
            }
            match &state.ended {
                Some(Ok(())) => return Ok(0),
                Some(Err(closed)) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, closed.clone())),
                None => {}
            }
            let f = self.client.block_on(self.socket.read_frame()).map_err(outside)?.map_err(session_error)?;
            match f.opcode {
                // An empty frame is the relay's keepalive.
                frame::OPCODE_BINARY => {
                    state.pending = f.payload;
                    state.at = 0;
                }
                frame::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    state.ended = Some(match code {
                        None | Some(1000) => Ok(()),
                        Some(code) => Err(Closed { code, reason }),
                    });
                }
                frame::OPCODE_TEXT => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the relay sent a text frame on the forward path",
                    ))
                }
                _ => {}
            }
        }
    }
}

impl Write for &Forward<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(FRAME_PAYLOAD);
        self.client.block_on(self.socket.send_binary(&buf[..n])).map_err(outside)?.map_err(session_error)?;
        Ok(n)
    }

    /// Each write is a frame on the wire already.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for Forward<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }
}

impl Write for Forward<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}

impl std::fmt::Debug for Forward<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forward").field("relay", &self.relay).field("notes", &self.notes).finish_non_exhaustive()
    }
}

/// A call from inside a tokio runtime, as an I/O error.
fn outside(e: super::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// A failure of the session, with the kind that it names.
fn session_error(e: SessionError) -> io::Error {
    let kind = match &e {
        SessionError::Io { kind, .. } => *kind,
        SessionError::Idle(_) | SessionError::WriteStalled(_) | SessionError::Dead(_) => io::ErrorKind::TimedOut,
        SessionError::ClosedWithoutClose(_) => io::ErrorKind::UnexpectedEof,
        SessionError::Protocol(_) | SessionError::TooLarge(_) => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, e.to_string())
}
