//! An open WebSocket session to the relay, usable from two tasks at once.
//!
//! The stream is split into a read half and a write half with separate locks,
//! so a task waiting for the relay's next frame never blocks another task that
//! is sending. (The first version held one lock across the read, so a
//! keystroke could not be sent while the reader waited for the echo that the
//! keystroke would have caused.)
//!
//! The reader answers Pings itself, ignores Pongs, reassembles fragmented
//! messages, and echoes a Close it did not start (RFC 6455 §5.5.1). It
//! returns data frames and the Close; nothing else reaches the caller.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::client::{next_event, write_frame_over, Event};
use crate::frame::{self, Frame};

/// The stream a live session runs over.
pub type RelayStream = tokio_rustls::client::TlsStream<TcpStream>;

/// The largest message reassembled from fragments. The relay's own frames
/// are at most 262144 bytes; this leaves room and still bounds memory.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// A WebSocket session. All methods take `&self`, so an `Arc<RelaySession>`
/// can be read in one task and written in another.
pub struct RelaySession<S = RelayStream> {
    reader: Mutex<Reader<S>>,
    writer: Mutex<WriteHalf<S>>,
    close_sent: AtomicBool,
    /// Bound on one write.
    write_timeout: Duration,
}

struct Reader<S> {
    half: ReadHalf<S>,
    /// Bytes read off the socket and not yet decoded (the first may have
    /// arrived with the upgrade response).
    pending: Vec<u8>,
    close_received: bool,
    /// A fragmented message being reassembled: its opcode and payload so far.
    partial: Option<(u8, Vec<u8>)>,
    /// How long a read may wait for the next frame. The relay sends a
    /// keepalive every 25 s, so anything above that only fires on a dead link.
    idle: Option<Duration>,
}

impl<S> std::fmt::Debug for RelaySession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Opaque: a session is a credential in use.
        f.write_str("RelaySession(..)")
    }
}

impl<S: AsyncRead + AsyncWrite> RelaySession<S> {
    /// A session over an upgraded stream. `pending` holds any bytes that
    /// arrived after the upgrade response; `idle` bounds each read (None waits
    /// forever); `write_timeout` bounds each write.
    pub fn new(stream: S, pending: Vec<u8>, idle: Option<Duration>, write_timeout: Duration) -> Self {
        let (read, write) = tokio::io::split(stream);
        RelaySession {
            reader: Mutex::new(Reader {
                half: read,
                pending,
                close_received: false,
                partial: None,
                idle,
            }),
            writer: Mutex::new(write),
            close_sent: AtomicBool::new(false),
            write_timeout,
        }
    }

    /// Send one binary frame.
    pub async fn send_binary(&self, payload: &[u8]) -> Result<(), String> {
        self.write(frame::OPCODE_BINARY, payload).await
    }

    /// Send one text frame.
    pub async fn send_text(&self, text: &str) -> Result<(), String> {
        self.write(frame::OPCODE_TEXT, text.as_bytes()).await
    }

    /// Send a Pong. The reader already answers Pings; this exists for callers
    /// that manage control frames themselves.
    pub async fn send_pong(&self, payload: &[u8]) -> Result<(), String> {
        self.write(frame::OPCODE_PONG, payload).await
    }

    /// Start (or answer) the closing handshake. Sends at most one Close per
    /// session; later calls do nothing. `reason` is cut to fit a control frame.
    pub async fn send_close(&self, code: u16, reason: &str) -> Result<(), String> {
        if self.close_sent.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.write(frame::OPCODE_CLOSE, &close_payload(Some(code), reason)).await
    }

    /// Whether this side has sent a Close.
    pub fn close_sent(&self) -> bool {
        self.close_sent.load(Ordering::SeqCst)
    }

    /// The next data message (binary or text, reassembled) or the Close.
    /// Pings are answered and Pongs skipped along the way.
    pub async fn read_frame(&self) -> Result<Frame, String> {
        let mut guard = self.reader.lock().await;
        // A plain `&mut` so the fields can be borrowed separately below.
        let reader = &mut *guard;
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            match next_event(&mut reader.pending).map_err(|e| e.to_string())? {
                Some(Event::Pong(payload)) => {
                    // A Ping: answered unless a Close already arrived, and never
                    // echoed when it breaks the control-frame size limit.
                    if payload.len() <= frame::MAX_CONTROL_PAYLOAD && !reader.close_received {
                        self.write(frame::OPCODE_PONG, &payload).await?;
                    }
                }
                Some(Event::Frame(f)) if f.opcode == frame::OPCODE_PONG => {}
                Some(Event::Frame(f)) if f.opcode == frame::OPCODE_CLOSE => {
                    reader.close_received = true;
                    if !self.close_sent.swap(true, Ordering::SeqCst) {
                        // Echo the status code, as RFC 6455 §5.5.1 requires.
                        let (code, _) = close_code_and_reason(&f.payload);
                        let _ = self.write(frame::OPCODE_CLOSE, &close_payload(code, "")).await;
                    }
                    return Ok(f);
                }
                Some(Event::Frame(f)) => {
                    if let Some(message) = reader.assemble(f)? {
                        return Ok(message);
                    }
                }
                None => {
                    let read = reader.half.read(&mut chunk);
                    let n = match reader.idle {
                        Some(limit) => tokio::time::timeout(limit, read).await.map_err(|_| {
                            format!("no data from the relay for {}s", limit.as_secs())
                        })?,
                        None => read.await,
                    }
                    .map_err(|e| e.to_string())?;
                    if n == 0 {
                        return Err("the relay closed the connection without a WebSocket Close".into());
                    }
                    reader.pending.extend_from_slice(&chunk[..n]);
                }
            }
        }
    }

    async fn write(&self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let mut writer = self.writer.lock().await;
        tokio::time::timeout(self.write_timeout, write_frame_over(&mut *writer, opcode, payload))
            .await
            .map_err(|_| format!("sending to the relay stalled for {}s", self.write_timeout.as_secs()))?
    }
}

impl<S> Reader<S> {
    /// Feed one data or continuation frame; returns a whole message when one
    /// is complete.
    fn assemble(&mut self, f: Frame) -> Result<Option<Frame>, String> {
        match (f.opcode, self.partial.take()) {
            (frame::OPCODE_CONTINUATION, None) => {
                Err("the relay sent a continuation frame with no message to continue".into())
            }
            (frame::OPCODE_CONTINUATION, Some((opcode, mut payload))) => {
                if payload.len() + f.payload.len() > MAX_MESSAGE {
                    return Err(format!("a fragmented message exceeded {MAX_MESSAGE} bytes"));
                }
                payload.extend_from_slice(&f.payload);
                if f.fin {
                    Ok(Some(Frame { fin: true, opcode, payload }))
                } else {
                    self.partial = Some((opcode, payload));
                    Ok(None)
                }
            }
            (_, Some(_)) => Err("the relay started a new message inside a fragmented one".into()),
            (opcode, None) if !f.fin => {
                self.partial = Some((opcode, f.payload));
                Ok(None)
            }
            (_, None) => Ok(Some(f)),
        }
    }
}

/// A Close payload: the code (big-endian), then a reason cut to fit the
/// 125-byte control-frame limit on a character boundary.
pub fn close_payload(code: Option<u16>, reason: &str) -> Vec<u8> {
    let Some(code) = code else { return Vec::new() };
    let mut out = code.to_be_bytes().to_vec();
    let mut end = reason.len().min(frame::MAX_CONTROL_PAYLOAD - 2);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    out.extend_from_slice(&reason.as_bytes()[..end]);
    out
}

/// The status code and reason of a received Close frame's payload.
pub fn close_code_and_reason(payload: &[u8]) -> (Option<u16>, String) {
    if payload.len() < 2 {
        return (None, String::new());
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    // The reason is the peer's text and is printed to the user's terminal.
    (Some(code), crate::text::one_line(&String::from_utf8_lossy(&payload[2..])))
}
