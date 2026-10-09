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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::client::{next_event, write_frame_over, Event};
use crate::error::SessionError;
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
    /// Pongs received, and frames of any kind received, for
    /// [`RelaySession::watch_liveness`].
    pongs: AtomicU64,
    heard: AtomicU64,
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
            reader: Mutex::new(Reader { half: read, pending, close_received: false, partial: None, idle }),
            writer: Mutex::new(write),
            close_sent: AtomicBool::new(false),
            pongs: AtomicU64::new(0),
            heard: AtomicU64::new(0),
            write_timeout,
        }
    }

    /// Send one binary frame.
    pub async fn send_binary(&self, payload: &[u8]) -> Result<(), SessionError> {
        self.no_data_after_close()?;
        self.write(frame::OPCODE_BINARY, payload).await
    }

    /// Send one text frame.
    pub async fn send_text(&self, text: &str) -> Result<(), SessionError> {
        self.no_data_after_close()?;
        self.write(frame::OPCODE_TEXT, text.as_bytes()).await
    }

    /// RFC 6455 section 5.5.1: no data frame after this side's Close.
    fn no_data_after_close(&self) -> Result<(), SessionError> {
        if self.close_sent() {
            return Err(SessionError::Io {
                kind: std::io::ErrorKind::BrokenPipe,
                text: "this side sent its Close; no data may follow".into(),
            });
        }
        Ok(())
    }

    /// Send a Pong. The reader already answers Pings; this exists for callers
    /// that manage control frames themselves.
    pub async fn send_pong(&self, payload: &[u8]) -> Result<(), SessionError> {
        self.write(frame::OPCODE_PONG, payload).await
    }

    /// Start (or answer) the closing handshake. Sends at most one Close per
    /// session; later calls do nothing. `reason` is cut to fit a control frame.
    pub async fn send_close(&self, code: u16, reason: &str) -> Result<(), SessionError> {
        if self.close_sent.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.write(frame::OPCODE_CLOSE, &close_payload(Some(code), reason)).await
    }

    /// Whether this side has sent a Close.
    pub fn close_sent(&self) -> bool {
        self.close_sent.load(Ordering::SeqCst)
    }

    /// Send a Ping; its Pong is counted by [`RelaySession::read_frame`], which
    /// must be running for liveness to be seen.
    pub async fn send_ping(&self, payload: &[u8]) -> Result<(), SessionError> {
        self.write(frame::OPCODE_PING, payload).await
    }

    /// How many Pongs have arrived.
    pub fn pongs_received(&self) -> u64 {
        self.pongs.load(Ordering::SeqCst)
    }

    /// Frames of any kind received so far.
    pub fn frames_received(&self) -> u64 {
        self.heard.load(Ordering::SeqCst)
    }

    /// Ping the relay every `every`; return (with the reason) once `allowed`
    /// intervals in a row pass with nothing at all from the relay. Any frame
    /// counts, not only a Pong: a Ping can wait behind a large upload on a slow
    /// link, but a healthy relay always sends something (data, a Pong, or its
    /// own keepalive every 25 s). A link that dies silently is found in about
    /// `every * allowed` instead of at the idle read limit. Enforced only after
    /// the relay has answered a Ping, so a relay that never answers Pings is
    /// not mistaken for a dead one (the idle read limit still covers it). Runs
    /// until it returns; the caller races it with its pumps, and
    /// [`RelaySession::read_frame`] must be running for anything to be heard.
    pub async fn watch_liveness(&self, every: Duration, allowed: u32) -> SessionError {
        let mut sent: u64 = 0;
        let mut heard = self.frames_received();
        let mut missed: u32 = 0;
        loop {
            tokio::time::sleep(every).await;
            let now = self.frames_received();
            if now > heard {
                heard = now;
                missed = 0;
            } else if sent > 0 {
                missed += 1;
            }
            if self.pongs_received() > 0 && missed >= allowed {
                return SessionError::Dead(format!(
                    "nothing from the relay for {} s, pings unanswered: the connection is dead",
                    every.as_secs() * u64::from(allowed)
                ));
            }
            sent += 1;
            if let Err(e) = self.send_ping(&sent.to_be_bytes()).await {
                return e.context("sending a ping to the relay failed");
            }
        }
    }

    /// The next data message (binary or text, reassembled) or the Close.
    /// Pings are answered and Pongs skipped along the way.
    pub async fn read_frame(&self) -> Result<Frame, SessionError> {
        let mut guard = self.reader.lock().await;
        // A plain `&mut` so the fields can be borrowed separately below.
        let reader = &mut *guard;
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            let event = match next_event(&mut reader.pending) {
                Ok(event) => event,
                Err(e) => return Err(self.fail(1002, SessionError::Protocol(e.to_string())).await),
            };
            if event.is_some() {
                self.heard.fetch_add(1, Ordering::SeqCst);
            }
            match event {
                Some(Event::Pong(payload)) => {
                    // A Ping: answered unless a Close already arrived, and never
                    // echoed when it breaks the control-frame size limit.
                    if payload.len() <= frame::MAX_CONTROL_PAYLOAD && !reader.close_received {
                        self.write(frame::OPCODE_PONG, &payload).await?;
                    }
                }
                Some(Event::Frame(f)) if f.opcode == frame::OPCODE_PONG => {
                    self.pongs.fetch_add(1, Ordering::SeqCst);
                }
                Some(Event::Frame(f)) if f.opcode == frame::OPCODE_CLOSE => {
                    reader.close_received = true;
                    if !self.close_sent.swap(true, Ordering::SeqCst) {
                        // Echo the status code, as RFC 6455 §5.5.1 requires.
                        let (code, _) = close_code_and_reason(&f.payload);
                        let _ = self.write(frame::OPCODE_CLOSE, &close_payload(code, "")).await;
                    }
                    return Ok(f);
                }
                Some(Event::Frame(f)) => match reader.assemble(f) {
                    Ok(Some(message)) => return Ok(message),
                    Ok(None) => {}
                    Err((code, why)) => {
                        let error =
                            if code == 1009 { SessionError::TooLarge(why) } else { SessionError::Protocol(why) };
                        return Err(self.fail(code, error).await);
                    }
                },
                None => {
                    let read = reader.half.read(&mut chunk);
                    let n = match reader.idle {
                        Some(limit) => tokio::time::timeout(limit, read).await.map_err(|_| {
                            SessionError::Idle(format!("no data from the relay for {}s", limit.as_secs()))
                        })?,
                        None => read.await,
                    }
                    .map_err(|e| SessionError::io(&e))?;
                    if n == 0 {
                        return Err(SessionError::ClosedWithoutClose(
                            "the relay closed the connection without a WebSocket Close".into(),
                        ));
                    }
                    reader.pending.extend_from_slice(&chunk[..n]);
                }
            }
        }
    }

    /// Fail the connection after a frame or a message that RFC 6455 forbids:
    /// a Close with `code` goes first (section 7.1.7), then the error is
    /// returned. A broken socket or an end of stream sends nothing: there is
    /// no peer left to tell.
    async fn fail(&self, code: u16, error: SessionError) -> SessionError {
        let _ = self.send_close(code, "").await;
        error
    }

    async fn write(&self, opcode: u8, payload: &[u8]) -> Result<(), SessionError> {
        let mut writer = self.writer.lock().await;
        tokio::time::timeout(self.write_timeout, write_frame_over(&mut *writer, opcode, payload)).await.map_err(
            |_| {
                SessionError::WriteStalled(format!(
                    "sending to the relay stalled for {}s",
                    self.write_timeout.as_secs()
                ))
            },
        )?
    }
}

impl<S> Reader<S> {
    /// Feed one data or continuation frame; returns a whole message when one
    /// is complete. An error carries the close code that it fails the
    /// connection with: 1002 for a protocol error, 1009 for a message too big.
    fn assemble(&mut self, f: Frame) -> Result<Option<Frame>, (u16, String)> {
        match (f.opcode, self.partial.take()) {
            (frame::OPCODE_CONTINUATION, None) => {
                Err((1002, "the relay sent a continuation frame with no message to continue".into()))
            }
            (frame::OPCODE_CONTINUATION, Some((opcode, mut payload))) => {
                if payload.len() + f.payload.len() > MAX_MESSAGE {
                    return Err((1009, format!("a fragmented message exceeded {MAX_MESSAGE} bytes")));
                }
                payload.extend_from_slice(&f.payload);
                if f.fin {
                    Ok(Some(Frame { fin: true, opcode, payload }))
                } else {
                    self.partial = Some((opcode, payload));
                    Ok(None)
                }
            }
            (_, Some(_)) => Err((1002, "the relay started a new message inside a fragmented one".into())),
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

/// The part of a forward session that a Close of the relay names, by its
/// code and reason (the relay's own words; `docs/relay.md`, "Errors and
/// close codes"). `podssh ssh` and `podssh proxy` both use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardClose {
    /// 1000: the target or the client ended the session.
    Normal,
    /// A limit of the relay: 1001 (idle, session time) or 1009 (bytes, frame).
    Limit,
    /// The relay's connection to the target failed or broke.
    Target,
    /// The connection between podssh and the relay broke; also no Close.
    Client,
    /// A code or a reason that the relay's table does not list.
    Unknown,
}

/// Classify a Close of the forward path; `None` is a connection that ended
/// with no Close.
pub fn forward_close(code: Option<u16>, reason: &str) -> ForwardClose {
    const TARGET: [&str; 4] =
        ["connect failed", "target closed before sending anything", "wrong target banner", "write failed"];
    match code {
        None => ForwardClose::Client,
        Some(1000) => ForwardClose::Normal,
        Some(1001 | 1009) => ForwardClose::Limit,
        Some(1011) if TARGET.iter().any(|t| reason.starts_with(t)) => ForwardClose::Target,
        Some(1011) if reason.starts_with("client send failed") || reason.starts_with("client error") => {
            ForwardClose::Client
        }
        Some(1013) if reason.starts_with("target write backlog") => ForwardClose::Target,
        Some(1013) if reason.starts_with("client receive backlog") => ForwardClose::Client,
        Some(_) => ForwardClose::Unknown,
    }
}

impl ForwardClose {
    /// What broke, in words: `target` is the `host:port` that the relay dials.
    pub fn what(self, target: &str) -> String {
        match self {
            ForwardClose::Normal => format!("{target} ended the connection"),
            ForwardClose::Limit => "the relay ended the session at one of its limits".into(),
            ForwardClose::Target => format!("the relay lost its connection to {target}"),
            ForwardClose::Client => "the connection between podssh and the relay broke".into(),
            ForwardClose::Unknown => "the relay closed the session".into(),
        }
    }

    /// What may help, when something may. The limits are the relay's
    /// (`/relays.json`, measured 2026-10-08): 180 s idle, 64 MiB, 12 h.
    pub fn remedy(self, reason: &str) -> Option<&'static str> {
        match self {
            ForwardClose::Target => Some("another relay host may reach it: --relay-host HOST"),
            ForwardClose::Client => Some("podssh doctor checks the way to the relay"),
            ForwardClose::Limit if reason.contains("idle") => {
                Some("the relay closes a session after 180 s with no traffic; set ServerAliveInterval below 180")
            }
            ForwardClose::Limit if reason.contains("byte cap") => {
                Some("a session carries 64 MiB at most through the relay; use a new session for more")
            }
            ForwardClose::Limit if reason.contains("time cap") => {
                Some("a session lasts 12 h at most through the relay; connect again")
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod forward_close_tests {
    use super::*;

    /// One case for each row of the relay's table, and an unknown code.
    #[test]
    fn forward_close_names_the_hop_for_each_row() {
        let cases = [
            (Some(1000), "target closed", ForwardClose::Normal),
            (Some(1001), "idle timeout", ForwardClose::Limit),
            (Some(1001), "session time cap", ForwardClose::Limit),
            (Some(1009), "session byte cap", ForwardClose::Limit),
            (Some(1009), "frame larger than 262144 bytes", ForwardClose::Limit),
            (Some(1011), "connect failed: refused", ForwardClose::Target),
            (Some(1011), "target closed before sending anything", ForwardClose::Target),
            (Some(1011), "wrong target banner SSH-1.5", ForwardClose::Target),
            (Some(1011), "write failed: Network connection lost.", ForwardClose::Target),
            (Some(1011), "client send failed: reset", ForwardClose::Client),
            (Some(1011), "client error", ForwardClose::Client),
            (Some(1013), "target write backlog", ForwardClose::Target),
            (Some(1013), "client receive backlog", ForwardClose::Client),
            (None, "", ForwardClose::Client),
            (Some(4321), "something new", ForwardClose::Unknown),
            (Some(1011), "a reason the table does not list", ForwardClose::Unknown),
        ];
        for (code, reason, want) in cases {
            assert_eq!(forward_close(code, reason), want, "{code:?} {reason}");
        }
        assert_eq!(ForwardClose::Target.what("railway.new:22"), "the relay lost its connection to railway.new:22");
        assert!(ForwardClose::Limit.remedy("idle timeout").unwrap().contains("ServerAliveInterval"));
        assert!(ForwardClose::Unknown.remedy("x").is_none());
    }
}
