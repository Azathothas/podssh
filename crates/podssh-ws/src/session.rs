//! An open WebSocket session, to the relay unless made otherwise, usable
//! from two tasks at once. It speaks as a client unless made a server's
//! (T-368), and names the other end in its errors as the relay unless named.
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

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::client::Event;
use crate::error::SessionError;
use crate::frame::{self, Frame};
use crate::wire::{next_event_from, write_frame_as};

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
    /// When the last frame of any kind came (T-307): a notice of the far
    /// end's silence reads it. tokio's clock, which a test can pause.
    last_heard: std::sync::Mutex<tokio::time::Instant>,
    /// The payload of each Pong with when it came, the last [`PONGS_KEPT`],
    /// for `podssh ping`, which matches each Pong to its Ping (T-053); and a
    /// permit for each Pong, for the one who waits.
    pong_log: std::sync::Mutex<std::collections::VecDeque<(Vec<u8>, std::time::Instant)>>,
    pong_seen: tokio::sync::Notify,
    /// Bound on one write.
    write_timeout: Duration,
    /// The largest message that [`RelaySession::send_binary`] sends, when
    /// one is set: a larger payload goes as several messages (T-264).
    max_message: Option<usize>,
    /// Whether [`RelaySession::watch_liveness`] sends Pings.
    pings: bool,
    /// The cap on a received frame: the forward cap, or the relay's own,
    /// wider one (T-342, [`frame::receive_cap`]).
    receive_cap: AtomicUsize,
    /// The address of the TCP connection that carries the session, when the
    /// stream knows it: the relay's, or the proxy's (T-344).
    peer: Option<std::net::SocketAddr>,
    /// The side that this end speaks: a client masks each frame and takes
    /// the server's unmasked, a server the reverse (RFC 6455 section 5.1).
    role: frame::Role,
    /// The other end, in the words of an error: `the relay`, unless named.
    peer_name: &'static str,
}

/// The Pongs that [`RelaySession::take_pongs`] keeps for the one who reads.
pub const PONGS_KEPT: usize = 64;

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
            last_heard: std::sync::Mutex::new(tokio::time::Instant::now()),
            pong_log: std::sync::Mutex::new(std::collections::VecDeque::new()),
            pong_seen: tokio::sync::Notify::new(),
            write_timeout,
            max_message: None,
            pings: true,
            receive_cap: AtomicUsize::new(frame::FORWARD_MAX_FRAME),
            peer: None,
            role: frame::Role::Client,
            peer_name: "the relay",
        }
    }

    /// The address of the TCP connection that carries the session: the
    /// relay's when no proxy carried it, which the cache of addresses keeps
    /// once the upgrade passed (T-344); none for a stream of another kind.
    pub fn peer(&self) -> Option<std::net::SocketAddr> {
        self.peer
    }

    /// Speak as the server: each frame written unmasked, and only masked
    /// ones taken, as from a client of `podssh pipe ws-listen:` (T-368).
    pub fn as_server(mut self) -> Self {
        self.role = frame::Role::Server;
        self
    }

    /// Name the other end in the words of an error, such as `the server`.
    pub fn naming(mut self, peer: &'static str) -> Self {
        self.peer_name = peer;
        self
    }

    /// Send no binary message over `max` bytes: a larger payload goes as
    /// several messages, never as fragments of one, as a peer that cuts each
    /// message at a size of its own needs (the origin of `cloudflared`,
    /// T-264).
    pub fn with_max_message(mut self, max: usize) -> Self {
        self.max_message = Some(max.max(1));
        self
    }

    /// Take in frames up to `cap` bytes, from the relay's `/relays.json`
    /// through [`frame::receive_cap`] (T-342).
    pub fn set_receive_cap(&self, cap: usize) {
        self.receive_cap.store(cap.clamp(frame::FORWARD_MAX_FRAME, frame::MAX_RECEIVE_CAP), Ordering::SeqCst);
    }

    /// Send no Ping: [`RelaySession::watch_liveness`] then waits for ever,
    /// and the idle bound of each read finds a dead link. For a peer that
    /// answers a Ping outside the lock of its other writes (T-264).
    pub fn without_pings(mut self) -> Self {
        self.pings = false;
        self
    }

    /// The Pongs that came since the last call, each with its payload and
    /// when it came; [`RelaySession::read_frame`] must be running.
    pub fn take_pongs(&self) -> Vec<(Vec<u8>, std::time::Instant)> {
        self.pong_log.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect()
    }

    /// Until a Pong comes, or one came since the last wait.
    pub async fn pong_arrived(&self) {
        self.pong_seen.notified().await;
    }

    /// Send one binary frame; several messages when the payload is over the
    /// bound of [`RelaySession::with_max_message`].
    pub async fn send_binary(&self, payload: &[u8]) -> Result<(), SessionError> {
        self.no_data_after_close()?;
        match self.max_message {
            Some(max) if payload.len() > max => {
                for part in payload.chunks(max) {
                    self.write(frame::OPCODE_BINARY, part).await?;
                }
                Ok(())
            }
            _ => self.write(frame::OPCODE_BINARY, payload).await,
        }
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

    /// When the last frame of any kind came, or the session began.
    pub fn last_heard(&self) -> tokio::time::Instant {
        *self.last_heard.lock().unwrap_or_else(|e| e.into_inner())
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
        if !self.pings {
            return std::future::pending().await;
        }
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
                    "nothing from {} for {} s, pings unanswered: the connection is dead",
                    self.peer_name,
                    every.as_secs() * u64::from(allowed)
                ));
            }
            sent += 1;
            if let Err(e) = self.send_ping(&sent.to_be_bytes()).await {
                return e.context(&format!("sending a ping to {} failed", self.peer_name));
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
            let cap = self.receive_cap.load(Ordering::SeqCst);
            let event = match next_event_from(&mut reader.pending, self.role.peer(), cap) {
                Ok(event) => event,
                Err(e) => return Err(self.fail(1002, SessionError::Protocol(e.to_string())).await),
            };
            if event.is_some() {
                *self.last_heard.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
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
                    let mut log = self.pong_log.lock().unwrap_or_else(|e| e.into_inner());
                    if log.len() == PONGS_KEPT {
                        log.pop_front();
                    }
                    log.push_back((f.payload, std::time::Instant::now()));
                    drop(log);
                    self.pong_seen.notify_one();
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
                Some(Event::Frame(f)) => match reader.assemble(f, self.peer_name) {
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
                            SessionError::Idle(format!("no data from {} for {}s", self.peer_name, limit.as_secs()))
                        })?,
                        None => read.await,
                    }
                    .map_err(|e| SessionError::io(&e))?;
                    if n == 0 {
                        return Err(SessionError::ClosedWithoutClose(format!(
                            "{} closed the connection without a WebSocket Close",
                            self.peer_name
                        )));
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
        let written = write_frame_as(&mut *writer, self.role, opcode, payload);
        let (peer, limit) = (self.peer_name, self.write_timeout.as_secs());
        tokio::time::timeout(self.write_timeout, written)
            .await
            .map_err(|_| SessionError::WriteStalled(format!("sending to {peer} stalled for {limit}s")))?
    }
}

impl RelaySession<RelayStream> {
    /// A session over the relay's TLS stream, as [`crate::connect`] opens it,
    /// which keeps the address of its TCP connection ([`RelaySession::peer`]).
    pub fn over_tls(stream: RelayStream, pending: Vec<u8>, idle: Option<Duration>) -> Self {
        let peer = stream.get_ref().0.peer_addr().ok();
        let mut session = Self::new(stream, pending, idle, crate::client::WRITE_TIMEOUT);
        session.peer = peer;
        session
    }
}

impl<S> Reader<S> {
    /// Feed one data or continuation frame; returns a whole message when one
    /// is complete. An error carries the close code that it fails the
    /// connection with: 1002 for a protocol error, 1009 for a message too big.
    fn assemble(&mut self, f: Frame, peer: &str) -> Result<Option<Frame>, (u16, String)> {
        match (f.opcode, self.partial.take()) {
            (frame::OPCODE_CONTINUATION, None) => {
                Err((1002, format!("{peer} sent a continuation frame with no message to continue")))
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
            (_, Some(_)) => Err((1002, format!("{peer} started a new message inside a fragmented one"))),
            (opcode, None) if !f.fin => {
                self.partial = Some((opcode, f.payload));
                Ok(None)
            }
            (_, None) => Ok(Some(f)),
        }
    }
}

pub use crate::close::{close_code_and_reason, close_payload, forward_close, ForwardClose};
