//! The connection layer: `session` channels (RFC 4254).
//!
//! Payloads only — no framing, no I/O, no clock. The caller wraps these in
//! `packet`/`cipher` frames and feeds replies back into `Channel`.
//!
//! ⛔ Window accounting is enforced, not advisory. `on_data` refuses bytes
//! beyond the peer's window instead of clamping them: silently accepting
//! over-window data is how a stuck session looks healthy. `adjust` refuses
//! overflow for the same reason — a window that wrapped is a window that lies.
//!
//! ⛔ Exit mapping: `Status(n)` becomes process status `n`; `Signal` becomes
//! **255** (OpenSSH's convention for a remotely-signalled command). Both are
//! pinned by the Task 6 live proof (remote `exit 3` → 3, remote `kill -9`
//! → 255), not by assertion here.

use crate::ssh::types::{Reader, TypeError, put_string, put_u32};

pub const MSG_CHANNEL_OPEN: u8 = 90;
pub const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const MSG_CHANNEL_DATA: u8 = 94;
pub const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const MSG_CHANNEL_EOF: u8 = 96;
pub const MSG_CHANNEL_CLOSE: u8 = 97;
pub const MSG_CHANNEL_REQUEST: u8 = 98;
pub const MSG_CHANNEL_SUCCESS: u8 = 99;
pub const MSG_CHANNEL_FAILURE: u8 = 100;

pub const TYPE_SESSION: &str = "session";

/// What we advertise: 64 KiB windows, 32 KiB max packet. Both directions.
pub const INITIAL_WINDOW: u32 = 64 * 1024;
pub const MAX_PACKET: u32 = 32 * 1024;

/// Why bytes are not a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    Types(TypeError),
    /// A message outside 90–100, or a truncated one: not a channel message,
    /// never half-applied.
    UnexpectedMessage { byte: Option<u8> },
    /// The server refused the open. Carries the reason code AND the message
    /// — a code without the text is unactionable, text without the code is
    /// unmatchable.
    OpenFailed { reason: u32, message: String },
    /// Data arrived past the send window. Names how many bytes were left and
    /// how many arrived: the arithmetic is the finding.
    WindowExceeded { available: u32, arrived: u32 },
    /// An adjust would push the window past u32::MAX. Refused, never wrapped.
    WindowOverflow { window: u32, adjust: u32 },
    /// A single data payload larger than MAX_PACKET. The peer was told our
    /// maximum in the open; bigger is a violation, not a jumbo to accept.
    OversizePayload { bytes: usize },
    /// A message for a channel that is not open (or a second confirmation for
    /// one that already is): state confusion, surfaced, never absorbed.
    BadState { what: &'static str },
    /// `exit-signal` without a signal name: the one field that makes the
    /// message meaningful.
    SignalWithoutName,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Types(e) => write!(f, "{e}"),
            Self::UnexpectedMessage { byte } => write!(f, "not a channel message: {byte:?}"),
            Self::OpenFailed { reason, message } => {
                write!(f, "server refused channel open ({reason}): {message}")
            }
            Self::WindowExceeded { available, arrived } => {
                write!(f, "channel data over window: {arrived} bytes with {available} left")
            }
            Self::WindowOverflow { window, adjust } => {
                write!(f, "window adjust {adjust} overflows window {window}")
            }
            Self::OversizePayload { bytes } => write!(f, "channel payload of {bytes} bytes exceeds maximum"),
            Self::BadState { what } => write!(f, "channel message while {what}"),
            Self::SignalWithoutName => write!(f, "exit-signal with no signal name"),
        }
    }
}

impl std::error::Error for ChannelError {}

impl From<TypeError> for ChannelError {
    fn from(e: TypeError) -> Self {
        Self::Types(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Opening,
    Open,
    Closing,
    Closed,
}

/// How the remote command ended. `Status` carries the raw u32; `code()`
/// applies the E24 mapping (status passes through, signal is 255).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    Status(u32),
    Signal { name: String, core: bool, message: String },
}

impl Exit {
    pub fn code(&self) -> i32 {
        match self {
            Self::Status(n) => *n as i32,
            Self::Signal { .. } => 255,
        }
    }
}

/// One `session` channel. `local_id` is ours (we chose it); `remote_id` is
/// learned from the confirmation — sending data under the wrong id delivers
/// our bytes to somebody else's session, so every outbound builder reads it
/// from here and `Open` is the only state that has one.
pub struct Channel {
    state: State,
    local_id: u32,
    remote_id: Option<u32>,
    /// Bytes we may still send (peer's window, decremented on send).
    send_window: u32,
    send_max_packet: u32,
    /// Bytes the peer may still send (our window, decremented on receive,
    /// replenished by `take_received` draining to the caller).
    recv_window: u32,
    pending: Vec<u8>,
    eof: bool,
    exit: Option<Exit>,
}

impl Channel {
    pub fn new(local_id: u32) -> Self {
        Self {
            state: State::Opening,
            local_id,
            remote_id: None,
            send_window: 0,
            send_max_packet: 0,
            recv_window: INITIAL_WINDOW,
            pending: Vec::new(),
            eof: false,
            exit: None,
        }
    }

    /// `SSH_MSG_CHANNEL_OPEN` for a `session` (RFC 4254 §5.1).
    pub fn open_session(&self) -> Vec<u8> {
        let mut out = vec![MSG_CHANNEL_OPEN];
        put_string(&mut out, TYPE_SESSION.as_bytes());
        put_u32(&mut out, self.local_id);
        put_u32(&mut out, INITIAL_WINDOW);
        put_u32(&mut out, MAX_PACKET);
        out
    }

    /// Fold a server message into the channel. Returns outbound data the
    /// caller should send (currently only window replenishment never sends —
    /// see `take_received`; the Vec exists so future adjustments have a path
    /// without reshaping every call site).
    pub fn on_message(&mut self, payload: &[u8]) -> Result<ChannelEvent, ChannelError> {
        let mut r = Reader::new(payload);
        match r.u8()? {
            MSG_CHANNEL_OPEN_CONFIRMATION => {
                if self.state != State::Opening {
                    return Err(ChannelError::BadState { what: "already confirmed" });
                }
                let _their_id = r.u32()?;
                let our_id = r.u32()?;
                if our_id != self.local_id {
                    return Err(ChannelError::BadState { what: "confirmed for another id" });
                }
                self.remote_id = Some(r.u32()?);
                self.send_window = r.u32()?;
                self.send_max_packet = r.u32()?;
                self.state = State::Open;
                Ok(ChannelEvent::Opened)
            }
            MSG_CHANNEL_OPEN_FAILURE => {
                let _their_id = r.u32()?;
                let reason = r.u32()?;
                let message = String::from_utf8_lossy(r.string()?).into_owned();
                self.state = State::Closed;
                Err(ChannelError::OpenFailed { reason, message })
            }
            MSG_CHANNEL_WINDOW_ADJUST => {
                let _their_id = r.u32()?;
                let adjust = r.u32()?;
                if self.state != State::Open {
                    return Err(ChannelError::BadState { what: "not open" });
                }
                self.send_window = self
                    .send_window
                    .checked_add(adjust)
                    .ok_or(ChannelError::WindowOverflow { window: self.send_window, adjust })?;
                Ok(ChannelEvent::WindowAdjusted { by: adjust })
            }
            MSG_CHANNEL_DATA => {
                let _their_id = r.u32()?;
                let data = r.string()?;
                self.inbound(data)?;
                Ok(ChannelEvent::Data)
            }
            MSG_CHANNEL_EXTENDED_DATA => {
                let _their_id = r.u32()?;
                let kind = r.u32()?;
                let data = r.string()?;
                self.inbound(data)?;
                Ok(ChannelEvent::ExtendedData { kind })
            }
            MSG_CHANNEL_EOF => {
                self.eof = true;
                Ok(ChannelEvent::Eof)
            }
            MSG_CHANNEL_CLOSE => {
                self.state = State::Closed;
                Ok(ChannelEvent::Closed)
            }
            MSG_CHANNEL_REQUEST => return self.on_request(&mut r),
            MSG_CHANNEL_SUCCESS => Ok(ChannelEvent::RequestOk),
            MSG_CHANNEL_FAILURE => Ok(ChannelEvent::RequestFailed),
            other => Err(ChannelError::UnexpectedMessage { byte: Some(other) }),
        }
    }

    fn inbound(&mut self, data: &[u8]) -> Result<(), ChannelError> {
        if self.state != State::Open {
            return Err(ChannelError::BadState { what: "not open" });
        }
        if data.len() > MAX_PACKET as usize {
            return Err(ChannelError::OversizePayload { bytes: data.len() });
        }
        if data.len() as u32 > self.recv_window {
            return Err(ChannelError::WindowExceeded {
                available: self.recv_window,
                arrived: data.len() as u32,
            });
        }
        self.recv_window -= data.len() as u32;
        self.pending.extend_from_slice(data);
        Ok(())
    }

    fn on_request(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent, ChannelError> {
        let _their_id = r.u32()?;
        let kind = std::str::from_utf8(r.string()?)
            .map_err(|_| ChannelError::UnexpectedMessage { byte: Some(MSG_CHANNEL_REQUEST) })?
            .to_string();
        let _want_reply = r.boolean()?;
        match kind.as_str() {
            "exit-status" => {
                let status = r.u32()?;
                self.exit = Some(Exit::Status(status));
                Ok(ChannelEvent::Exit)
            }
            "exit-signal" => {
                let name = std::str::from_utf8(r.string()?)
                    .map_err(|_| ChannelError::SignalWithoutName)?
                    .to_string();
                if name.is_empty() {
                    return Err(ChannelError::SignalWithoutName);
                }
                let core = r.boolean()?;
                let message = String::from_utf8_lossy(r.string()?).into_owned();
                let _lang = r.string()?;
                self.exit = Some(Exit::Signal { name, core, message });
                Ok(ChannelEvent::Exit)
            }
            other => Ok(ChannelEvent::UnhandledRequest { kind: other.to_string() }),
        }
    }

    /// Bytes received so far. Draining replenishes the window 1:1 — the
    /// caller must call this to keep the session flowing, which is why the
    /// window math lives here and not in a comment.
    pub fn take_received(&mut self) -> Vec<u8> {
        let out = std::mem::take(&mut self.pending);
        self.recv_window = self.recv_window.saturating_add(out.len() as u32);
        // Saturating is honest here, not silent: the window can only refill
        // to what was consumed, and consumption never exceeds INITIAL_WINDOW
        // without an adjust the peer never sent. Overflow past u32::MAX would
        // need 4 GiB in flight; saturation keeps a giant session alive rather
        // than killing it on arithmetic.
        out
    }

    /// Reserve `n` bytes of send window, returning the length to actually
    /// emit (window-limited AND max-packet-limited). Zero means "wait for an
    /// adjust" — the caller blocks, never over-sends.
    pub fn claim_send(&mut self, n: usize) -> usize {
        if self.state != State::Open {
            return 0;
        }
        (n as u32).min(self.send_window).min(self.send_max_packet) as usize
    }

    /// Record bytes actually sent (framed by the caller).
    pub fn sent(&mut self, n: usize) {
        self.send_window = self.send_window.saturating_sub(n as u32);
    }

    pub fn exit(&self) -> Option<&Exit> {
        self.exit.as_ref()
    }

    pub fn eof(&self) -> bool {
        self.eof
    }

    pub fn is_open(&self) -> bool {
        self.state == State::Open
    }

    /// `SSH_MSG_CHANNEL_DATA` under the remote id. Empty while closed —
    /// framing a payload for a dead channel delivers it nowhere.
    pub fn data(&self, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![MSG_CHANNEL_DATA];
        put_u32(&mut out, self.remote_id.unwrap_or(u32::MAX));
        put_string(&mut out, bytes);
        out
    }

    /// `SSH_MSG_CHANNEL_CLOSE`. Idempotent to build; the state moves when the
    /// peer's close arrives (or when the caller decides to stop reading).
    pub fn close(&self) -> Vec<u8> {
        let mut out = vec![MSG_CHANNEL_CLOSE];
        put_u32(&mut out, self.remote_id.unwrap_or(u32::MAX));
        out
    }

    /// A `CHANNEL_REQUEST` envelope around one request body.
    fn request(&self, kind: &str, want_reply: bool, body: &[u8]) -> Vec<u8> {
        let mut out = vec![MSG_CHANNEL_REQUEST];
        put_u32(&mut out, self.remote_id.unwrap_or(u32::MAX));
        put_string(&mut out, kind.as_bytes());
        out.push(u8::from(want_reply));
        out.extend_from_slice(body);
        out
    }

    /// `pty-req` (RFC 4254 §6.2): TERM, size, pixels, and the encoded modes.
    /// want-reply is TRUE — a shell without a pty the server silently denied
    /// is a broken terminal wearing a working one's clothes.
    pub fn pty_request(
        &self,
        term: &str,
        cols: u32,
        rows: u32,
        pix_w: u32,
        pix_h: u32,
        modes: &[(u8, u32)],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        put_string(&mut body, term.as_bytes());
        put_u32(&mut body, cols);
        put_u32(&mut body, rows);
        put_u32(&mut body, pix_w);
        put_u32(&mut body, pix_h);
        body.extend_from_slice(&encode_pty_modes(modes));
        self.request("pty-req", true, &body)
    }

    /// `env` (RFC 4254 §6.4): one `NAME=value` for the remote command.
    pub fn env_request(&self, name: &str, value: &str) -> Vec<u8> {
        let mut body = Vec::new();
        put_string(&mut body, name.as_bytes());
        put_string(&mut body, value.as_bytes());
        self.request("env", true, &body)
    }

    /// `exec` (RFC 4254 §6.5): run one command, then the channel carries its
    /// stdio until `exit-status`.
    pub fn exec_request(&self, command: &str) -> Vec<u8> {
        let mut body = Vec::new();
        put_string(&mut body, command.as_bytes());
        self.request("exec", true, &body)
    }

    /// `shell` (RFC 4254 §6.5): the login shell, interactive or piped.
    pub fn shell_request(&self) -> Vec<u8> {
        self.request("shell", true, &[])
    }

    /// `window-change` (RFC 4254 §6.7.2): the new size. want-reply FALSE —
    /// the server applies it or ignores it; waiting for an answer would stall
    /// every resize on a reply that never comes.
    pub fn window_change(&self, cols: u32, rows: u32, pix_w: u32, pix_h: u32) -> Vec<u8> {
        let mut body = Vec::new();
        put_u32(&mut body, cols);
        put_u32(&mut body, rows);
        put_u32(&mut body, pix_w);
        put_u32(&mut body, pix_h);
        self.request("window-change", false, &body)
    }
}

/// Encode pty modes (RFC 4254 §8): `byte opcode || uint32 value`, ended by
/// TTY_OP_END (0). Every opcode the caller passes lands on the wire verbatim
/// — this function validates nothing, because the caller's discipline owns
/// the semantics and a mode this layer refused would be a policy this layer
/// does not own.
pub fn encode_pty_modes(modes: &[(u8, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(modes.len() * 5 + 1);
    for (op, val) in modes {
        out.push(*op);
        put_u32(&mut out, *val);
    }
    out.push(0);
    out
}

/// What one inbound message meant. Data lands in `take_received`; the event
/// only says which kind arrived, so a caller that ignores the queue still
/// sees the shape of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelEvent {
    Opened,
    WindowAdjusted { by: u32 },
    Data,
    ExtendedData { kind: u32 },
    Eof,
    Closed,
    Exit,
    RequestOk,
    RequestFailed,
    UnhandledRequest { kind: String },
}
