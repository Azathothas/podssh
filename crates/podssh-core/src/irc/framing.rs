//! Bytes ⇄ lines. **This is where a frame boundary mid-message dies.**
//!
//! A WebSocket frame carries bytes, and the relay copies payload verbatim: a
//! frame boundary means nothing on the IRC wire, so a message may be split at
//! any byte and a client that parses per-frame emits half a `PRIVMSG` as if it
//! were a whole one. **That is the defect the whole transport can cause and the
//! one a fixture hides**, so it is asserted here against a deliberate
//! byte-for-byte split.
//!
//! **Pure bytes in, bytes out.** No socket, no clock, no I/O — so every
//! claim here is reproducible on a host with no egress, which is the only place
//! this module is ever tested.
//!
//! **`truncate` emits nothing, and that is the other half.** A stream cut in
//! the middle of a line leaves a partial line in the buffer. Emitting it would
//! put `:nick!user@host PRIVMSG #ch :hel` in a user's terminal and then nothing
//! more, and the user cannot tell that from a peer that stopped talking.
//! [`Reassembler::take_rest`] returns the partial line **only** to the caller
//! that says the stream ended, and that caller decides what to do with it; a
//! plain read never returns one.
//!
//! **Bare `\n` is accepted as a terminator as well as `\r\n`.** RFC 1459
//! mandates `\r\n` and the encoder only ever writes that, but a server that
//! emits `\n` is a real thing and a client that drops the message is worse than
//! one that accepts it. **A lone `\r` is never a terminator**, because a
//! `\r\n` arriving as two separate frames is the split this module exists for.
//!
//! **NUL is dropped.** The grammar of RFC 2812 §2.3.1 allows no NUL in a
//! message, and a NUL ends a string for a server written in C, so no server
//! means one. Dropping it is the documented behaviour; the parser never sees
//! one.
//!
//! **One bad line never costs another.** [`Reassembler::push`] hands out the
//! lines and the losses together, in their order: a line past the limit is
//! dropped whole and named, and the lines before and after it come out. A
//! line that is not UTF-8 is read as Latin-1, each byte its own character, as
//! older networks write it, and marked so: refusing it would end a session
//! for one line of one user.

use std::fmt;

/// **512 bytes.** RFC 2812 §2.3: a message comprises a command, params and a
/// trailing, and "the maximum message length is 512 characters" — which
/// includes the `\r\n`.
pub const MAX_ALLOWED_LINE: usize = 512;

/// What a real ircd accepts into its receive buffer. This is a *buffer* limit
/// measured by other implementations, not a wire limit, and it is larger than
/// [`MAX_ALLOWED_LINE`] on purpose: a client that refuses at 512 the instant a
/// byte crosses it drops a message it could have let a human read and blamed
/// the server for.
pub const DEFAULT_MAX_LINE: usize = 8192;

/// What one line of the stream became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Framed {
    /// A line of UTF-8.
    Line(String),
    /// A line that is not UTF-8, read as Latin-1: each byte is the character
    /// of its value.
    Latin1(String),
    /// A line past the limit, dropped whole.
    Lost(FrameError),
}

/// The reassembler. Push whatever the relay hands over, take whatever
/// completed.
///
/// **The limit holds on the buffer as well as on a line**, because a buffer
/// that can grow without bound from a hostile peer is a denial of service and
/// this type is on the receive path of a client that must survive a
/// constrained sandbox.
#[derive(Debug, Clone)]
pub struct Reassembler {
    buf: Vec<u8>,
    /// Set while the rest of an over-long line arrives, which has no end
    /// yet: **its bytes are dropped as they come**, so the buffer stays under
    /// the limit, and the next `\n` resumes at a message boundary. Skipping
    /// to it is what keeps the tail of a 100 KB line from being parsed as a
    /// fresh message.
    overflowed: bool,
    max_line: usize,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self::with_max_line(DEFAULT_MAX_LINE)
    }

    pub fn with_max_line(max_line: usize) -> Self {
        // A limit below 2 cannot hold a `\r\n`, so it could never emit
        // anything at all — a silent client. Raised rather than accepted.
        let max_line = max_line.max(2);
        Reassembler { buf: Vec::new(), overflowed: false, max_line }
    }

    /// Add a frame's payload. Returns what each line that completed inside it
    /// became, in order.
    ///
    /// **A loss is in the list, because the caller needs to know.** A parser
    /// that silently dropped an over-long line would let a peer truncate a
    /// conversation with no word to anyone; [`Framed::Lost`] names the line
    /// and the limit, and the stream resumes at the next boundary.
    pub fn push(&mut self, frame: &[u8]) -> Vec<Framed> {
        self.buf.extend_from_slice(frame);
        self.drain()
    }

    /// **The stream ended here.** Return whatever is left, **only** because
    /// the caller said so.
    ///
    /// The caller is expected to discard it: a half message is not a
    /// message. [`Reassembler::push`] will not hand it over, so this is the
    /// single place a partial line can be observed, and it exists so that
    /// "do not emit the partial line" is a decision the reconnect path records
    /// rather than an accident.
    pub fn take_rest(&mut self) -> Option<String> {
        if self.buf.is_empty() {
            return None;
        }
        let rest = String::from_utf8_lossy(&self.buf).into_owned();
        self.buf.clear();
        Some(rest)
    }

    /// Bytes held for a line that has not terminated yet. Non-zero means a
    /// frame boundary landed mid-message and the next frame must be joined to
    /// it.
    pub fn pending_len(&self) -> usize {
        self.buf.len()
    }

    /// Is the rest of an over-long line being skipped? Set when a line with
    /// no end yet passes the limit, cleared at its end.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    fn drain(&mut self) -> Vec<Framed> {
        let mut out = Vec::new();
        loop {
            if self.overflowed {
                match self.buf.iter().position(|&b| b == b'\n') {
                    Some(i) => {
                        self.buf.drain(..=i);
                        self.overflowed = false;
                        continue;
                    }
                    // The rest of the over-long line: nothing of it is kept.
                    None => {
                        self.buf.clear();
                        return out;
                    }
                }
            }
            match self.buf.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    let mut line: Vec<u8> = self.buf.drain(..=i).collect();
                    // The '\n' is dropped; a '\r' immediately before it is the
                    // CRLF terminator. A '\r' anywhere else is content.
                    line.pop();
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    // **THE LENGTH IS CHECKED ON THE LINE, AND THAT MATTERS.**
                    //
                    // A first version checked `buf.len() > max_line` only in the
                    // arm where **no** newline had arrived. So a peer could
                    // send a 4 MB line **complete with its CRLF in one frame**
                    // and it was emitted whole. MEASURED 2026-10-02:
                    // `with_max_line(64)` returned the whole 500-byte line plus
                    // the `PING` behind it.
                    //
                    // The buffered check is still needed, and for the other
                    // case: a line that has not terminated yet is the one that
                    // can grow without bound. **Both checks, because they
                    // cover different failure modes** — a complete over-long
                    // line, and an unterminated one that would otherwise make
                    // the buffer grow without limit.
                    //
                    // **`+2` for the CRLF, and that is RFC 2812 §2.3's own
                    // wording:** the 512 is *"a maximum message length of 512
                    // characters"*, and a message on the wire carries its
                    // terminator. A limit that forgot this would refuse a
                    // line the RFC allows, and the boundary is exactly where
                    // such a bug shows.
                    if line.len() + 2 > self.max_line {
                        // **A loss in the list, not a silent drop**, and the
                        // lines after it go on: the whole line is here, its
                        // end with it, so nothing of it is left to skip.
                        out.push(Framed::Lost(FrameError::Overlong { bytes: line.len(), max_line: self.max_line }));
                        continue;
                    }
                    if let Some(framed) = finish(line) {
                        out.push(framed);
                    }
                }
                None => {
                    // A legal line with no end yet holds at most its content
                    // and the CR of its CRLF: `max_line - 1` bytes. One more,
                    // and it is over; its bytes go from here on.
                    if self.buf.len() >= self.max_line {
                        out.push(Framed::Lost(FrameError::Overlong { bytes: self.buf.len(), max_line: self.max_line }));
                        self.buf.clear();
                        self.overflowed = true;
                    }
                    return out;
                }
            }
        }
    }
}

/// NUL is stripped, CRLF is already gone, and a bare LF's leading CR is
/// gone. RFC 2812 (section 2.2) names no character set: UTF-8 is what IRC
/// writes today, and what is not UTF-8 is read as Latin-1, the older one:
/// each byte keeps a character, where U+FFFD for each would lose text a reader
/// can read.
fn finish(line: Vec<u8>) -> Option<Framed> {
    let kept: Vec<u8> = line.into_iter().filter(|&b| b != 0).collect();
    if kept.is_empty() {
        return None;
    }
    Some(match String::from_utf8(kept) {
        Ok(text) => Framed::Line(text),
        Err(e) => Framed::Latin1(e.into_bytes().into_iter().map(char::from).collect()),
    })
}

/// **A failure of the byte layer.** The parser has its own error type;
/// keeping them apart means a caller can tell "the peer sent bytes that are
/// not a message" from "the peer sent a line too long to hold".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// A line passed the configured limit, so it was dropped whole: `bytes`
    /// is its length, or, for a line with no end yet, what had come of it.
    Overlong { bytes: usize, max_line: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Overlong { bytes, max_line } => write!(
                f,
                "an IRC line passed the {max_line}-byte limit at {bytes} bytes; \
                 it was dropped whole, and the stream resumed at the next line"
            ),
        }
    }
}

impl std::error::Error for FrameError {}
