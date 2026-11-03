//! One direction of an SSH handshake, read as it passes (T-588): the lines
//! before the version line, the version line, then the header of each
//! binary packet (RFC 4253, sections 4.2 and 6) up to NEWKEYS, after which
//! the packets are encrypted and only counted. It reads; it never changes a
//! byte, and a stream that is no SSH stops the reading, not the stream.

/// The most of a line that is kept: what RFC 4253 allows a version line,
/// its CR LF included.
const LINE_MAX: usize = 255;
/// The most of another service's line that a message shows.
const SHOWN: usize = 100;
/// A packet's length, its padding's length and its message number.
const HEADER: usize = 6;
/// The length of a packet of a key exchange: a byte of the padding's length,
/// a message number and 4 bytes of padding at least, and OpenSSH's largest
/// packet at most (256 KiB).
const SHORTEST: u32 = 6;
const LONGEST: u32 = 256 * 1024;
/// SSH_MSG_NEWKEYS: each packet after it is encrypted.
const NEWKEYS: u8 = 21;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum State {
    /// The lines before the version line, and the version line.
    #[default]
    Line,
    /// The first bytes of a packet.
    Header,
    /// The rest of a packet, this many bytes.
    Body(u32),
    /// After NEWKEYS: counted, not read.
    Sealed,
    /// Bytes after the version line that are no packet of SSH.
    Unknown,
}

/// What one direction carried.
#[derive(Debug, Default)]
pub(crate) struct Side {
    /// Each byte, the encrypted ones too.
    pub(crate) bytes: u64,
    state: State,
    line: Vec<u8>,
    head: [u8; HEADER],
    head_len: usize,
    /// The version line, made safe for a terminal.
    pub(crate) version: Option<String>,
    /// The first line before it that was not empty: another service's words.
    pub(crate) other: Option<String>,
    /// The number of the last message whose header passed.
    pub(crate) last: Option<u8>,
}

impl Side {
    /// Read `data`, the next bytes of this direction.
    pub(crate) fn feed(&mut self, data: &[u8]) {
        self.bytes = self.bytes.saturating_add(data.len() as u64);
        let mut at = 0;
        while at < data.len() {
            let (rest, state) = (&data[at..], self.state);
            // Each part takes one byte at least, so the loop ends.
            at += match state {
                State::Sealed | State::Unknown => return,
                State::Line => self.line_part(rest),
                State::Header => self.header_part(rest),
                State::Body(left) => self.body_part(left, rest),
            };
        }
    }

    /// Whether this direction's packets are encrypted now.
    pub(crate) fn sealed(&self) -> bool {
        self.state == State::Sealed
    }

    /// The last thing that this side sent, in the words of a line.
    pub(crate) fn step(&self) -> String {
        self.last.map_or_else(|| "version line".to_string(), message)
    }

    fn line_part(&mut self, rest: &[u8]) -> usize {
        let end = rest.iter().position(|&b| b == b'\n');
        let take = end.map_or(rest.len(), |i| i + 1);
        // A longer line is read to its end, and its start kept.
        let room = LINE_MAX.saturating_sub(self.line.len());
        self.line.extend_from_slice(&rest[..take.min(room)]);
        if end.is_some() {
            let line = std::mem::take(&mut self.line);
            self.ended(&line);
        }
        take
    }

    fn ended(&mut self, line: &[u8]) {
        let raw = String::from_utf8_lossy(line);
        let raw = raw.trim_end_matches(['\r', '\n']);
        let text = podssh_ws::text::one_line(raw);
        if raw.starts_with("SSH-") {
            self.version = Some(text);
            self.state = State::Header;
        } else if self.other.is_none() && !text.is_empty() {
            self.other = Some(text.chars().take(SHOWN).collect());
        }
    }

    fn header_part(&mut self, rest: &[u8]) -> usize {
        let take = (HEADER - self.head_len).min(rest.len());
        self.head[self.head_len..self.head_len + take].copy_from_slice(&rest[..take]);
        self.head_len += take;
        if self.head_len == HEADER {
            self.head_len = 0;
            let length = u32::from_be_bytes([self.head[0], self.head[1], self.head[2], self.head[3]]);
            self.state = if (SHORTEST..=LONGEST).contains(&length) {
                self.last = Some(self.head[5]);
                // The length counts each byte after its own 4.
                State::Body(length + 4 - HEADER as u32)
            } else {
                State::Unknown
            };
        }
        take
    }

    fn body_part(&mut self, left: u32, rest: &[u8]) -> usize {
        let take = (left as usize).min(rest.len());
        self.state = match left - take as u32 {
            0 if self.last == Some(NEWKEYS) => State::Sealed,
            0 => State::Header,
            more => State::Body(more),
        };
        take
    }
}

/// A message of the transport by its name in RFC 4253 and RFC 4419, as
/// OpenSSH's `-v` names it; the exchanges of ECDH, Curve25519 and the hybrid
/// ones send their two messages under the numbers 30 and 31.
pub(crate) fn message(number: u8) -> String {
    // One string of number and name in turn: the manual's reader of the
    // variables a run reads takes a quoted name of capitals for one.
    const NAMES: &str = "1 DISCONNECT 2 IGNORE 3 UNIMPLEMENTED 4 DEBUG 5 SERVICE_REQUEST 6 SERVICE_ACCEPT \
        7 EXT_INFO 20 KEXINIT 21 NEWKEYS 30 KEX_ECDH_INIT 31 KEX_ECDH_REPLY 32 KEX_DH_GEX_INIT 33 KEX_DH_GEX_REPLY \
        34 KEX_DH_GEX_REQUEST";
    let mut words = NAMES.split_whitespace();
    while let (Some(n), Some(name)) = (words.next(), words.next()) {
        if n.parse::<u8>() == Ok(number) {
            return name.to_string();
        }
    }
    format!("message {number}")
}
