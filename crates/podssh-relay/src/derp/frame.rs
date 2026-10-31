//! DERP's frames, as tailscale/tailscale:derp/derp.go writes them at
//! v1.104.4: a type byte, the length of the body in 4 bytes, big-endian, then
//! the body. Sans-IO: the bytes of a stream in, whole frames out, and the
//! frames that a client sends as bytes. A server's WebSocket carries the
//! stream in messages whose ends mean nothing, so a frame may span them.

use std::fmt;

/// What the server's first frame starts with: "DERP" and a key, in UTF-8.
pub const MAGIC: &[u8; 8] = b"DERP\xF0\x9F\x94\x91";
/// The type byte and the length.
pub const HEADER: usize = 5;
/// A key of DERP: a Curve25519 public key.
pub const KEY: usize = 32;
/// The nonce of a sealed box.
pub const NONCE: usize = 24;
/// The largest packet that a server forwards (`MaxPacketSize`).
pub const MAX_PACKET: usize = 64 << 10;
/// The largest frame that this end reads: a server's info may be 1 MiB
/// (`MaxInfoLen`) after its nonce; each other frame is smaller.
pub const MAX_FRAME: usize = (1 << 20) + NONCE;
/// The version of DERP that this end speaks (`ProtocolVersion`): a received
/// packet starts with its sender's key.
pub const VERSION: u32 = 2;

/// The type bytes of the frames.
pub mod kind {
    pub const SERVER_KEY: u8 = 0x01;
    pub const CLIENT_INFO: u8 = 0x02;
    pub const SERVER_INFO: u8 = 0x03;
    pub const SEND_PACKET: u8 = 0x04;
    pub const RECV_PACKET: u8 = 0x05;
    pub const KEEP_ALIVE: u8 = 0x06;
    pub const NOTE_PREFERRED: u8 = 0x07;
    pub const PEER_GONE: u8 = 0x08;
    pub const PEER_PRESENT: u8 = 0x09;
    pub const FORWARD_PACKET: u8 = 0x0a;
    pub const WATCH_CONNS: u8 = 0x10;
    pub const CLOSE_PEER: u8 = 0x11;
    pub const PING: u8 = 0x12;
    pub const PONG: u8 = 0x13;
    pub const HEALTH: u8 = 0x14;
    pub const RESTARTING: u8 = 0x15;
}

/// The reason byte of a peer that is gone.
pub mod gone {
    /// The peer was here, and left.
    pub const DISCONNECTED: u8 = 0x00;
    /// The server does not know the peer.
    pub const NOT_HERE: u8 = 0x01;
}

/// A frame from the server, as a client reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// The server's key, after the magic; more bytes may follow, for later
    /// versions.
    ServerKey {
        key: [u8; KEY],
    },
    /// The server's info: a nonce, then the box.
    ServerInfo {
        sealed: Vec<u8>,
    },
    /// A packet of the peer `src`.
    RecvPacket {
        src: [u8; KEY],
        packet: Vec<u8>,
    },
    KeepAlive,
    /// A peer that sent to this end left, or is not on the server; an old
    /// server sends no reason.
    PeerGone {
        key: [u8; KEY],
        reason: Option<u8>,
    },
    Ping([u8; 8]),
    Pong([u8; 8]),
    /// What is wrong with this connection, made safe; empty when nothing is.
    Health(String),
    /// The server restarts: when to connect again, and for how long to try.
    Restarting {
        reconnect_ms: u32,
        total_ms: u32,
    },
    /// A frame that a client has no use for (a mesh's, a later version's).
    Other {
        kind: u8,
        len: usize,
    },
}

impl Frame {
    /// The frame's name, for a line.
    pub fn name(&self) -> &'static str {
        match self {
            Frame::ServerKey { .. } => "its key",
            Frame::ServerInfo { .. } => "its info",
            Frame::RecvPacket { .. } => "a packet",
            Frame::KeepAlive => "a keepalive",
            Frame::PeerGone { .. } => "a peer that is gone",
            Frame::Ping(_) => "a ping",
            Frame::Pong(_) => "a pong",
            Frame::Health(_) => "its health",
            Frame::Restarting { .. } => "its restart",
            Frame::Other { .. } => "a frame of another kind",
        }
    }
}

/// Why the stream of frames cannot go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// A frame longer than [`MAX_FRAME`].
    TooLong { kind: u8, len: usize },
    /// A frame too short for its kind.
    Short { kind: u8, len: usize },
    /// A server's key with no DERP magic before it.
    Magic,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLong { kind, len } => {
                write!(f, "a frame of type {kind:#04x} of {len} bytes, over the {MAX_FRAME} that DERP allows")
            }
            FrameError::Short { kind, len } => write!(f, "a frame of type {kind:#04x} of {len} bytes, too short"),
            FrameError::Magic => f.write_str("a first frame with no DERP magic: not a DERP server"),
        }
    }
}

impl std::error::Error for FrameError {}

/// The frames of a byte stream that comes in pieces.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    at: usize,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// More bytes of the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        // The bytes before `at` are read: dropped when nothing follows them,
        // or when they are most of the buffer, so no copy is made per frame.
        if self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        } else if self.at > 64 * 1024 && self.at * 2 > self.buf.len() {
            self.buf.drain(..self.at);
            self.at = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole frame; `None` until its last byte came.
    pub fn decode(&mut self) -> Result<Option<Frame>, FrameError> {
        let rest = &self.buf[self.at..];
        if rest.len() < HEADER {
            return Ok(None);
        }
        let kind = rest[0];
        let len = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        if len > MAX_FRAME {
            return Err(FrameError::TooLong { kind, len });
        }
        if rest.len() < HEADER + len {
            return Ok(None);
        }
        let frame = parse(kind, &rest[HEADER..HEADER + len])?;
        self.at += HEADER + len;
        Ok(Some(frame))
    }

    /// The bytes that came and are in no frame yet.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.at
    }
}

fn key_at(body: &[u8], at: usize) -> [u8; KEY] {
    let mut key = [0u8; KEY];
    key.copy_from_slice(&body[at..at + KEY]);
    key
}

fn eight(body: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&body[..8]);
    out
}

fn parse(kind: u8, body: &[u8]) -> Result<Frame, FrameError> {
    let at_least = |need: usize| {
        if body.len() < need {
            Err(FrameError::Short { kind, len: body.len() })
        } else {
            Ok(())
        }
    };
    Ok(match kind {
        kind::SERVER_KEY => {
            at_least(MAGIC.len() + KEY)?;
            if &body[..MAGIC.len()] != MAGIC {
                return Err(FrameError::Magic);
            }
            Frame::ServerKey { key: key_at(body, MAGIC.len()) }
        }
        kind::SERVER_INFO => {
            at_least(NONCE)?;
            Frame::ServerInfo { sealed: body.to_vec() }
        }
        kind::RECV_PACKET => {
            at_least(KEY)?;
            Frame::RecvPacket { src: key_at(body, 0), packet: body[KEY..].to_vec() }
        }
        kind::KEEP_ALIVE => Frame::KeepAlive,
        kind::PEER_GONE => {
            at_least(KEY)?;
            Frame::PeerGone { key: key_at(body, 0), reason: body.get(KEY).copied() }
        }
        kind::PING => {
            at_least(8)?;
            Frame::Ping(eight(body))
        }
        kind::PONG => {
            at_least(8)?;
            Frame::Pong(eight(body))
        }
        // The server's words go to a terminal: made safe first.
        kind::HEALTH => Frame::Health(podssh_ws::text::one_line(&String::from_utf8_lossy(body))),
        kind::RESTARTING => {
            at_least(8)?;
            Frame::Restarting {
                reconnect_ms: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                total_ms: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            }
        }
        other => Frame::Other { kind: other, len: body.len() },
    })
}

/// A frame of `kind` whose body is `parts`, one after the other.
pub fn encode(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(HEADER + len);
    out.push(kind);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// The client's key and its info, sealed to the server's key.
pub fn client_info(key: &[u8; KEY], sealed: &[u8]) -> Vec<u8> {
    encode(kind::CLIENT_INFO, &[&key[..], sealed])
}

/// A packet for the peer `dst`.
pub fn send_packet(dst: &[u8; KEY], packet: &[u8]) -> Vec<u8> {
    encode(kind::SEND_PACKET, &[&dst[..], packet])
}

pub fn ping(data: [u8; 8]) -> Vec<u8> {
    encode(kind::PING, &[&data[..]])
}

pub fn pong(data: [u8; 8]) -> Vec<u8> {
    encode(kind::PONG, &[&data[..]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_key(key: [u8; KEY]) -> Vec<u8> {
        encode(kind::SERVER_KEY, &[&MAGIC[..], &key[..]])
    }

    #[test]
    fn a_frame_in_pieces_comes_whole_once_its_last_byte_came() {
        let bytes = encode(kind::RECV_PACKET, &[&[7u8; KEY][..], &b"hello"[..]]);
        let mut decoder = Decoder::new();
        for byte in &bytes[..bytes.len() - 1] {
            decoder.push(&[*byte]);
            assert_eq!(decoder.decode(), Ok(None));
        }
        decoder.push(&bytes[bytes.len() - 1..]);
        assert_eq!(decoder.decode(), Ok(Some(Frame::RecvPacket { src: [7u8; KEY], packet: b"hello".to_vec() })));
        assert_eq!(decoder.decode(), Ok(None));
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn several_frames_in_one_piece_come_in_order() {
        let mut stream = server_key([1u8; KEY]);
        stream.extend(encode(kind::KEEP_ALIVE, &[]));
        stream.extend(encode(kind::PING, &[&b"12345678"[..]]));
        stream.extend(encode(kind::PEER_GONE, &[&[2u8; KEY][..], &[gone::NOT_HERE]]));
        stream.extend(encode(kind::RESTARTING, &[&500u32.to_be_bytes()[..], &9000u32.to_be_bytes()[..]]));
        let mut decoder = Decoder::new();
        decoder.push(&stream);
        assert_eq!(decoder.decode(), Ok(Some(Frame::ServerKey { key: [1u8; KEY] })));
        assert_eq!(decoder.decode(), Ok(Some(Frame::KeepAlive)));
        assert_eq!(decoder.decode(), Ok(Some(Frame::Ping(*b"12345678"))));
        assert_eq!(decoder.decode(), Ok(Some(Frame::PeerGone { key: [2u8; KEY], reason: Some(gone::NOT_HERE) })));
        assert_eq!(decoder.decode(), Ok(Some(Frame::Restarting { reconnect_ms: 500, total_ms: 9000 })));
        assert_eq!(decoder.decode(), Ok(None));
    }

    #[test]
    fn a_server_key_with_more_bytes_after_it_is_read_and_one_with_no_magic_is_refused() {
        let mut longer = encode(kind::SERVER_KEY, &[&MAGIC[..], &[3u8; KEY][..], &b"later"[..]]);
        let mut decoder = Decoder::new();
        decoder.push(&longer);
        assert_eq!(decoder.decode(), Ok(Some(Frame::ServerKey { key: [3u8; KEY] })));
        longer[HEADER] = b'X';
        let mut decoder = Decoder::new();
        decoder.push(&longer);
        assert_eq!(decoder.decode(), Err(FrameError::Magic));
    }

    #[test]
    fn a_frame_too_long_or_too_short_for_its_kind_is_refused() {
        let mut header = vec![kind::RECV_PACKET];
        header.extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
        let mut decoder = Decoder::new();
        decoder.push(&header);
        assert_eq!(decoder.decode(), Err(FrameError::TooLong { kind: kind::RECV_PACKET, len: MAX_FRAME + 1 }));
        let mut decoder = Decoder::new();
        decoder.push(&encode(kind::RECV_PACKET, &[&[0u8; 31][..]]));
        assert_eq!(decoder.decode(), Err(FrameError::Short { kind: kind::RECV_PACKET, len: 31 }));
    }

    #[test]
    fn a_server_s_words_are_made_safe_and_an_unknown_kind_is_kept_as_other() {
        let mut decoder = Decoder::new();
        decoder.push(&encode(kind::HEALTH, &[&b"duplicate\x1b[2J connection"[..]]));
        decoder.push(&encode(0x7f, &[&b"later"[..]]));
        let Ok(Some(Frame::Health(text))) = decoder.decode() else { panic!("a health frame") };
        assert!(!text.contains('\x1b'), "{text:?}");
        assert_eq!(decoder.decode(), Ok(Some(Frame::Other { kind: 0x7f, len: 5 })));
    }

    #[test]
    fn the_frames_of_a_client_have_derp_s_header() {
        let frame = send_packet(&[9u8; KEY], b"abc");
        assert_eq!(frame[0], kind::SEND_PACKET);
        assert_eq!(&frame[1..5], &35u32.to_be_bytes());
        assert_eq!(&frame[5..37], &[9u8; KEY]);
        assert_eq!(&frame[37..], b"abc");
        assert_eq!(ping(*b"abcdefgh"), [&[kind::PING, 0, 0, 0, 8][..], &b"abcdefgh"[..]].concat());
        assert_eq!(pong(*b"abcdefgh")[0], kind::PONG);
        assert_eq!(client_info(&[1u8; KEY], b"box").len(), HEADER + KEY + 3);
    }
}
