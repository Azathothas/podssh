//! The frames of yamux, which frpc and frps run on each connection with
//! their default `transport.tcpMux` (`fatedier/yamux`, hashicorp's yamux):
//! a header of 12 bytes, the version 0, a type, flags, a stream id and a
//! length, all big-endian; the payload follows a data frame alone.

/// The types of a frame.
pub const DATA: u8 = 0;
pub const WINDOW_UPDATE: u8 = 1;
pub const PING: u8 = 2;
pub const GO_AWAY: u8 = 3;

/// The flags of a frame.
pub const SYN: u16 = 1;
pub const ACK: u16 = 2;
pub const FIN: u16 = 4;
pub const RST: u16 = 8;

/// The window that each side grants each stream at its start (yamux's
/// `initialStreamWindow`).
pub const INITIAL_WINDOW: u32 = 256 * 1024;

/// The length of a header.
pub const HEADER: usize = 12;

/// A frame's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub flags: u16,
    pub stream: u32,
    /// A data frame's payload length; a window update's delta; a ping's
    /// opaque value; a go-away's code.
    pub length: u32,
}

impl Header {
    pub fn new(kind: u8, flags: u16, stream: u32, length: u32) -> Header {
        Header { kind, flags, stream, length }
    }

    pub fn encode(&self) -> [u8; HEADER] {
        let mut out = [0u8; HEADER];
        out[0] = 0;
        out[1] = self.kind;
        out[2..4].copy_from_slice(&self.flags.to_be_bytes());
        out[4..8].copy_from_slice(&self.stream.to_be_bytes());
        out[8..12].copy_from_slice(&self.length.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8; HEADER]) -> Result<Header, String> {
        if bytes[0] != 0 {
            return Err(format!("a yamux frame of the version {}, where yamux has 0", bytes[0]));
        }
        let kind = bytes[1];
        if kind > GO_AWAY {
            return Err(format!("a yamux frame of the type {kind}, which yamux does not have"));
        }
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let stream = u32::from_be_bytes(bytes[4..8].try_into().expect("4 bytes"));
        let length = u32::from_be_bytes(bytes[8..12].try_into().expect("4 bytes"));
        Ok(Header { kind, flags, stream, length })
    }

    pub fn has(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }
}

/// A data frame with `payload`.
pub fn data(stream: u32, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Header::new(DATA, flags, stream, payload.len() as u32).encode().to_vec();
    out.extend_from_slice(payload);
    out
}

/// A window update of `delta` bytes.
pub fn window(stream: u32, flags: u16, delta: u32) -> Vec<u8> {
    Header::new(WINDOW_UPDATE, flags, stream, delta).encode().to_vec()
}

/// The words of a go-away's code, as yamux names them.
pub fn go_away_words(code: u32) -> &'static str {
    match code {
        0 => "it ended the session normally",
        1 => "it found an error of the protocol",
        2 => "it had an internal error",
        _ => "it ended the session",
    }
}
