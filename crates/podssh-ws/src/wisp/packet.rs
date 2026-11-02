//! Wisp's packets, as version 2 of its protocol writes them (version 1 is
//! the same packets with no INFO): a type of one byte, a stream id of four,
//! and the payload in the rest of the WebSocket message, each number
//! little-endian and each string with no NUL at its end. Written from the
//! protocol's document (MercuryWorkshop/wisp-protocol:protocol.md, branch
//! v2), not from an implementation.

/// The types of a packet.
pub const CONNECT: u8 = 0x01;
pub const DATA: u8 = 0x02;
pub const CONTINUE: u8 = 0x03;
pub const CLOSE: u8 = 0x04;
pub const INFO: u8 = 0x05;

/// The stream type of a CONNECT for TCP. UDP (0x02) is optional in version
/// 2, and this road carries none.
pub const TCP: u8 = 0x01;

/// The type and the stream id before each payload.
pub const HEADER: usize = 5;

/// The ids of the extensions of version 2, as an INFO lists them.
pub mod ext {
    pub const UDP: u8 = 0x01;
    pub const PASSWORD: u8 = 0x02;
    pub const KEY: u8 = 0x03;
    pub const MOTD: u8 = 0x04;
    /// Stream open confirmation: the server's CONTINUE once the target's
    /// socket is open.
    pub const CONFIRM: u8 = 0x05;
}

/// A packet's payload, by its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Connect {
        kind: u8,
        port: u16,
        host: String,
    },
    Data(Vec<u8>),
    /// The number of packets that the server can buffer for the stream.
    Continue(u32),
    Close(Reason),
    Info(Info),
    /// A type that version 2 does not name: kept, so that a later version's
    /// packet is skipped rather than taken for a broken connection.
    Other {
        kind: u8,
        payload: Vec<u8>,
    },
}

impl Packet {
    /// Its name, for a line.
    pub fn name(&self) -> String {
        match self {
            Packet::Connect { .. } => "CONNECT".into(),
            Packet::Data(_) => "DATA".into(),
            Packet::Continue(_) => "CONTINUE".into(),
            Packet::Close(_) => "CLOSE".into(),
            Packet::Info(_) => "INFO".into(),
            Packet::Other { kind, .. } => format!("a packet of type {kind:#04x}"),
        }
    }
}

/// An INFO: the version that its sender takes, and its extensions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Info {
    pub major: u8,
    pub minor: u8,
    pub extensions: Vec<Extension>,
}

impl Info {
    /// The payload of the extension `id`, when its sender lists it.
    pub fn extension(&self, id: u8) -> Option<&[u8]> {
        self.extensions.iter().find(|e| e.id == id).map(|e| e.payload.as_slice())
    }
}

/// One extension of an INFO: its id and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub id: u8,
    pub payload: Vec<u8>,
}

/// The reason of a CLOSE, in the words of the protocol's document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reason(pub u8);

impl Reason {
    pub const UNSPECIFIED: Reason = Reason(0x01);
    /// The ordinary end of a stream, either side's.
    pub const VOLUNTARY: Reason = Reason(0x02);
    pub const NETWORK: Reason = Reason(0x03);
    pub const INCOMPATIBLE: Reason = Reason(0x04);
    pub const INVALID: Reason = Reason(0x41);
    pub const UNREACHABLE: Reason = Reason(0x42);
    pub const TIMED_OUT: Reason = Reason(0x43);
    pub const REFUSED: Reason = Reason(0x44);
    pub const TRANSFER_TIMED_OUT: Reason = Reason(0x47);
    pub const BLOCKED: Reason = Reason(0x48);
    pub const THROTTLED: Reason = Reason(0x49);

    /// What it means.
    pub fn words(self) -> &'static str {
        match self.0 {
            0x01 => "no reason given",
            0x02 => "the stream was closed on purpose",
            0x03 => "a network error",
            0x04 => "incompatible extensions",
            0x41 => "the server found the destination invalid (a reserved address or a bad port)",
            0x42 => "the destination is unreachable (its name may not resolve)",
            0x43 => "the destination did not answer in time",
            0x44 => "the destination refused the connection",
            0x47 => "the TCP transfer timed out",
            0x48 => "the server blocks this destination",
            0x49 => "the server throttled the connection",
            0x81 => "the client could take no more data",
            0xc0 => "a wrong user name or password",
            0xc1 => "a wrong signature",
            0xc2 => "the server requires credentials",
            _ => "a reason that version 2 of Wisp does not name",
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#04x}, {}", self.0, self.words())
    }
}

/// The header of a packet of `kind` on `stream`.
fn header(kind: u8, stream: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER);
    out.push(kind);
    out.extend_from_slice(&stream.to_le_bytes());
    out
}

/// A DATA packet, the bytes copied once behind its header.
pub fn data(stream: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = header(DATA, stream);
    out.extend_from_slice(bytes);
    out
}

/// `packet` on `stream`, as one WebSocket message carries it.
pub fn encode(stream: u32, packet: &Packet) -> Vec<u8> {
    match packet {
        Packet::Connect { kind, port, host } => {
            let mut out = header(CONNECT, stream);
            out.push(*kind);
            out.extend_from_slice(&port.to_le_bytes());
            out.extend_from_slice(host.as_bytes());
            out
        }
        Packet::Data(bytes) => data(stream, bytes),
        Packet::Continue(left) => {
            let mut out = header(CONTINUE, stream);
            out.extend_from_slice(&left.to_le_bytes());
            out
        }
        Packet::Close(reason) => {
            let mut out = header(CLOSE, stream);
            out.push(reason.0);
            out
        }
        Packet::Info(info) => {
            let mut out = header(INFO, stream);
            out.extend_from_slice(&[info.major, info.minor]);
            for e in &info.extensions {
                out.push(e.id);
                out.extend_from_slice(&(e.payload.len() as u32).to_le_bytes());
                out.extend_from_slice(&e.payload);
            }
            out
        }
        Packet::Other { kind, payload } => {
            let mut out = header(*kind, stream);
            out.extend_from_slice(payload);
            out
        }
    }
}

/// The stream id and the packet of one message; a message too short for
/// its type, a hostname that is not UTF-8, and an extension longer than
/// its INFO are refused. A field past the end of a CONTINUE, a CLOSE or a
/// CONNECT's fixed part is the payload of a later minor version, and is
/// not read.
pub fn decode(bytes: &[u8]) -> Result<(u32, Packet), String> {
    if bytes.len() < HEADER {
        return Err(format!("a Wisp packet of {} bytes, shorter than its header of {HEADER}", bytes.len()));
    }
    let kind = bytes[0];
    let stream = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    let payload = &bytes[HEADER..];
    let short = |name: &str, want: usize| format!("a {name} of {} bytes, shorter than its {want}", payload.len());
    let packet = match kind {
        CONNECT => {
            if payload.len() < 3 {
                return Err(short("CONNECT", 3));
            }
            let port = u16::from_le_bytes([payload[1], payload[2]]);
            let host = std::str::from_utf8(&payload[3..]).map_err(|_| "a CONNECT whose host is not UTF-8")?;
            Packet::Connect { kind: payload[0], port, host: host.to_string() }
        }
        DATA => Packet::Data(payload.to_vec()),
        CONTINUE => {
            if payload.len() < 4 {
                return Err(short("CONTINUE", 4));
            }
            Packet::Continue(u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]))
        }
        CLOSE => match payload.first() {
            Some(reason) => Packet::Close(Reason(*reason)),
            None => return Err(short("CLOSE", 1)),
        },
        INFO => Packet::Info(info(payload)?),
        _ => Packet::Other { kind, payload: payload.to_vec() },
    };
    Ok((stream, packet))
}

/// An INFO's payload: two bytes of version, then each extension as its id,
/// its length and its metadata.
fn info(payload: &[u8]) -> Result<Info, String> {
    if payload.len() < 2 {
        return Err(format!("an INFO of {} bytes, shorter than its version of 2", payload.len()));
    }
    let mut info = Info { major: payload[0], minor: payload[1], extensions: Vec::new() };
    let mut rest = &payload[2..];
    while !rest.is_empty() {
        if rest.len() < 5 {
            return Err(format!("an INFO's extension of {} bytes, shorter than its id and length", rest.len()));
        }
        let id = rest[0];
        let len = u32::from_le_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        // A length near 4 GiB must not wrap on a 32-bit target.
        let end = len
            .checked_add(5)
            .filter(|end| *end <= rest.len())
            .ok_or_else(|| format!("an INFO's extension {id:#04x} of {len} bytes, past the end of its packet"))?;
        info.extensions.push(Extension { id, payload: rest[5..end].to_vec() });
        rest = &rest[end..];
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each byte string below is written from the tables of the protocol's
    // document, field by field, little-endian.

    #[test]
    fn a_connect_is_its_type_its_stream_its_kind_its_port_and_its_host() {
        // CONNECT, stream 1, TCP, port 443 (0x01bb), the host's bytes.
        let bytes = [&[0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0xbb, 0x01][..], &b"github.com"[..]].concat();
        let packet = Packet::Connect { kind: TCP, port: 443, host: "github.com".into() };
        assert_eq!(encode(1, &packet), bytes);
        assert_eq!(decode(&bytes).unwrap(), (1, packet));
        // Port 22, the stream id in its four bytes, low byte first.
        let ssh = encode(0x0403_0201, &Packet::Connect { kind: TCP, port: 22, host: "h".into() });
        assert_eq!(ssh, [0x01, 0x01, 0x02, 0x03, 0x04, 0x01, 0x16, 0x00, b'h']);
    }

    #[test]
    fn data_continue_and_close_are_as_the_tables_write_them() {
        assert_eq!(data(7, b"SSH-2.0-"), [&[0x02, 0x07, 0, 0, 0][..], &b"SSH-2.0-"[..]].concat());
        assert_eq!(decode(&[0x02, 0x07, 0, 0, 0]).unwrap(), (7, Packet::Data(Vec::new())), "an empty DATA");
        // The initial CONTINUE of a server of version 1: stream 0, 128 packets.
        let initial = [0x03, 0, 0, 0, 0, 0x80, 0, 0, 0];
        assert_eq!(decode(&initial).unwrap(), (0, Packet::Continue(128)));
        assert_eq!(encode(0, &Packet::Continue(128)), initial);
        assert_eq!(decode(&[0x03, 9, 0, 0, 0, 0x00, 0x01, 0x00, 0x00]).unwrap(), (9, Packet::Continue(256)));
        let close = [0x04, 0x02, 0, 0, 0, 0x42];
        assert_eq!(decode(&close).unwrap(), (2, Packet::Close(Reason::UNREACHABLE)));
        assert_eq!(encode(2, &Packet::Close(Reason(0x42))), close);
    }

    #[test]
    fn an_info_carries_the_version_and_each_extension_with_its_length() {
        // Version 2.0, UDP with no metadata, a MOTD of "hi", password
        // authentication that is required.
        #[rustfmt::skip]
        let bytes = [
            0x05, 0, 0, 0, 0, // INFO, stream 0
            0x02, 0x00, // version 2.0
            0x01, 0, 0, 0, 0, // UDP
            0x04, 0x02, 0, 0, 0, b'h', b'i', // MOTD
            0x02, 0x01, 0, 0, 0, 0x01, // password, required
        ];
        let (stream, packet) = decode(&bytes).unwrap();
        let Packet::Info(info) = &packet else { panic!("{packet:?}") };
        assert_eq!((stream, info.major, info.minor), (0, 2, 0));
        assert_eq!(info.extension(ext::UDP), Some(&[][..]));
        assert_eq!(info.extension(ext::MOTD), Some(&b"hi"[..]));
        assert_eq!(info.extension(ext::PASSWORD), Some(&[0x01][..]));
        assert_eq!(info.extension(ext::CONFIRM), None);
        assert_eq!(encode(0, &packet), bytes, "the same bytes back");
    }

    #[test]
    fn a_packet_too_short_for_its_type_is_refused() {
        for bad in [
            &[][..],
            &[0x02, 0, 0, 0][..],
            &[0x01, 1, 0, 0, 0, 0x01, 0x16][..],
            &[0x03, 1, 0, 0, 0, 0x80, 0, 0][..],
            &[0x04, 1, 0, 0, 0][..],
            &[0x05, 0, 0, 0, 0, 0x02][..],
            // An extension whose length runs past the packet.
            &[0x05, 0, 0, 0, 0, 0x02, 0x00, 0x04, 0x09, 0, 0, 0, b'x'][..],
            // An extension cut inside its length.
            &[0x05, 0, 0, 0, 0, 0x02, 0x00, 0x04, 0x01][..],
        ] {
            assert!(decode(bad).is_err(), "{bad:?}");
        }
        assert!(decode(&[0x01, 1, 0, 0, 0, 0x01, 0x16, 0x00, 0xff]).unwrap_err().contains("not UTF-8"));
    }

    #[test]
    fn a_type_that_version_2_does_not_name_is_kept_and_a_later_field_is_not_read() {
        let (stream, packet) = decode(&[0x09, 3, 0, 0, 0, 0xaa]).unwrap();
        assert_eq!((stream, packet.clone()), (3, Packet::Other { kind: 9, payload: vec![0xaa] }));
        assert_eq!(packet.name(), "a packet of type 0x09");
        assert_eq!(decode(&[0x04, 1, 0, 0, 0, 0x02, 0xff]).unwrap(), (1, Packet::Close(Reason::VOLUNTARY)));
        assert_eq!(decode(&[0x03, 1, 0, 0, 0, 4, 0, 0, 0, 0xff]).unwrap(), (1, Packet::Continue(4)));
    }

    #[test]
    fn a_reason_says_its_byte_and_its_words() {
        assert_eq!(Reason::UNREACHABLE.to_string(), "0x42, the destination is unreachable (its name may not resolve)");
        assert_eq!(Reason(0x44).words(), "the destination refused the connection");
        assert_eq!(Reason(0x7f).to_string(), "0x7f, a reason that version 2 of Wisp does not name");
    }
}
