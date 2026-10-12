//! The bytes of ZMODEM (the spec's section 7): the ZDLE escapes, the three
//! forms of a header, the data subpackets, and their CRCs. [`Reader`] reads
//! them one byte at a time, so that a header that two messages of the
//! channel cut reads the same as a whole one.

pub use super::read::{Event, Reader};

/// "Padding character begins frames" (lrzsz's `zmodem.h`).
pub const ZPAD: u8 = b'*';
/// Ctrl-X, the escape of ZMODEM. It is also CAN: five in a row cancel (7.2).
pub const ZDLE: u8 = 0x18;
pub const CAN: u8 = ZDLE;
/// The forms of a header (7.3): binary with CRC-16, hex, binary with CRC-32.
pub const ZBIN: u8 = b'A';
pub const ZHEX: u8 = b'B';
pub const ZBIN32: u8 = b'C';
/// XON and XOFF: "The receiver ignores 021, 0221, 023, and 0223 characters
/// in the data stream" (7.2).
pub const XON: u8 = 0x11;
pub const XOFF: u8 = 0x13;

// The frame types, with lrzsz's numbers.
pub const ZRQINIT: u8 = 0;
pub const ZRINIT: u8 = 1;
pub const ZSINIT: u8 = 2;
pub const ZACK: u8 = 3;
pub const ZFILE: u8 = 4;
pub const ZSKIP: u8 = 5;
pub const ZNAK: u8 = 6;
pub const ZABORT: u8 = 7;
pub const ZFIN: u8 = 8;
pub const ZRPOS: u8 = 9;
pub const ZDATA: u8 = 10;
pub const ZEOF: u8 = 11;
pub const ZFERR: u8 = 12;
pub const ZCRC: u8 = 13;
pub const ZCHALLENGE: u8 = 14;
pub const ZCOMPL: u8 = 15;
pub const ZCAN: u8 = 16;
pub const ZFREECNT: u8 = 17;
pub const ZCOMMAND: u8 = 18;
pub const ZSTDERR: u8 = 19;

/// The ends of a data subpacket, after a ZDLE (7.4, 8.2): the frame ends
/// and a header follows (ZCRCE); the frame goes on with no answer (ZCRCG);
/// it goes on, and a ZACK answers (ZCRCQ); it ends, and a ZACK answers
/// (ZCRCW).
pub const ZCRCE: u8 = b'h';
pub const ZCRCG: u8 = b'i';
pub const ZCRCQ: u8 = b'j';
pub const ZCRCW: u8 = b'k';
/// After a ZDLE: DEL, and DEL with the parity bit.
pub const ZRUB0: u8 = b'l';
pub const ZRUB1: u8 = b'm';

/// The flags of ZRINIT, in ZF0: full duplex, I/O during the disk's work,
/// CRC-32, and each control character escaped.
pub const CANFDX: u8 = 0x01;
pub const CANOVIO: u8 = 0x02;
pub const CANFC32: u8 = 0x20;
pub const ESCCTL: u8 = 0x40;

/// ZFILE's conversion option in ZF0: binary, with no change of line ends.
pub const ZCBIN: u8 = 1;

/// Where ZF0 and ZF1 are among a header's four bytes. A position is the
/// four bytes, the least significant first.
pub const ZF0: usize = 3;
pub const ZF1: usize = 2;

/// The longest data subpacket read: twice the 8 KiB that `sz -8` sends.
pub const MOST_DATA: usize = 16 * 1024;

/// The form of a header on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    Hex,
    Bin16,
    Bin32,
}

/// A header: its type, and its four bytes of flags or of a position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub bytes: [u8; 4],
    pub form: Form,
}

impl Header {
    /// The four bytes as a position.
    pub fn position(&self) -> u32 {
        u32::from_le_bytes(self.bytes)
    }

    /// The flags of ZF0.
    pub fn flags(&self) -> u8 {
        self.bytes[ZF0]
    }
}

/// The four bytes of a position. Positions have 32 bits; a file of 4 GiB
/// or more is refused before it crosses.
pub fn at(position: u64) -> [u8; 4] {
    (position as u32).to_le_bytes()
}

/// A frame type's name, for a message.
pub fn name(kind: u8) -> String {
    const NAMES: [&str; 20] = [
        "ZRQINIT",
        "ZRINIT",
        "ZSINIT",
        "ZACK",
        "ZFILE",
        "ZSKIP",
        "ZNAK",
        "ZABORT",
        "ZFIN",
        "ZRPOS",
        "ZDATA",
        "ZEOF",
        "ZFERR",
        "ZCRC",
        "ZCHALLENGE",
        "ZCOMPL",
        "ZCAN",
        "ZFREECNT",
        "ZCOMMAND",
        "ZSTDERR",
    ];
    NAMES.get(usize::from(kind)).map_or_else(|| format!("frame type {kind}"), |n| n.to_string())
}

/// The CRC-16 of ZMODEM: the polynomial 0x1021, from 0, with no reflection
/// (CRC-16/XMODEM).
pub fn crc16(data: &[u8]) -> u16 {
    crc16_update(0, data)
}

pub fn crc16_update(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc = (crc << 8) ^ CRC16_TABLE[usize::from((crc >> 8) as u8 ^ b)];
    }
    crc
}

/// The CRC-32 of ZMODEM, the one of Ethernet and zip: "-1 preset,
/// inversion" (3.3).
pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(!0, data)
}

/// The register of the CRC-32 after `data`, with no inversion at the end.
pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = (crc >> 8) ^ CRC32_TABLE[usize::from(crc as u8 ^ b)];
    }
    crc
}

const CRC16_TABLE: [u16; 256] = crc16_table();
const CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// A hex digit's value, of either case.
pub fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A hex header (7.3.3): ZPAD ZPAD ZDLE ZHEX, then the type, the four bytes
/// and their CRC-16 in lowercase hex, then CR and LF (LF with the parity
/// bit, as lrzsz sends it), and XON: "An XON character is appended to all
/// HEX packets except ZACK and ZFIN."
pub fn hex_header(kind: u8, bytes: [u8; 4]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let body = [kind, bytes[0], bytes[1], bytes[2], bytes[3]];
    let crc = crc16(&body).to_be_bytes();
    let mut out = vec![ZPAD, ZPAD, ZDLE, ZHEX];
    for &b in body.iter().chain(&crc) {
        out.push(DIGITS[usize::from(b >> 4)]);
        out.push(DIGITS[usize::from(b & 0x0f)]);
    }
    out.extend_from_slice(b"\r\x8a");
    if kind != ZACK && kind != ZFIN {
        out.push(XON);
    }
    out
}

/// The escapes of what podssh sends: "ZMODEM software escapes ZDLE, 020,
/// 0220, 021, 0221, 023, and 0223" (7.2), and CR after `@`, as lrzsz's
/// `zsendline` does; with `ctl` (the receiver's ESCCTL), each control
/// character. An escaped byte is ZDLE, then the byte with bit 6 inverted.
#[derive(Debug, Clone, Default)]
pub struct Escaper {
    pub ctl: bool,
    last: u8,
}

impl Escaper {
    pub fn new(ctl: bool) -> Escaper {
        Escaper { ctl, last: 0 }
    }

    fn put(&mut self, out: &mut Vec<u8>, byte: u8) {
        // A byte with bit 5 or bit 6 set is never escaped.
        let escape = (byte & 0x60) == 0
            && match byte {
                ZDLE | 0x10 | 0x90 | XON | 0x91 | XOFF | 0x93 => true,
                b'\r' | 0x8d => self.ctl || (self.last & 0x7f) == b'@',
                _ => self.ctl,
            };
        if escape {
            out.push(ZDLE);
            out.push(byte ^ 0x40);
            self.last = byte ^ 0x40;
        } else {
            out.push(byte);
            self.last = byte;
        }
    }

    /// A binary header (7.3.1, 7.3.2): ZPAD ZDLE ZBIN or ZBIN32, then the
    /// type, the four bytes and the CRC, each escaped. The CRC-16 goes high
    /// byte first; the four bytes of the CRC-32, low byte first.
    pub fn header(&mut self, kind: u8, bytes: [u8; 4], crc32: bool) -> Vec<u8> {
        let body = [kind, bytes[0], bytes[1], bytes[2], bytes[3]];
        let mut out = vec![ZPAD, ZDLE, if crc32 { ZBIN32 } else { ZBIN }];
        for b in body {
            self.put(&mut out, b);
        }
        self.put_crc(&mut out, &[&body[..]], crc32);
        out
    }

    /// A data subpacket (7.4): the data escaped, ZDLE and the frame end, then
    /// the CRC: "The CRC accumulates the data bytes and frameend." An XON
    /// follows ZCRCW, as lrzsz sends it.
    pub fn subpacket(&mut self, data: &[u8], end: u8, crc32: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 16);
        for &b in data {
            self.put(&mut out, b);
        }
        out.push(ZDLE);
        out.push(end);
        self.put_crc(&mut out, &[data, &[end][..]], crc32);
        if end == ZCRCW {
            out.push(XON);
        }
        out
    }

    fn put_crc(&mut self, out: &mut Vec<u8>, parts: &[&[u8]], crc32: bool) {
        if crc32 {
            let crc = !parts.iter().fold(!0u32, |c, p| crc32_update(c, p));
            for b in crc.to_le_bytes() {
                self.put(out, b);
            }
        } else {
            let crc = parts.iter().fold(0u16, |c, p| crc16_update(c, p));
            for b in crc.to_be_bytes() {
                self.put(out, b);
            }
        }
    }
}
