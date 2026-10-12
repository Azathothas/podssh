//! Reading the bytes of ZMODEM (the spec's section 7) one byte at a time,
//! as lrzsz's `zgethdr` and `zdlread` read them: the search for a header,
//! its three forms, the escapes undone, the data subpackets and their CRCs,
//! and five CAN. A header that two messages of the channel cut reads the
//! same as a whole one.

use super::wire::{
    crc16, crc16_update, crc32, crc32_update, hex_digit, Form, Header, CAN, MOST_DATA, XOFF, XON, ZBIN, ZBIN32,
    ZCOMMAND, ZCRCE, ZCRCG, ZCRCQ, ZCRCW, ZDATA, ZDLE, ZFILE, ZHEX, ZPAD, ZRUB0, ZRUB1, ZSINIT, ZSTDERR,
};

/// What [`Reader`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Header(Header),
    /// A data subpacket whose CRC holds, and its frame end.
    Data {
        data: Vec<u8>,
        end: u8,
    },
    /// A header or a subpacket whose CRC fails, or that a wrong byte cut.
    Bad,
    /// Five CAN in a row: "Receipt of five successive CAN characters will
    /// abort a ZMODEM session" (7.2).
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Looking for ZPAD; each other byte is dropped.
    Hunt,
    /// After ZPAD: more ZPAD, then ZDLE.
    Pad,
    /// After ZPAD and ZDLE: the form.
    Dle,
    Hex,
    Bin,
    Data,
}

/// A byte once its escape is undone.
#[derive(Debug, Clone, Copy)]
enum Unescaped {
    Byte(u8),
    End(u8),
    /// Nothing yet: a ZDLE, a CAN after it, an XON or an XOFF.
    Nothing,
    Bad,
}

/// Reads headers and data subpackets out of a stream of bytes, as lrzsz's
/// `zgethdr` and `zdlread` do. After a header that data follows (ZFILE,
/// ZDATA, ZSINIT, ZCOMMAND, ZSTDERR), it reads data subpackets until ZCRCE
/// or ZCRCW, with the CRC of the header's form.
#[derive(Debug)]
pub struct Reader {
    state: State,
    /// CAN bytes in a row.
    cans: u8,
    /// A ZDLE came: the next byte is escaped.
    escaped: bool,
    /// Whether the header, or the data of its frame, has a CRC-32.
    crc32: bool,
    buf: Vec<u8>,
    crc: Vec<u8>,
    /// The end of the subpacket whose CRC is being read.
    end: Option<u8>,
}

impl Default for Reader {
    fn default() -> Self {
        Reader::new()
    }
}

impl Reader {
    pub fn new() -> Reader {
        Reader {
            state: State::Hunt,
            cans: 0,
            escaped: false,
            crc32: false,
            buf: Vec::new(),
            crc: Vec::new(),
            end: None,
        }
    }

    /// Whether it looks for the next header.
    pub fn hunting(&self) -> bool {
        self.state == State::Hunt
    }

    /// Drop what was read, and look for the next header: the data of a
    /// frame that is not wanted is skipped so.
    pub fn hunt(&mut self) {
        self.state = State::Hunt;
        self.escaped = false;
        self.buf.clear();
        self.crc.clear();
        self.end = None;
    }

    /// The next byte: an event, when one ends with it.
    pub fn push(&mut self, byte: u8) -> Option<Event> {
        if byte == CAN {
            self.cans += 1;
            if self.cans >= 5 {
                self.cans = 0;
                self.hunt();
                return Some(Event::Cancel);
            }
        } else {
            self.cans = 0;
        }
        match self.state {
            State::Hunt => {
                if (byte & 0x7f) == ZPAD {
                    self.state = State::Pad;
                }
                None
            }
            State::Pad => {
                match byte & 0x7f {
                    ZPAD | XON | XOFF => {}
                    ZDLE => self.state = State::Dle,
                    _ => self.state = State::Hunt,
                }
                None
            }
            State::Dle => {
                self.buf.clear();
                self.escaped = false;
                match byte & 0x7f {
                    ZHEX => self.state = State::Hex,
                    ZBIN => {
                        self.crc32 = false;
                        self.state = State::Bin;
                    }
                    ZBIN32 => {
                        self.crc32 = true;
                        self.state = State::Bin;
                    }
                    XON | XOFF => {}
                    _ => self.state = State::Hunt,
                }
                None
            }
            State::Hex => self.hex(byte),
            State::Bin => self.bin(byte),
            State::Data => self.data(byte),
        }
    }

    /// The 14 hex digits of a hex header.
    fn hex(&mut self, byte: u8) -> Option<Event> {
        let byte = byte & 0x7f;
        if byte == XON || byte == XOFF {
            return None;
        }
        let Some(digit) = hex_digit(byte) else {
            self.hunt();
            // A ZPAD may start the next header.
            if byte == ZPAD {
                self.state = State::Pad;
            }
            return Some(Event::Bad);
        };
        self.buf.push(digit);
        if self.buf.len() < 14 {
            return None;
        }
        let raw: Vec<u8> = self.buf.chunks(2).map(|pair| (pair[0] << 4) | pair[1]).collect();
        self.hunt();
        if crc16(&raw[..5]) != u16::from_be_bytes([raw[5], raw[6]]) {
            return Some(Event::Bad);
        }
        Some(self.after(Header { kind: raw[0], bytes: [raw[1], raw[2], raw[3], raw[4]], form: Form::Hex }))
    }

    /// The escaped type, four bytes and CRC of a binary header.
    fn bin(&mut self, byte: u8) -> Option<Event> {
        match self.unescape(byte) {
            Unescaped::Nothing => None,
            Unescaped::Byte(b) => {
                self.buf.push(b);
                let crc_len = if self.crc32 { 4 } else { 2 };
                if self.buf.len() < 5 + crc_len {
                    return None;
                }
                let got = std::mem::take(&mut self.buf);
                self.hunt();
                let holds = if self.crc32 {
                    crc32(&got[..5]) == u32::from_le_bytes([got[5], got[6], got[7], got[8]])
                } else {
                    crc16(&got[..5]) == u16::from_be_bytes([got[5], got[6]])
                };
                if !holds {
                    return Some(Event::Bad);
                }
                let form = if self.crc32 { Form::Bin32 } else { Form::Bin16 };
                Some(self.after(Header { kind: got[0], bytes: [got[1], got[2], got[3], got[4]], form }))
            }
            Unescaped::End(_) | Unescaped::Bad => Some(self.bad()),
        }
    }

    /// After a header whose frame has data, read its subpackets.
    fn after(&mut self, header: Header) -> Event {
        if matches!(header.kind, ZFILE | ZDATA | ZSINIT | ZCOMMAND | ZSTDERR) {
            self.hunt();
            self.state = State::Data;
            self.crc32 = header.form == Form::Bin32;
        }
        Event::Header(header)
    }

    /// The bytes of a data subpacket, its end, and its CRC.
    fn data(&mut self, byte: u8) -> Option<Event> {
        let got = self.unescape(byte);
        match (self.end, got) {
            (_, Unescaped::Nothing) => None,
            (None, Unescaped::Byte(b)) => {
                if self.buf.len() >= MOST_DATA {
                    return Some(self.bad());
                }
                self.buf.push(b);
                None
            }
            (None, Unescaped::End(end)) => {
                self.end = Some(end);
                None
            }
            (Some(end), Unescaped::Byte(b)) => {
                self.crc.push(b);
                let crc_len = if self.crc32 { 4 } else { 2 };
                if self.crc.len() < crc_len {
                    return None;
                }
                let holds = if self.crc32 {
                    let crc = !crc32_update(crc32_update(!0, &self.buf), &[end]);
                    crc == u32::from_le_bytes([self.crc[0], self.crc[1], self.crc[2], self.crc[3]])
                } else {
                    let crc = crc16_update(crc16_update(0, &self.buf), &[end]);
                    crc == u16::from_be_bytes([self.crc[0], self.crc[1]])
                };
                if !holds {
                    return Some(self.bad());
                }
                let data = std::mem::take(&mut self.buf);
                self.crc.clear();
                self.end = None;
                if end == ZCRCE || end == ZCRCW {
                    self.state = State::Hunt;
                }
                Some(Event::Data { data, end })
            }
            (_, Unescaped::End(_)) | (_, Unescaped::Bad) => Some(self.bad()),
        }
    }

    /// One byte with its escape undone: "The receiving program decodes any
    /// sequence of ZDLE followed by a byte with bit 6 set and bit 5 reset"
    /// (7.2); ZCRCE to ZCRCW end a subpacket, and ZRUB0 and ZRUB1 are DEL.
    fn unescape(&mut self, byte: u8) -> Unescaped {
        if !self.escaped {
            return match byte {
                ZDLE => {
                    self.escaped = true;
                    Unescaped::Nothing
                }
                XON | XOFF | 0x91 | 0x93 => Unescaped::Nothing,
                _ => Unescaped::Byte(byte),
            };
        }
        let got = match byte {
            // More CAN after a ZDLE: `push` counts them.
            CAN | XON | XOFF | 0x91 | 0x93 => return Unescaped::Nothing,
            ZCRCE | ZCRCG | ZCRCQ | ZCRCW => Unescaped::End(byte),
            ZRUB0 => Unescaped::Byte(0x7f),
            ZRUB1 => Unescaped::Byte(0xff),
            _ if (byte & 0x60) == 0x40 => Unescaped::Byte(byte ^ 0x40),
            _ => Unescaped::Bad,
        };
        self.escaped = false;
        got
    }

    fn bad(&mut self) -> Event {
        self.hunt();
        Event::Bad
    }
}
