//! The side that receives (8.1 to 8.3): podssh answers `sz` on the server.
//! It sends ZRINIT; it takes the file that ZFILE offers once its caller
//! agrees, with ZRPOS 0; it takes ZDATA's subpackets at its own position,
//! each with its CRC; and it closes the file at a ZEOF whose position is the
//! length that came. ZFIN ends the session, and the sender's "OO" is its
//! last word. Each wait has [`WAIT`]; after it the last header goes again,
//! [`TRIES`] waits at most.

use std::time::Instant;

use super::wire::{self, Event, Header, Reader};
use super::{stop, Act, Ended, CANCEL, TRIES, WAIT};

/// ZRINIT's flags: full duplex, I/O during the disk's work, and CRC-32, as
/// lrzsz's `rz` sends them (`B0100000023`).
pub const FLAGS: u8 = wire::CANFDX | wire::CANOVIO | wire::CANFC32;

/// What ZFILE offers (the spec's section 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The pathname as sent: "conventionally, the file name".
    pub name: String,
    /// "the number of data bytes in the file", when it was sent.
    pub size: Option<u64>,
    /// The time of the last change, seconds since 1970.
    pub mtime: Option<u64>,
    /// The file mode.
    pub mode: Option<u32>,
}

impl Offer {
    /// ZFILE's data subpacket: the pathname and a NUL, then the length in
    /// decimal, the time and the mode in octal, separated by spaces. A field
    /// that is missing or 0 is none.
    pub fn parse(data: &[u8]) -> Option<Offer> {
        let nul = data.iter().position(|&b| b == 0)?;
        let name = String::from_utf8_lossy(&data[..nul]).into_owned();
        let rest = data[nul + 1..].split(|&b| b == 0).next().unwrap_or_default();
        let text = String::from_utf8_lossy(rest);
        let mut fields = text.split_ascii_whitespace();
        let size = fields.next().and_then(|f| f.parse::<u64>().ok());
        let mtime = fields.next().and_then(|f| u64::from_str_radix(f, 8).ok()).filter(|&t| t > 0);
        let mode = fields.next().and_then(|f| u32::from_str_radix(f, 8).ok()).filter(|&m| m > 0);
        Some(Offer { name, size, mtime, mode })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// ZRINIT went: ZFILE or ZFIN comes.
    Init,
    /// ZFILE came: the caller decides.
    Offered,
    /// ZRPOS went: the file's data comes.
    File,
    /// ZFIN went: the sender's "OO" comes.
    Fin,
    Over,
}

/// The receiving side of one session of `sz`.
#[derive(Debug)]
pub struct Receiver {
    reader: Reader,
    step: Step,
    /// The header of the frame whose data subpacket comes next.
    pending: Option<u8>,
    /// The bytes of the file so far.
    offset: u64,
    /// The header that the step waits on, sent again after a wait.
    last: Vec<u8>,
    /// Waits and bad frames in a row.
    misses: u32,
    deadline: Option<Instant>,
    /// The `O` bytes after ZFIN.
    outs: u8,
}

impl Receiver {
    /// The receiver, and ZRINIT to send.
    pub fn new(now: Instant) -> (Receiver, Vec<Act>) {
        let mut receiver = Receiver {
            reader: Reader::new(),
            step: Step::Init,
            pending: None,
            offset: 0,
            last: Vec::new(),
            misses: 0,
            deadline: None,
            outs: 0,
        };
        let first = receiver.send(zrinit(), now);
        (receiver, vec![first])
    }

    /// When [`Receiver::timeout`] is due.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The server's output.
    pub fn feed(&mut self, data: &[u8], now: Instant) -> Vec<Act> {
        let mut acts = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            if self.step == Step::Over {
                break;
            }
            if self.step == Step::Fin && self.reader.hunting() {
                match byte {
                    b'O' => {
                        self.outs += 1;
                        if self.outs == 2 {
                            return self.over(acts, Ended::Done, &data[i + 1..]);
                        }
                        continue;
                    }
                    // A ZFIN that the sender sends again, and the end of a
                    // hex header.
                    wire::ZPAD | b'\r' | b'\n' | 0x8a | wire::XON => {}
                    // Anything else: the sender is gone, and this is the
                    // shell's.
                    _ => return self.over(acts, Ended::Done, &data[i..]),
                }
            }
            if let Some(event) = self.reader.push(byte) {
                if let Some(ended) = self.event(event, now, &mut acts) {
                    return self.over(acts, ended, &data[i + 1..]);
                }
            }
        }
        acts
    }

    /// The caller's answer to an offer: the file from its start, or none.
    pub fn decide(&mut self, take: bool, now: Instant) -> Vec<Act> {
        if self.step != Step::Offered {
            return Vec::new();
        }
        self.misses = 0;
        if take {
            self.step = Step::File;
            self.offset = 0;
            vec![self.send(zrpos(0), now)]
        } else {
            self.step = Step::Init;
            vec![self.send(wire::hex_header(wire::ZSKIP, [0; 4]), now)]
        }
    }

    /// A wait that ran out: the last header again, or the end.
    pub fn timeout(&mut self, now: Instant) -> Vec<Act> {
        if self.deadline.is_none_or(|due| now < due) {
            return Vec::new();
        }
        if self.step == Step::Fin {
            // "The receiver waits briefly for the "O" characters, then exits
            // whether they were received or not" (8.3).
            return self.over(Vec::new(), Ended::Done, &[]);
        }
        let mut acts = Vec::new();
        match self.miss(now, &mut acts) {
            Some(ended) => self.over(acts, ended, &[]),
            None => acts,
        }
    }

    /// Stop here: the cancel sequence, and the end.
    pub fn cancel(&mut self, why: &str) -> Vec<Act> {
        self.step = Step::Over;
        self.deadline = None;
        stop(why.to_string())
    }

    fn over(&mut self, mut acts: Vec<Act>, ended: Ended, rest: &[u8]) -> Vec<Act> {
        self.step = Step::Over;
        self.deadline = None;
        acts.push(Act::End { ended, rest: rest.to_vec() });
        acts
    }

    fn send(&mut self, header: Vec<u8>, now: Instant) -> Act {
        self.last.clone_from(&header);
        self.deadline = Some(now + WAIT);
        Act::Send(header)
    }

    /// A wait with no answer, or a bad frame: the last header again, or,
    /// at the position of the file, ZRPOS (9.1); after [`TRIES`], the end.
    fn miss(&mut self, now: Instant, acts: &mut Vec<Act>) -> Option<Ended> {
        self.misses += 1;
        if self.misses >= TRIES {
            acts.push(Act::Send(CANCEL.to_vec()));
            let tries = format!("{TRIES} tries of {} s", WAIT.as_secs());
            return Some(Ended::Stopped(format!("nothing good came from the server in {tries}")));
        }
        let again = if self.step == Step::File { zrpos(self.offset) } else { self.last.clone() };
        acts.push(self.send(again, now));
        None
    }

    fn event(&mut self, event: Event, now: Instant, acts: &mut Vec<Act>) -> Option<Ended> {
        match event {
            Event::Cancel => Some(Ended::Stopped("the server cancelled the transfer".into())),
            Event::Bad if matches!(self.step, Step::Init | Step::File) => {
                self.pending = None;
                self.miss(now, acts)
            }
            Event::Bad => None,
            Event::Header(header) => self.header(header, now, acts),
            Event::Data { data, end } => self.data(data, end, now, acts),
        }
    }

    fn header(&mut self, header: Header, now: Instant, acts: &mut Vec<Act>) -> Option<Ended> {
        self.pending = None;
        match header.kind {
            // "If the receiving program receives a ZRQINIT header, it
            // resends the ZRINIT header" (8.1).
            wire::ZRQINIT => {
                if self.step == Step::Init {
                    acts.push(self.send(zrinit(), now));
                }
            }
            wire::ZSINIT => self.pending = Some(wire::ZSINIT),
            wire::ZFILE if self.step == Step::Init => self.pending = Some(wire::ZFILE),
            wire::ZDATA if self.step == Step::File => {
                if u64::from(header.position()) == self.offset {
                    self.pending = Some(wire::ZDATA);
                    self.deadline = Some(now + WAIT);
                } else {
                    // "If they do not agree, a ZRPOS error response is
                    // generated to force the sender to the right position
                    // within the file" (8.2).
                    self.reader.hunt();
                    acts.push(self.send(zrpos(self.offset), now));
                }
            }
            // A frame that is not wanted now: its data is skipped.
            wire::ZFILE | wire::ZDATA => self.reader.hunt(),
            wire::ZEOF => {
                // "The receiver should ignore a ZEOF with an offset that does
                // not match the current file length" (the spec's notes of
                // 1987-07-31).
                if self.step == Step::File && u64::from(header.position()) == self.offset {
                    acts.push(Act::Close(self.offset));
                    self.step = Step::Init;
                    self.offset = 0;
                    self.misses = 0;
                    acts.push(self.send(zrinit(), now));
                }
            }
            // "The receiver acknowledges this with its own ZFIN header" (8.3).
            wire::ZFIN => {
                self.step = Step::Fin;
                self.outs = 0;
                acts.push(self.send(wire::hex_header(wire::ZFIN, [0; 4]), now));
            }
            // lrzsz's answers: no count of free space, and the challenge's
            // number back.
            wire::ZFREECNT => acts.push(Act::Send(wire::hex_header(wire::ZACK, [0xff; 4]))),
            wire::ZCHALLENGE => acts.push(Act::Send(wire::hex_header(wire::ZACK, header.bytes))),
            wire::ZNAK => acts.push(Act::Send(self.last.clone())),
            wire::ZCOMMAND => {
                acts.push(Act::Send(CANCEL.to_vec()));
                return Some(Ended::Stopped("the server asked to run a command here, which podssh refuses".into()));
            }
            wire::ZABORT | wire::ZFERR | wire::ZCAN => {
                return Some(Ended::Stopped(format!("the server ended the transfer ({})", wire::name(header.kind))));
            }
            _ => {}
        }
        None
    }

    fn data(&mut self, data: Vec<u8>, end: u8, now: Instant, acts: &mut Vec<Act>) -> Option<Ended> {
        let pending = self.pending;
        if end == wire::ZCRCE || end == wire::ZCRCW {
            self.pending = None;
        }
        match pending {
            // The attention string is not used: podssh never interrupts the
            // sender. lrzsz's `rz` answers ZSINIT with ZACK 1.
            Some(wire::ZSINIT) => acts.push(Act::Send(wire::hex_header(wire::ZACK, wire::at(1)))),
            Some(wire::ZFILE) => match Offer::parse(&data) {
                Some(offer) => {
                    self.step = Step::Offered;
                    self.deadline = None;
                    acts.push(Act::Offer(offer));
                }
                None => acts.push(self.send(wire::hex_header(wire::ZSKIP, [0; 4]), now)),
            },
            Some(wire::ZDATA) => {
                self.misses = 0;
                self.offset += data.len() as u64;
                if self.offset > u64::from(u32::MAX) {
                    acts.push(Act::Send(CANCEL.to_vec()));
                    return Some(Ended::Stopped("the file passed 4 GiB, the end of ZMODEM's positions".into()));
                }
                acts.push(Act::Write(data));
                acts.push(Act::Progress(self.offset));
                self.deadline = Some(now + WAIT);
                // "ZCRCQ data subpackets expect a ZACK response with the
                // receiver's file offset" (8.2), and so do ZCRCW's.
                if end == wire::ZCRCQ || end == wire::ZCRCW {
                    acts.push(Act::Send(wire::hex_header(wire::ZACK, wire::at(self.offset))));
                }
            }
            _ => {}
        }
        None
    }
}

/// ZRINIT, with [`FLAGS`] and no limit of the buffer (ZP0 and ZP1 are 0).
fn zrinit() -> Vec<u8> {
    wire::hex_header(wire::ZRINIT, [0, 0, 0, FLAGS])
}

fn zrpos(offset: u64) -> Vec<u8> {
    wire::hex_header(wire::ZRPOS, wire::at(offset))
}
