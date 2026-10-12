//! The side that sends (8.1 to 8.3): podssh answers `rz` on the server with
//! one file. ZFILE offers it; ZRPOS gives the position to send from, and
//! ZDATA's subpackets follow: ZCRCG while the receiver takes a stream, ZCRCW
//! where its buffer is full, and ZCRCE at the end, then ZEOF. A ZRINIT after
//! ZEOF says that the file is whole; ZFIN, its answer and "OO" end the
//! session. Each wait has [`WAIT`]; after it the last header goes again,
//! [`TRIES`] waits at most.

use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

use super::files::Outgoing;
use super::wire::{self, Escaper, Event, Header, Reader};
use super::{stop, Act, Ended, CANCEL, SUBPACKET, TRIES, WAIT};

/// The bytes of the file that one pull sends at most: a few subpackets, so
/// that the session reads the server's answers between them.
pub const CHUNK: usize = 16 * SUBPACKET;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// ZFILE went: ZRPOS or ZSKIP comes.
    File,
    /// Data goes.
    Stream,
    /// A ZCRCW went: ZACK comes.
    Ack,
    /// ZEOF went: ZRINIT comes.
    Eof,
    /// ZFIN went: ZFIN comes.
    Fin,
    Over,
}

/// The sending side of one session of `rz`.
#[derive(Debug)]
pub struct Sender<R> {
    reader: Reader,
    file: R,
    info: Outgoing,
    esc: Escaper,
    crc32: bool,
    /// The receiver's buffer: the bytes until a ZCRCW; 0 for a stream.
    window: u64,
    step: Step,
    offset: u64,
    since_ack: u64,
    /// A ZDATA header goes before the next subpacket.
    header: bool,
    /// The header or the frame that the step waits on, sent again after a
    /// wait.
    last: Vec<u8>,
    /// The position of the last ZRPOS.
    asked: Option<u64>,
    /// Waits, or the same ZRPOS, in a row.
    misses: u32,
    deadline: Option<Instant>,
}

impl<R: Read + Seek> Sender<R> {
    /// The sender of `file` to a receiver whose ZRINIT is `zrinit`, and
    /// ZFILE to send.
    pub fn new(file: R, info: Outgoing, zrinit: &Header, now: Instant) -> (Sender<R>, Vec<Act>) {
        let flags = zrinit.flags();
        // ZP0 and ZP1: the receiver's buffer, 0 when it takes a stream.
        let buffer = u64::from(u16::from_le_bytes([zrinit.bytes[0], zrinit.bytes[1]]));
        let streams = (flags & wire::CANFDX) != 0 && (flags & wire::CANOVIO) != 0;
        let window = match (buffer, streams) {
            (0, true) => 0,
            (0, false) => SUBPACKET as u64,
            (n, _) => n,
        };
        let mut sender = Sender {
            reader: Reader::new(),
            file,
            info,
            esc: Escaper::new((flags & wire::ESCCTL) != 0),
            crc32: (flags & wire::CANFC32) != 0,
            window,
            step: Step::File,
            offset: 0,
            since_ack: 0,
            header: true,
            last: Vec::new(),
            asked: None,
            misses: 0,
            deadline: None,
        };
        let zfile = sender.zfile();
        let first = sender.send(zfile, now);
        (sender, vec![first])
    }

    /// When [`Sender::timeout`] is due.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Whether data waits to go now: [`Sender::pull`] gives it.
    pub fn streaming(&self) -> bool {
        self.step == Step::Stream
    }

    /// The server's output.
    pub fn feed(&mut self, data: &[u8], now: Instant) -> Vec<Act> {
        let mut acts = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            if self.step == Step::Over {
                break;
            }
            if let Some(event) = self.reader.push(byte) {
                if let Some(ended) = self.event(event, now, &mut acts) {
                    self.step = Step::Over;
                    self.deadline = None;
                    acts.push(Act::End { ended, rest: data[i + 1..].to_vec() });
                    return acts;
                }
            }
        }
        acts
    }

    /// The next bytes of the file, as ZDATA's subpackets: [`CHUNK`] at most.
    pub fn pull(&mut self, now: Instant) -> Vec<Act> {
        if self.step != Step::Stream {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(CHUNK + CHUNK / 4);
        if std::mem::take(&mut self.header) {
            out.extend(self.esc.header(wire::ZDATA, wire::at(self.offset), self.crc32));
        }
        let mut buf = vec![0u8; SUBPACKET];
        while out.len() < CHUNK {
            let room = match self.window {
                0 => SUBPACKET,
                window => usize::try_from(window.saturating_sub(self.since_ack)).unwrap_or(SUBPACKET).min(SUBPACKET),
            };
            let n = match read_full(&mut self.file, &mut buf[..room]) {
                Ok(n) => n,
                Err(e) => {
                    self.step = Step::Over;
                    self.deadline = None;
                    return stop(format!("{}: {e}", self.info.name));
                }
            };
            self.offset += n as u64;
            self.since_ack += n as u64;
            if n < room {
                // The end of the file: ZCRCE, then ZEOF with the length (8.2).
                out.extend(self.esc.subpacket(&buf[..n], wire::ZCRCE, self.crc32));
                let eof = self.esc.header(wire::ZEOF, wire::at(self.offset), self.crc32);
                out.extend_from_slice(&eof);
                self.last = eof;
                self.step = Step::Eof;
                self.misses = 0;
                self.deadline = Some(now + WAIT);
                break;
            }
            if self.window > 0 && self.since_ack >= self.window {
                // The receiver's buffer is full: ZCRCW, and its ZACK (8.2).
                out.extend(self.esc.subpacket(&buf[..n], wire::ZCRCW, self.crc32));
                self.step = Step::Ack;
                self.deadline = Some(now + WAIT);
                break;
            }
            out.extend(self.esc.subpacket(&buf[..n], wire::ZCRCG, self.crc32));
        }
        vec![Act::Send(out), Act::Progress(self.offset)]
    }

    /// A wait that ran out: the last header again, or the end.
    pub fn timeout(&mut self, now: Instant) -> Vec<Act> {
        if self.deadline.is_none_or(|due| now < due) {
            return Vec::new();
        }
        self.misses += 1;
        if self.misses >= TRIES {
            let fin = self.step == Step::Fin;
            self.step = Step::Over;
            self.deadline = None;
            // ZEOF had its ZRINIT: the file is whole, and only the last words
            // of the session were lost.
            if fin {
                return vec![Act::End { ended: Ended::Done, rest: Vec::new() }];
            }
            let tries = format!("{TRIES} tries of {} s", WAIT.as_secs());
            return stop(format!("no answer from the server in {tries}"));
        }
        if self.step == Step::Ack {
            // "the sender to remain silent until the receiver times out"
            // (14.3): its ZRPOS comes.
            self.deadline = Some(now + WAIT);
            return Vec::new();
        }
        let again = self.last.clone();
        vec![self.send(again, now)]
    }

    /// Stop here: the cancel sequence, and the end.
    pub fn cancel(&mut self, why: &str) -> Vec<Act> {
        self.step = Step::Over;
        self.deadline = None;
        stop(why.to_string())
    }

    fn send(&mut self, bytes: Vec<u8>, now: Instant) -> Act {
        self.last.clone_from(&bytes);
        self.deadline = Some(now + WAIT);
        Act::Send(bytes)
    }

    /// ZFILE: a binary header with ZCBIN (binary, no change of line ends)
    /// and no option for a name that exists, so that the receiver's own rule
    /// holds; then the data, ending in ZCRCW.
    fn zfile(&mut self) -> Vec<u8> {
        let mut out = self.esc.header(wire::ZFILE, [0, 0, 0, wire::ZCBIN], self.crc32);
        let data = self.info.zfile();
        out.extend(self.esc.subpacket(&data, wire::ZCRCW, self.crc32));
        out
    }

    fn event(&mut self, event: Event, now: Instant, acts: &mut Vec<Act>) -> Option<Ended> {
        let header = match event {
            Event::Cancel => return Some(Ended::Stopped("the server cancelled the transfer".into())),
            Event::Header(header) => header,
            // A receiver sends headers only.
            Event::Data { .. } | Event::Bad => return None,
        };
        let sending = matches!(self.step, Step::File | Step::Stream | Step::Ack | Step::Eof);
        match header.kind {
            wire::ZRPOS if sending => return self.seek(u64::from(header.position()), acts),
            wire::ZRINIT if self.step == Step::File => {
                // The receiver did not read ZFILE: again.
                self.misses += 1;
                if self.misses >= TRIES {
                    acts.push(Act::Send(CANCEL.to_vec()));
                    return Some(Ended::Stopped(format!("the server did not take ZFILE in {TRIES} tries")));
                }
                let zfile = self.zfile();
                acts.push(self.send(zfile, now));
            }
            wire::ZRINIT if self.step == Step::Eof => {
                // The file is whole (8.2), and ZFIN ends the session (8.3).
                acts.push(Act::Close(self.offset));
                self.fin(now, acts);
            }
            wire::ZSKIP if sending => {
                acts.push(Act::Skipped);
                self.fin(now, acts);
            }
            wire::ZACK if self.step == Step::Ack => {
                self.step = Step::Stream;
                self.header = true;
                self.since_ack = 0;
                self.deadline = None;
            }
            // The CRC-32 of the file's first bytes, or of all of it for 0, as
            // lrzsz's `sz` answers it.
            wire::ZCRC if self.step == Step::File => match self.file_crc(u64::from(header.position())) {
                Ok(crc) => acts.push(Act::Send(self.esc.header(wire::ZCRC, crc.to_le_bytes(), self.crc32))),
                Err(e) => {
                    acts.push(Act::Send(CANCEL.to_vec()));
                    return Some(Ended::Stopped(format!("{}: {e}", self.info.name)));
                }
            },
            // "it sends two characters, "OO" (Over and Out)" (8.3).
            wire::ZFIN if self.step == Step::Fin => {
                acts.push(Act::Send(b"OO".to_vec()));
                return Some(Ended::Done);
            }
            wire::ZFIN => return Some(Ended::Stopped("the server ended the transfer".into())),
            wire::ZNAK => acts.push(Act::Send(self.last.clone())),
            wire::ZCHALLENGE => acts.push(Act::Send(wire::hex_header(wire::ZACK, header.bytes))),
            wire::ZABORT | wire::ZFERR | wire::ZCAN => {
                return Some(Ended::Stopped(format!("the server ended the transfer ({})", wire::name(header.kind))));
            }
            _ => {}
        }
        None
    }

    fn fin(&mut self, now: Instant, acts: &mut Vec<Act>) {
        self.misses = 0;
        self.step = Step::Fin;
        acts.push(self.send(wire::hex_header(wire::ZFIN, [0; 4]), now));
    }

    /// ZRPOS: send from `position` on (9.1). The same position asked for
    /// again and again ends the transfer: its bytes do not cross.
    fn seek(&mut self, position: u64, acts: &mut Vec<Act>) -> Option<Ended> {
        if self.asked == Some(position) && self.step != Step::File {
            self.misses += 1;
            if self.misses >= TRIES {
                acts.push(Act::Send(CANCEL.to_vec()));
                return Some(Ended::Stopped(format!("the server asked for the bytes at {position} {TRIES} times")));
            }
        } else {
            self.misses = 0;
        }
        self.asked = Some(position);
        if let Err(e) = self.file.seek(SeekFrom::Start(position)) {
            acts.push(Act::Send(CANCEL.to_vec()));
            return Some(Ended::Stopped(format!("{}: {e}", self.info.name)));
        }
        self.offset = position;
        self.since_ack = 0;
        self.header = true;
        self.step = Step::Stream;
        self.deadline = None;
        None
    }

    fn file_crc(&mut self, count: u64) -> std::io::Result<u32> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut crc = !0u32;
        let mut left = if count == 0 { u64::MAX } else { count };
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let want = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
            let n = self.file.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            crc = wire::crc32_update(crc, &buf[..n]);
            left -= n as u64;
        }
        self.file.seek(SeekFrom::Start(self.offset))?;
        Ok(!crc)
    }
}

/// Read until `buf` is full or the file ends.
fn read_full(file: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match file.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}
