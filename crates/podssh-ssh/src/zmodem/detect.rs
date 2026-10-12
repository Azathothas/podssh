//! The start of a transfer in the server's output. `sz` sends `rz\r` and
//! the hex header ZRQINIT: `**`, ZDLE, `B00` and twelve more hex digits
//! (8.1: the output "may be scanned for B00 indicating a ZRQINIT header").
//! `rz` sends the hex header ZRINIT, `B01`, after its words "rz waiting to
//! receive." trzsz and zssh look for the same two. A start counts only when
//! its 14 hex digits are whole and their CRC holds, so that text which only
//! looks like one passes as it came.
//!
//! Each byte that cannot begin a start passes on at once. The bytes of a
//! possible start that the end of a message cut wait for the next message,
//! [`HOLD`] at most.

use std::time::{Duration, Instant};

use super::wire::{crc16, hex_digit, Form, Header, ZDLE, ZHEX, ZPAD, ZRQINIT};

/// How long the start of a possible header waits for the rest of it.
pub const HOLD: Duration = Duration::from_millis(100);

/// The bytes before the type: ZPAD ZPAD ZDLE ZHEX.
const LEAD: [u8; 4] = [ZPAD, ZPAD, ZDLE, ZHEX];

/// A whole start: the lead, then 14 hex digits (the type, the four bytes
/// and the CRC-16).
const WHOLE: usize = LEAD.len() + 14;

/// What started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// ZRQINIT: `sz` on the server offers files.
    Offer(Header),
    /// ZRINIT: `rz` on the server waits for files; its flags are the
    /// header's.
    Ready(Header),
}

/// What a scan found: the bytes to show, a start, and the bytes after it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    pub shown: Vec<u8>,
    pub start: Option<Start>,
    pub rest: Vec<u8>,
}

/// Watches the output for a start.
#[derive(Debug, Default)]
pub struct Detector {
    held: Vec<u8>,
    since: Option<Instant>,
}

enum Match {
    No,
    Partial,
    Whole(Start),
}

impl Detector {
    pub fn new() -> Detector {
        Detector::default()
    }

    /// The next output: what shows, and a start when one is whole. The
    /// bytes after a start are the protocol's, not the terminal's.
    pub fn feed(&mut self, data: &[u8], now: Instant) -> Scan {
        let mut input = std::mem::take(&mut self.held);
        input.extend_from_slice(data);
        self.since = None;
        let mut scan = Scan::default();
        let mut at = 0;
        while let Some(found) = input[at..].iter().position(|&b| b == ZPAD) {
            let star = at + found;
            scan.shown.extend_from_slice(&input[at..star]);
            match matches(&input[star..]) {
                Match::No => {
                    scan.shown.push(ZPAD);
                    at = star + 1;
                }
                Match::Partial => {
                    self.held = input[star..].to_vec();
                    self.since = Some(now);
                    return scan;
                }
                Match::Whole(start) => {
                    scan.start = Some(start);
                    scan.rest = input[star + WHOLE..].to_vec();
                    return scan;
                }
            }
        }
        scan.shown.extend_from_slice(&input[at..]);
        scan
    }

    /// When the held bytes show, if nothing comes before.
    pub fn deadline(&self) -> Option<Instant> {
        self.since.map(|since| since + HOLD)
    }

    /// The held bytes, once they waited [`HOLD`]: they were no start.
    pub fn flush(&mut self, now: Instant) -> Vec<u8> {
        match self.deadline() {
            Some(due) if now >= due => {
                self.since = None;
                std::mem::take(&mut self.held)
            }
            _ => Vec::new(),
        }
    }
}

/// Whether `bytes`, from a ZPAD on, are a ZRQINIT or a ZRINIT.
fn matches(bytes: &[u8]) -> Match {
    for (i, &b) in bytes.iter().take(WHOLE).enumerate() {
        let fits = match i {
            0..=3 => b == LEAD[i],
            4 => b == b'0',
            5 => b == b'0' || b == b'1',
            _ => hex_digit(b).is_some(),
        };
        if !fits {
            return Match::No;
        }
    }
    if bytes.len() < WHOLE {
        return Match::Partial;
    }
    let digits: Vec<u8> = bytes[LEAD.len()..WHOLE].iter().filter_map(|&b| hex_digit(b)).collect();
    let raw: Vec<u8> = digits.chunks(2).map(|pair| (pair[0] << 4) | pair[1]).collect();
    if crc16(&raw[..5]) != u16::from_be_bytes([raw[5], raw[6]]) {
        return Match::No;
    }
    let header = Header { kind: raw[0], bytes: [raw[1], raw[2], raw[3], raw[4]], form: Form::Hex };
    Match::Whole(if header.kind == ZRQINIT { Start::Offer(header) } else { Start::Ready(header) })
}
