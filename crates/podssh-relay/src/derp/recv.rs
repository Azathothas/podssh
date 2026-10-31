//! The receiving half of a link: the segments that arrive, in any order and
//! some twice, given to the application once each and in order; and the
//! acknowledgements that tell the sender what arrived, with up to
//! [`MAX_RANGES`] ranges held past a gap, and the room left.
//!
//! A segment in order is acknowledged with the next, or after
//! [`ACK_DELAY`]; one past a gap, a repeated one, or one that finds no room
//! is acknowledged at once, so that the sender learns of a loss in one round
//! trip. A reader that does not read closes the window, and the sender
//! waits; a window that opens again is said at once.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use tokio::time::Instant;

use super::packet::{Ack, MAX_RANGES};
use super::send::{SEGMENT, SPAN};

/// The bytes held for a reader, in order or past a gap, past which the
/// window closes.
pub const RECV_BUFFER: usize = 1 << 20;
/// How long the acknowledgement of a segment in order may wait for the next
/// segment.
pub const ACK_DELAY: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Due {
    No,
    At(Instant),
    Now,
}

#[derive(Debug)]
pub struct Receiver {
    /// The number of the next segment in order.
    expected: u64,
    /// The segments past a gap, by number, with their end flag.
    held: BTreeMap<u64, (Vec<u8>, bool)>,
    held_bytes: usize,
    /// The bytes in order that the reader has not read, and how much of the
    /// first is read.
    ready: VecDeque<Vec<u8>>,
    front: usize,
    ready_bytes: usize,
    /// The end of this direction came, after each byte before it.
    fin: bool,
    due: Due,
    in_order: u32,
    /// The window of the last acknowledgement.
    told: u64,
}

impl Default for Receiver {
    fn default() -> Receiver {
        Receiver {
            expected: 0,
            held: BTreeMap::new(),
            held_bytes: 0,
            ready: VecDeque::new(),
            front: 0,
            ready_bytes: 0,
            fin: false,
            due: Due::No,
            in_order: 0,
            told: SPAN,
        }
    }
}

impl Receiver {
    pub fn new() -> Receiver {
        Receiver::default()
    }

    /// A segment arrived.
    pub fn on_data(&mut self, seq: u64, fin: bool, data: Vec<u8>, now: Instant) {
        let room = self.ready_bytes + self.held_bytes + data.len() <= RECV_BUFFER + SEGMENT;
        let repeat = seq < self.expected || self.held.contains_key(&seq);
        let outside = self.fin || seq >= self.expected + SPAN;
        // A repeat, one past the end or past what is held, or one with no
        // room: dropped, and where this side is goes back at once.
        if repeat || outside || !room {
            self.due = Due::Now;
            return;
        }
        if seq > self.expected {
            self.held_bytes += data.len();
            self.held.insert(seq, (data, fin));
            self.due = Due::Now;
            return;
        }
        let filled = !self.held.is_empty();
        self.deliver(data, fin);
        while let Some((data, fin)) = self.held.remove(&self.expected) {
            self.held_bytes -= data.len();
            self.deliver(data, fin);
        }
        self.in_order += 1;
        if filled || self.fin || self.in_order >= 2 {
            self.due = Due::Now;
        } else if self.due == Due::No {
            self.due = Due::At(now + ACK_DELAY);
        }
    }

    fn deliver(&mut self, data: Vec<u8>, fin: bool) {
        self.expected += 1;
        if !data.is_empty() {
            self.ready_bytes += data.len();
            self.ready.push_back(data);
        }
        if fin {
            self.fin = true;
            // Nothing follows the end.
            self.held.clear();
            self.held_bytes = 0;
        }
    }

    /// The bytes in order, into `buf`: how many.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let before = self.window();
        let mut n = 0;
        while n < buf.len() {
            let Some(first) = self.ready.front() else { break };
            let len = first.len();
            let take = (len - self.front).min(buf.len() - n);
            buf[n..n + take].copy_from_slice(&first[self.front..self.front + take]);
            n += take;
            self.front += take;
            if self.front == len {
                self.ready.pop_front();
                self.front = 0;
            }
        }
        self.ready_bytes -= n;
        // The sender waits on a window that closed: it hears at once that
        // it opened.
        if self.told < 2 && self.window() >= 4 && self.window() > before {
            self.due = Due::Now;
        }
        n
    }

    /// The segments that the sender may send from the next in order.
    pub fn window(&self) -> u64 {
        let free = RECV_BUFFER.saturating_sub(self.ready_bytes + self.held_bytes) / SEGMENT;
        (free as u64).min(SPAN)
    }

    /// The acknowledgement that is due now, if one is.
    pub fn ack(&mut self, now: Instant) -> Option<Ack> {
        match self.due {
            Due::No => return None,
            Due::At(at) if now < at => return None,
            _ => {}
        }
        self.due = Due::No;
        self.in_order = 0;
        let window = self.window();
        self.told = window;
        Some(Ack { next: self.expected, window: window as u16, ranges: self.ranges() })
    }

    /// An acknowledgement now, though nothing new came: the answer to an
    /// `OPEN`.
    pub fn ack_now(&mut self) {
        self.due = Due::Now;
    }

    /// When a delayed acknowledgement is due.
    pub fn deadline(&self) -> Option<Instant> {
        match self.due {
            Due::At(at) => Some(at),
            _ => None,
        }
    }

    /// Whether an acknowledgement waits to go out at once.
    pub fn wants_ack(&self) -> bool {
        self.due == Due::Now
    }

    /// The runs of segments held past the gap: the highest, which tells the
    /// sender of its latest segment that arrived, and the lowest, which it
    /// fills first.
    fn ranges(&self) -> Vec<(u64, u64)> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for &seq in self.held.keys() {
            match runs.last_mut() {
                Some((_, end)) if *end == seq => *end += 1,
                _ => runs.push((seq, seq + 1)),
            }
        }
        if runs.len() > MAX_RANGES {
            let last = runs[runs.len() - 1];
            runs.truncate(MAX_RANGES - 1);
            runs.push(last);
        }
        runs
    }

    pub fn readable(&self) -> bool {
        self.ready_bytes > 0
    }

    /// The end came, and each byte before it was read.
    pub fn at_end(&self) -> bool {
        self.fin && self.ready_bytes == 0
    }

    /// The bytes held, in order and past a gap.
    pub fn buffered(&self) -> usize {
        self.ready_bytes + self.held_bytes
    }
}
