//! A ring of a kept shell's output (T-159): the last bytes, at most its
//! capacity, given from a boundary of the grammar (T-221). It drops its
//! oldest bytes only up to a boundary, so the first byte that it gives after
//! dropped bytes starts clean, and a client that attaches sees no part of a
//! sequence as text.

use std::collections::VecDeque;
use std::time::Instant;

use super::{Boundary, Tracker};

/// The ring keeps about this many boundaries: one for each capacity / MARKS
/// bytes, the first after a broken sequence, and the newest. A cut then
/// drops at most about capacity / MARKS bytes more than it must, and a ring
/// of text does not keep a boundary for each byte.
const MARKS: usize = 256;

/// The last bytes of a stream, from a boundary.
#[derive(Debug, Clone)]
pub struct Ring {
    bytes: VecDeque<u8>,
    /// The offset of the first byte held.
    first: u64,
    capacity: usize,
    /// The least distance between two marks.
    gap: u64,
    tracker: Tracker,
    /// Boundaries among the bytes held, oldest first.
    marks: VecDeque<u64>,
    /// The newest boundary, which the gap may have left out of the marks.
    newest: Option<u64>,
}

impl Ring {
    /// A ring that holds `capacity` bytes at most (1 at least).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Ring {
            bytes: VecDeque::new(),
            first: 0,
            capacity,
            gap: capacity.div_ceil(MARKS) as u64,
            tracker: Tracker::new(),
            marks: VecDeque::new(),
            newest: None,
        }
    }

    /// Output that came at `now`.
    pub fn push(&mut self, chunk: &[u8], now: Instant) {
        let (marks, newest, gap) = (&mut self.marks, &mut self.newest, self.gap);
        self.tracker.feed(chunk, now, |b: Boundary| {
            if b.restart || marks.back().is_none_or(|&last| b.at >= last + gap) {
                marks.push_back(b.at);
            }
            *newest = Some(b.at);
        });
        self.bytes.extend(chunk);
        self.trim();
    }

    /// Drops the oldest bytes past the capacity, and on to the first
    /// boundary left. With none left, it keeps the last `capacity` bytes,
    /// and gives none of them until a boundary comes.
    fn trim(&mut self) {
        let from = self.end().saturating_sub(self.capacity as u64);
        if from <= self.first {
            return;
        }
        while self.marks.front().is_some_and(|&m| m < from) {
            self.marks.pop_front();
        }
        if self.marks.is_empty() {
            if let Some(newest) = self.newest.filter(|&n| n >= from) {
                self.marks.push_back(newest);
            }
        }
        let to = self.marks.front().copied().unwrap_or(from);
        self.bytes.drain(..(to - self.first) as usize);
        self.first = to;
    }

    /// The offset of the first byte that [`Ring::kept`] gives, a boundary;
    /// `None` while no byte held starts clean.
    pub fn start(&self) -> Option<u64> {
        self.marks.front().copied()
    }

    /// The offset after the last byte pushed.
    pub fn end(&self) -> u64 {
        self.first + self.bytes.len() as u64
    }

    /// The bytes from [`Ring::start`] on: what a client that attaches gets.
    pub fn kept(&self) -> Vec<u8> {
        match self.start() {
            Some(start) => self.bytes.range((start - self.first) as usize..).copied().collect(),
            None => Vec::new(),
        }
    }

    /// The bytes held, never more than the capacity.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammar::BROKEN_AFTER;

    #[test]
    fn the_ring_keeps_its_capacity_from_a_boundary() {
        let mut ring = Ring::new(8);
        let now = Instant::now();
        // The title's OSC holds no boundary: the ring drops it whole.
        ring.push(b"ab\x1b]0;a title\x07cdefgh", now);
        assert!(ring.len() <= 8, "{} bytes held", ring.len());
        assert_eq!(ring.kept(), b"cdefgh");
        assert_eq!(ring.start(), Some(14));
        assert_eq!(ring.end(), 20);
    }

    #[test]
    fn a_ring_with_no_boundary_left_gives_nothing_until_one_comes() {
        let mut ring = Ring::new(4);
        let now = Instant::now();
        ring.push(b"\x1b]0;a long title", now);
        assert!(ring.len() <= 4);
        assert_eq!(ring.start(), None);
        assert_eq!(ring.kept(), b"");
        ring.push(b"\x07xy", now);
        assert_eq!(ring.kept(), b"xy");
    }

    #[test]
    fn a_character_cut_by_the_capacity_is_dropped_whole() {
        // é is two bytes and the euro sign three: a cut inside either gives
        // the next character.
        let mut ring = Ring::new(4);
        ring.push("a\u{e9}\u{20ac}b".as_bytes(), Instant::now());
        assert_eq!(ring.kept(), "\u{20ac}b".as_bytes());
        let mut ring = Ring::new(3);
        ring.push("a\u{e9}\u{20ac}b".as_bytes(), Instant::now());
        assert_eq!(ring.kept(), b"b");
    }

    #[test]
    fn the_ring_never_holds_more_than_its_capacity_and_drops_few_bytes_more() {
        let now = Instant::now();
        let line = "\x1b[1;32muser@host\x1b[0m:~$ ls \u{65e5}\u{672c}\r\n".as_bytes();
        for capacity in [1, 7, 64, 1000, 5000] {
            let mut ring = Ring::new(capacity);
            for n in 0..400 {
                ring.push(&line[..n % line.len() + 1], now);
                ring.push(&line[n % line.len() + 1..], now);
                assert!(ring.len() <= capacity, "capacity {capacity}: {} bytes", ring.len());
                assert!(ring.marks.len() <= MARKS + 2, "capacity {capacity}: {} marks", ring.marks.len());
            }
            let start = ring.start().expect("a line ends at a boundary");
            // The marks are a gap apart: the cut drops at most a gap and the
            // longest sequence more than it had to.
            let had_to = ring.end().saturating_sub(capacity as u64);
            assert!(start >= had_to);
            assert!(start - had_to <= ring.gap + line.len() as u64, "capacity {capacity}: {start} for {had_to}");
        }
    }

    #[test]
    fn a_repaint_after_a_broken_sequence_starts_what_is_kept() {
        let t0 = Instant::now();
        let mut ring = Ring::new(24);
        ring.push(b"$ \x1b[38;5", t0);
        // The program said nothing for 10 s: the colour never ends, and the
        // bytes up to the repaint mean nothing.
        ring.push(b"junk\x1b[2Jscreen", t0 + BROKEN_AFTER);
        ring.push(b" and more", t0 + BROKEN_AFTER);
        assert_eq!(ring.kept(), b"\x1b[2Jscreen and more");
    }
}
