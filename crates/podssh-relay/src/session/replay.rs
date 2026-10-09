//! The replay buffer: the bytes that a side sent and its peer has not
//! acknowledged, so that a resume can send them again (T-152).
//!
//! It never drops a byte that is not acknowledged, and it never grows past
//! its capacity: when it is full, the writer waits for an `ACK`, and SSH's
//! window then stops the server. A resume from an offset that it no longer
//! keeps is refused with both offsets, never answered with a gap (the rule
//! of GitHub #31).

use std::collections::VecDeque;
use std::fmt;

use super::offset::OffsetError;

/// The capacity in each direction: the relay holds at most 1 MiB for a slow
/// receiver and the SSH window is 512 KiB, so 4 MiB keeps the bytes of a lost
/// link (the decision of T-152).
pub const DEFAULT_CAPACITY: usize = 4 << 20;
/// The largest capacity that the setting gives.
pub const MAX_CAPACITY: usize = 16 << 20;
/// The setting: a whole number of bytes, from [`DEFAULT_CAPACITY`] to
/// [`MAX_CAPACITY`].
pub const CAPACITY_ENV: &str = "PODSSH_REPLAY_BUFFER";

/// The capacity, with `env` (the value of [`CAPACITY_ENV`]) raising it up to
/// [`MAX_CAPACITY`]. Another value is ignored.
pub fn capacity(env: Option<&str>) -> usize {
    env.and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| (DEFAULT_CAPACITY..=MAX_CAPACITY).contains(n))
        .unwrap_or(DEFAULT_CAPACITY)
}

/// A resume from an offset that the buffer does not keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotKept {
    /// The peer's received offset, where the resume would send from.
    pub asked: u64,
    /// The first offset that the buffer keeps: the highest acknowledged.
    pub start: u64,
    /// The offset after the last byte sent.
    pub end: u64,
}

impl fmt::Display for NotKept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let NotKept { asked, start, end } = self;
        if asked < start {
            write!(f, "the peer asks for bytes from offset {asked}, but they were acknowledged; this side keeps {start} to {end}")
        } else {
            write!(f, "the peer asks for bytes from offset {asked}, but this side sent only {end}")
        }
    }
}

impl std::error::Error for NotKept {}

impl NotKept {
    /// The `REFUSE` that ends the session: both offsets in its reason.
    pub fn refusal(&self) -> super::record::Record {
        super::record::Record::Refuse { code: super::record::RefuseCode::NOT_KEPT, reason: self.to_string() }
    }
}

/// Bytes that do not fit the room that is left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full {
    pub room: usize,
    pub asked: usize,
}

impl fmt::Display for Full {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes do not fit the replay buffer, which has room for {}", self.asked, self.room)
    }
}

impl std::error::Error for Full {}

/// The bytes from the acknowledged offset to the sent offset of one
/// direction.
#[derive(Debug, Clone)]
pub struct Replay {
    /// The offset of the first byte kept.
    start: u64,
    bytes: VecDeque<u8>,
    capacity: usize,
}

impl Replay {
    /// An empty buffer whose next byte is at `start`. Its memory is taken as
    /// bytes arrive, not at once.
    pub fn new(start: u64, capacity: usize) -> Replay {
        Replay { start, bytes: VecDeque::new(), capacity }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The bytes kept.
    pub fn kept(&self) -> usize {
        self.bytes.len()
    }

    /// The bytes that still fit.
    pub fn room(&self) -> usize {
        self.capacity.saturating_sub(self.bytes.len())
    }

    /// The offset of the first byte kept.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// The offset after the last byte kept, which is the sent offset.
    pub fn end(&self) -> u64 {
        self.start + self.bytes.len() as u64
    }

    /// Keep bytes sent at [`Replay::end`]. Bytes past the room are refused
    /// whole and nothing is kept: the writer waits for room instead.
    pub fn keep(&mut self, bytes: &[u8]) -> Result<(), Full> {
        if bytes.len() > self.room() {
            return Err(Full { room: self.room(), asked: bytes.len() });
        }
        self.bytes.extend(bytes);
        Ok(())
    }

    /// The peer has each byte below `offset`: they are freed. An offset
    /// below the start frees nothing; one past the end is an error, as the
    /// peer cannot have bytes never sent.
    pub fn release(&mut self, offset: u64) -> Result<(), OffsetError> {
        if offset > self.end() {
            return Err(OffsetError::Ahead { sent: self.end(), acknowledged: offset });
        }
        if offset > self.start {
            let n = (offset - self.start) as usize;
            self.bytes.drain(..n);
            self.start = offset;
        }
        // An empty buffer gives its memory back, so an idle session holds none.
        if self.bytes.is_empty() && self.bytes.capacity() > 64 * 1024 {
            self.bytes = VecDeque::new();
        }
        Ok(())
    }

    /// The bytes from `offset` to the end, to send again, in the two parts
    /// of the ring. `offset` must be kept: from the start to the end.
    pub fn since(&self, offset: u64) -> Result<(&[u8], &[u8]), NotKept> {
        if offset < self.start || offset > self.end() {
            return Err(NotKept { asked: offset, start: self.start, end: self.end() });
        }
        let skip = (offset - self.start) as usize;
        let (a, b) = self.bytes.as_slices();
        Ok(if skip < a.len() { (&a[skip..], b) } else { (&b[skip - a.len()..], &[][..]) })
    }
}
