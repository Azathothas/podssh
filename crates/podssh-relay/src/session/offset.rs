//! The offsets of a session, one pair for each direction.
//!
//! Each side numbers the bytes that it sends from 0, with 64 bits that never
//! reset, across every link of the session. A receiver takes a `DATA` record
//! only at the next offset that it expects: the part of a record below it was
//! delivered already, and is dropped; a record that starts above it means
//! that bytes are missing, and nothing after a gap is ever delivered, since a
//! byte delivered out of place breaks SSH for good. The link then ends, and a
//! resume sends again from the received offset (T-153).

use std::fmt;

/// Why an offset is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetError {
    /// A `DATA` record that starts after the next byte expected.
    Gap { expected: u64, got: u64 },
    /// A `DATA` record whose end does not fit in 64 bits.
    Overflow { offset: u64, len: u64 },
    /// An acknowledgement of bytes that were never sent.
    Ahead { sent: u64, acknowledged: u64 },
}

impl fmt::Display for OffsetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OffsetError::Gap { expected, got } => {
                write!(f, "bytes are missing: the next byte is at offset {expected}, a record starts at {got}")
            }
            OffsetError::Overflow { offset, len } => {
                write!(f, "a record of {len} bytes at offset {offset} ends past 2^64")
            }
            OffsetError::Ahead { sent, acknowledged } => {
                write!(f, "the peer acknowledges offset {acknowledged}, but only {sent} bytes were sent")
            }
        }
    }
}

impl std::error::Error for OffsetError {}

/// One direction as its receiver sees it: the offset of the next byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Inbound {
    next: u64,
}

impl Inbound {
    /// A receiver that has each byte below `next`.
    pub fn new(next: u64) -> Inbound {
        Inbound { next }
    }

    /// The offset of the next byte expected, which is also the count of the
    /// bytes received.
    pub fn received(&self) -> u64 {
        self.next
    }

    /// The bytes of a `DATA` record at `offset` that were not delivered yet,
    /// in order; none for a record wholly below the next byte. A record that
    /// starts above it is a gap: an error, and nothing is taken.
    pub fn accept<'a>(&mut self, offset: u64, bytes: &'a [u8]) -> Result<&'a [u8], OffsetError> {
        let len = bytes.len() as u64;
        let end = offset.checked_add(len).ok_or(OffsetError::Overflow { offset, len })?;
        if offset > self.next {
            return Err(OffsetError::Gap { expected: self.next, got: offset });
        }
        if end <= self.next {
            return Ok(&[]);
        }
        // `offset <= next < end`, so the skip is below `len`.
        let skip = (self.next - offset) as usize;
        self.next = end;
        Ok(&bytes[skip..])
    }
}

/// One direction as its sender sees it: the offset of the next byte to
/// send, and the offset that the peer acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Outbound {
    next: u64,
    acknowledged: u64,
}

impl Outbound {
    /// A sender whose next byte is at `next`, all of them acknowledged.
    pub fn new(next: u64) -> Outbound {
        Outbound { next, acknowledged: next }
    }

    /// The offset of the next byte to send: the count of the bytes sent.
    pub fn sent(&self) -> u64 {
        self.next
    }

    /// The highest offset that the peer acknowledged.
    pub fn acknowledged(&self) -> u64 {
        self.acknowledged
    }

    /// Number `len` new bytes: the offset of the first.
    pub fn take(&mut self, len: usize) -> Result<u64, OffsetError> {
        let offset = self.next;
        let len = len as u64;
        self.next = offset.checked_add(len).ok_or(OffsetError::Overflow { offset, len })?;
        Ok(offset)
    }

    /// The peer has each byte below `offset`. An older acknowledgement than
    /// one already taken changes nothing; one past the bytes sent is an
    /// error, as the peer cannot have them.
    pub fn acknowledge(&mut self, offset: u64) -> Result<(), OffsetError> {
        if offset > self.next {
            return Err(OffsetError::Ahead { sent: self.next, acknowledged: offset });
        }
        self.acknowledged = self.acknowledged.max(offset);
        Ok(())
    }
}
