//! A session past its handshake, record by record: `DATA` both ways, and
//! `ACK`, `PING`, `PONG`, `REFUSE` and `CLOSE`. Sans-IO: records in, events
//! and records out. The state outlives a link: its offsets and its replay
//! buffer carry the session onto the next link (T-152, T-153).

use std::fmt;

use super::decode::DecodeError;
use super::offset::{Inbound, OffsetError, Outbound};
use super::record::{Record, RefuseCode, MAX_DATA};
use super::replay::{Full, NotKept, Replay};

/// A receiver acknowledges at least each this many bytes (T-152).
pub const ACK_EVERY: u64 = 64 * 1024;

/// What a record from the peer gives.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// New bytes of the session, in order.
    Deliver(Vec<u8>),
    /// Send this record back (a `PONG`).
    Reply(Record),
    /// The peer ended the session, with its reason.
    Closed(String),
    /// The peer retired this link: the session goes on over another one.
    Retired,
    /// Nothing for the application: an old `DATA`, an `ACK`, a `PONG`.
    Nothing,
}

/// Why a link can carry the session no further. Each but `Refused` ends the
/// link only: a resume (T-153) can carry the session on a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// Bytes that are not records of the layer.
    Decode(DecodeError),
    /// An offset that the session cannot take, a gap first of all.
    Offset(OffsetError),
    /// A record of the handshake on a link past it.
    Unexpected(&'static str),
    /// The peer refused the session, with its code and its reason.
    Refused { code: RefuseCode, reason: String },
    /// Bytes past the room of the replay buffer: the writer did not wait.
    Full(Full),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::Decode(e) => write!(f, "the link carried {e}"),
            LinkError::Offset(e) => e.fmt(f),
            LinkError::Unexpected(what) => write!(f, "{what} after the handshake"),
            LinkError::Refused { code, reason } if reason.is_empty() => {
                write!(f, "the far end refused the session ({code})")
            }
            LinkError::Refused { code, reason } => {
                write!(f, "the far end refused the session ({code}): {}", podssh_ws::text::one_line(reason))
            }
            LinkError::Full(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<DecodeError> for LinkError {
    fn from(e: DecodeError) -> Self {
        LinkError::Decode(e)
    }
}

impl From<OffsetError> for LinkError {
    fn from(e: OffsetError) -> Self {
        LinkError::Offset(e)
    }
}

/// The offsets of a session, and its replay buffer when the peer
/// acknowledges. After an error the link takes no record, so nothing after a
/// gap is ever delivered; [`Link::resume`] starts the next link.
#[derive(Debug)]
pub struct Link {
    inbound: Inbound,
    outbound: Outbound,
    replay: Option<Replay>,
    /// Whether to acknowledge: the peer keeps a replay buffer.
    acks: bool,
    /// The received offset of the last acknowledgement sent.
    acked: u64,
    /// Whether each end pings when idle: both named `heartbeat.v1`.
    heartbeat: bool,
    /// Whether the client moves the session to a new link before the
    /// relay's limits: both named `move.v1`.
    moves: bool,
    failed: Option<LinkError>,
}

impl Link {
    /// A link whose side has each byte below `received` and sends from
    /// `send_from` (0 and 0 for a new session), with no replay buffer and no
    /// acknowledgement.
    pub fn new(received: u64, send_from: u64) -> Link {
        Link {
            inbound: Inbound::new(received),
            outbound: Outbound::new(send_from),
            replay: None,
            acks: false,
            acked: received,
            heartbeat: false,
            moves: false,
            failed: None,
        }
    }

    /// Send a `PING` when idle, and take a link that carries nothing for
    /// three intervals as dead (T-154): both sides named `heartbeat.v1`.
    pub fn with_heartbeat(mut self) -> Link {
        self.heartbeat = true;
        self
    }

    /// Whether the link pings when idle.
    pub fn heartbeat(&self) -> bool {
        self.heartbeat
    }

    /// Move the session to a new link before the relay's limits, and retire
    /// the old one (T-155): both sides named `move.v1`.
    pub fn with_moves(mut self) -> Link {
        self.moves = true;
        self
    }

    /// Whether the session moves before the relay's limits.
    pub fn moves(&self) -> bool {
        self.moves
    }

    /// Keep each byte sent until the peer acknowledges it, `capacity` bytes
    /// at most, and acknowledge the peer's bytes in turn: both sides named
    /// `replay.v1`.
    pub fn with_replay(mut self, capacity: usize) -> Link {
        self.replay = Some(Replay::new(self.outbound.sent(), capacity));
        self.acks = true;
        self
    }

    pub fn received(&self) -> u64 {
        self.inbound.received()
    }

    pub fn sent(&self) -> u64 {
        self.outbound.sent()
    }

    /// The highest offset that the peer acknowledged.
    pub fn acknowledged(&self) -> u64 {
        self.outbound.acknowledged()
    }

    /// The bytes that the replay buffer keeps, 0 with none.
    pub fn kept(&self) -> usize {
        self.replay.as_ref().map_or(0, Replay::kept)
    }

    /// How many bytes the application may send now: the room of the replay
    /// buffer, and no limit with none.
    pub fn room(&self) -> usize {
        self.replay.as_ref().map_or(usize::MAX, Replay::room)
    }

    /// The error that ended the link, if one did.
    pub fn failed(&self) -> Option<&LinkError> {
        self.failed.as_ref()
    }

    /// Take a record from the peer.
    pub fn on_record(&mut self, record: Record) -> Result<Event, LinkError> {
        if let Some(failed) = &self.failed {
            return Err(failed.clone());
        }
        let event = self.event(record);
        if let Err(e) = &event {
            self.failed = Some(e.clone());
        }
        event
    }

    /// Mark the link as ended by an error found outside it (the decoder's).
    pub fn fail(&mut self, error: LinkError) -> LinkError {
        self.failed.get_or_insert(error).clone()
    }

    fn event(&mut self, record: Record) -> Result<Event, LinkError> {
        match record {
            Record::Data { offset, mut bytes } => {
                let fresh = self.inbound.accept(offset, &bytes)?.len();
                if fresh == 0 {
                    return Ok(Event::Nothing);
                }
                bytes.drain(..bytes.len() - fresh);
                Ok(Event::Deliver(bytes))
            }
            Record::Ack { offset } | Record::Pong { offset, .. } => {
                self.acknowledged_to(offset)?;
                Ok(Event::Nothing)
            }
            Record::Ping { value } => {
                // A `PONG` acknowledges too.
                let offset = self.inbound.received();
                self.acked = offset;
                Ok(Event::Reply(Record::Pong { value, offset }))
            }
            Record::Close { reason } => Ok(Event::Closed(reason)),
            Record::Retire => Ok(Event::Retired),
            Record::Refuse { code, reason } => Err(LinkError::Refused { code, reason }),
            other => Err(LinkError::Unexpected(other.name())),
        }
    }

    fn acknowledged_to(&mut self, offset: u64) -> Result<(), LinkError> {
        self.outbound.acknowledge(offset)?;
        if let Some(replay) = &mut self.replay {
            replay.release(offset)?;
        }
        Ok(())
    }

    /// Append `DATA` records for `bytes` to `out`, each of [`MAX_DATA`]
    /// bytes at most, and keep the bytes for a resume. More bytes than
    /// [`Link::room`] are refused, and nothing is sent.
    pub fn send(&mut self, bytes: &[u8], out: &mut Vec<u8>) -> Result<(), LinkError> {
        if let Some(failed) = &self.failed {
            return Err(failed.clone());
        }
        if let Some(replay) = &mut self.replay {
            replay.keep(bytes).map_err(LinkError::Full)?;
        }
        for chunk in bytes.chunks(MAX_DATA) {
            let offset = self.outbound.take(chunk.len())?;
            // `DATA` of up to MAX_DATA bytes always fits the table, so the
            // encoder cannot refuse it.
            push_data(out, offset, chunk);
        }
        Ok(())
    }

    /// Whether [`ACK_EVERY`] bytes or more came since the last
    /// acknowledgement: one goes out at once.
    pub fn ack_due(&self) -> bool {
        self.acks && self.inbound.received() - self.acked >= ACK_EVERY
    }

    /// Whether bytes came that are not acknowledged yet: one goes out after
    /// a short wait (the pump's 200 ms).
    pub fn ack_pending(&self) -> bool {
        self.acks && self.inbound.received() > self.acked
    }

    /// An `ACK` of each byte received so far.
    pub fn ack(&mut self) -> Record {
        self.acked = self.inbound.received();
        Record::Ack { offset: self.acked }
    }

    /// Carry the session onto a new link, from `peer_received`, the offset
    /// that the peer's handshake gave: the peer has each byte below it, and
    /// the bytes from it on go out again as `DATA` records appended to
    /// `out`. Their count is the result. An offset that this side no longer
    /// keeps, or never sent, is refused: never a silent gap.
    pub fn resume(&mut self, peer_received: u64, out: &mut Vec<u8>) -> Result<u64, NotKept> {
        let sent = self.outbound.sent();
        let (start, end) = match &self.replay {
            Some(replay) => (replay.start(), replay.end()),
            None => (sent, sent),
        };
        let not_kept = NotKept { asked: peer_received, start, end };
        if peer_received < start || peer_received > end {
            return Err(not_kept);
        }
        if self.acknowledged_to(peer_received).is_err() {
            return Err(not_kept);
        }
        let mut again = 0u64;
        if let Some(replay) = &self.replay {
            let (a, b) = replay.since(peer_received)?;
            let mut offset = peer_received;
            for chunk in a.chunks(MAX_DATA).chain(b.chunks(MAX_DATA)) {
                push_data(out, offset, chunk);
                offset += chunk.len() as u64;
                again += chunk.len() as u64;
            }
        }
        // The handshake told the peer this side's received offset: an
        // acknowledgement in effect.
        self.acked = self.inbound.received();
        self.failed = None;
        Ok(again)
    }
}

/// A `DATA` record written straight into `out`, with no copy of the bytes
/// into a `Record` first.
fn push_data(out: &mut Vec<u8>, offset: u64, bytes: &[u8]) {
    out.push(super::record::kind::DATA);
    out.extend_from_slice(&((8 + bytes.len()) as u32).to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(bytes);
}
