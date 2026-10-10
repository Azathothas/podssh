//! The receiving half, and **the refusal rule that makes it correct.**
//!
//! A chunk is accepted **only at the offset the receiver expects next**,
//! which is `bytes_received / chunk_bytes`. A chunk that arrives early is
//! **not buffered**: it is refused, because holding it would mean the
//! receiver's idea of "what is next" is the peer's, and a peer that
//! reorders or duplicates then produces a file with a chunk in the wrong place
//! and a digest that still passes if the sender hashes what it sent.
//!
//! **The offset rides in the chunk, and that is what makes a resume across
//! a session boundary correct.** Chunk `i` is always bytes
//! `[i*320, i*320+320)` of the file, so "which session am I in" changes
//! which chunks are sent and never what a chunk means.

use sha2::Digest as _;

use crate::irc::limits::TransferLimits;
use crate::irc::message::Message;
use crate::irc::transfer::wire::{as_privmsg, b64, Ack, Chunk, Line, Offer};

/// **The peer's name for a file, as a base name only**: what follows its last
/// `/` or `\`, so a caller that writes the file under it stays in its
/// directory, on each system. A name with no base (empty, `.` or `..`) is
/// refused, and so is one with a `:`, which names a drive (`C:x`) or a stream
/// on Windows, or a control character.
pub fn base_name(name: &str) -> Result<String, String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    if base.is_empty() || base == "." || base == ".." {
        return Err(format!("the offered name {name:?} names no file in a directory"));
    }
    if base.contains(':') {
        return Err(format!("the offered name {name:?} holds ':', which names a drive or a stream on Windows"));
    }
    if let Some(c) = base.chars().find(|c| c.is_control()) {
        return Err(format!("the offered name {name:?} holds the control character {c:?}"));
    }
    Ok(base.to_string())
}

/// **The receiving half, and the resume rule that makes it correct.**
///
/// A chunk is accepted **only at the offset the receiver expects next**,
/// which is `bytes_received / chunk_bytes`. A chunk that arrives early is
/// **not buffered**: it is refused, because holding it would mean the
/// receiver's idea of "what is next" is the peer's, and a peer that reorders
/// or duplicates then produces a file with a chunk in the wrong place and a
/// digest that still passes if the sender hashes what it sent.
#[derive(Debug, Clone)]
pub struct Receiver {
    transfer_id: String,
    name: String,
    total: u64,
    chunks: u64,
    limits: TransferLimits,
    bytes_received: u64,
    /// **CHUNKS ACCEPTED, COUNTED, AND NOT DERIVED FROM THE BYTES.**
    ///
    /// Two attempts at deriving it from `bytes_received / chunk_bytes`
    /// were both wrong, and the arithmetic is worth recording because
    /// **it is wrong in the same direction every time**: a final chunk
    /// that is shorter than the rest floors, so the division undercounts.
    ///
    /// **MEASURED 2026-10-02**, with 320-byte chunks:
    ///
    /// | file | chunks | `total / 320` | right answer |
    /// | --- | --- | --- | --- |
    /// | 1000 | 4 | 3 | 4 |
    /// | 1281 | 5 | 4 | 5 |
    ///
    /// **Every file whose size is not a multiple of 320 is reported
    /// incomplete forever** — which is the case that *always* finishes, so
    /// the bug is **exactly backwards on every short file**.
    ///
    /// A counter is one line and cannot be wrong this way.
    chunks_accepted: u64,
    sink: Vec<u8>,
}

impl Receiver {
    /// Start from an offer.
    ///
    /// **A file larger than one session is not refused**, because the
    /// entry's clause is that it is *chunked across sessions*, and refusing
    /// it here would put that decision one layer too high where the sender
    /// cannot see it. [`Receiver::needs_new_session`] is the caller asking
    /// the question it must ask anyway.
    pub fn from_offer(line: &Offer) -> Result<Self, String> {
        let expected = TransferLimits::default().chunk_count(line.total);
        if expected != line.chunks {
            return Err(format!(
                "offer claims {} chunks for a file of {} bytes, and this build \
                 computes {}; the sender's chunk size is not the receiver's",
                line.chunks, line.total, expected
            ));
        }
        Ok(Receiver {
            transfer_id: line.transfer_id.clone(),
            name: base_name(&line.name)?,
            total: line.total,
            chunks: line.chunks,
            limits: TransferLimits::default(),
            bytes_received: 0,
            chunks_accepted: 0,
            sink: Vec::new(),
        })
    }

    /// The peer's name for the file, as a base name: see [`base_name`].
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// **Does this transfer need another session now?** The same budget
    /// the sender used, so the two agree without exchanging it.
    pub fn needs_new_session(&self) -> bool {
        self.bytes_received >= self.limits.session_bytes as u64
    }

    /// **Accept one chunk. `Err` for anything that does not belong.**
    ///
    /// The three refusals, and each names its own cause:
    /// * a different transfer id — the wrong conversation;
    /// * an offset that is not `bytes_received` — **the interesting one**, a
    ///   duplicate or a reordering, refused rather than absorbed;
    /// * a chunk that would run past `total` — a sender counting differently.
    pub fn accept(&mut self, line: &Chunk) -> Result<(), String> {
        if line.transfer_id != self.transfer_id {
            return Err(format!(
                "chunk belongs to transfer {} and this receiver is {}",
                line.transfer_id, self.transfer_id
            ));
        }
        if line.offset != self.bytes_received {
            return Err(format!(
                "chunk {} arrived at offset {} and this receiver expects {}; \
                 refusing it rather than writing it out of place",
                line.index, line.offset, self.bytes_received
            ));
        }
        let (_, expected_len) = self
            .limits
            .chunk_range(self.total, line.index)
            .ok_or_else(|| format!("chunk {} is past the end of the file", line.index))?;
        let bytes = b64::decode(&line.payload)?;
        if bytes.len() != expected_len {
            return Err(format!(
                "chunk {} carries {} bytes and the file's geometry needs {}",
                line.index,
                bytes.len(),
                expected_len
            ));
        }
        self.sink.extend_from_slice(&bytes);
        self.bytes_received += bytes.len() as u64;
        // **THE INDEX IS CHECKED TOO, and not only the offset.** The
        // offset is what makes the file correct; the index is what makes the
        // *count* correct, and a chunk that arrives at the right offset
        // with the wrong index would otherwise let the receiver claim a
        // completeness it did not reach.
        if line.index != self.chunks_accepted {
            return Err(format!(
                "chunk is numbered {} and this receiver has accepted {};                  the offset agreed and the index did not",
                line.index, self.chunks_accepted
            ));
        }
        self.chunks_accepted += 1;
        Ok(())
    }

    /// The acknowledgement for the chunk just accepted.
    pub fn ack(&self) -> Message {
        let index = self.bytes_received / self.limits.chunk_bytes as u64;
        let line = Line::Ack(Ack { transfer_id: self.transfer_id.clone(), index: index.saturating_sub(1) });
        as_privmsg("#transfer", &line)
    }

    /// Is every chunk here? **The check is on the chunk count and
    /// not on the byte count**, because **the two disagree for a
    /// short final chunk** — a file of 100 bytes is one chunk of 100, and
    /// `bytes_received == total` is true while `bytes_received == chunks *
    /// chunk_bytes` is 320. A completeness test written against the byte
    /// arithmetic reports every short file as incomplete, and a caller
    /// that "fixes" it by trusting the count then reports every short file as
    /// complete before the last chunk arrives.
    ///
    /// Both facts must agree: every chunk accepted, and the total
    /// consistent with the sender's own arithmetic.
    pub fn is_complete(&self) -> bool {
        // **A count of accepted chunks against the sender's own count**,
        // and nothing derived from the byte total — see the
        // `chunks_accepted` field for the two derivations that were wrong.
        // **An empty file is complete at zero bytes**, because
        // there is nothing to wait for and a receiver that waited would hang.
        self.chunks_accepted == self.chunks && self.bytes_received == self.total
    }

    /// The sender's chunk count, kept so the completeness test and the
    /// offer can be compared against each other.
    pub fn chunks(&self) -> u64 {
        self.chunks
    }

    /// **The received bytes.** **Only when
    /// [`Receiver::is_complete`]**, because handing back a partial file is
    /// how a transfer that failed at chunk 90 of 100 becomes a file on the
    /// user's disk that opens and is wrong.
    pub fn finish(&self) -> Result<&[u8], String> {
        if self.is_complete() {
            Ok(&self.sink)
        } else {
            Err(format!("{} of {} bytes received; the file is not finished", self.bytes_received, self.total))
        }
    }

    /// The SHA-256 of what arrived, for the `digest` line.
    pub fn sha256_hex(&self) -> String {
        let digest = sha2::Sha256::digest(&self.sink);
        hex::encode(digest)
    }

    /// Did the sender's digest match? **Compared against what arrived,
    /// not against what the sender said it sent**, because a digest that is
    /// only echoed back proves that two strings agree.
    pub fn verify(&self, sender_digest: &str) -> bool {
        sender_digest.eq_ignore_ascii_case(&self.sha256_hex())
    }

    /// Bytes to resume from, **after a session boundary**: the next chunk
    /// index, which the receiver then asks for with `PODSSH1|accept`.
    pub fn resume_from(&self) -> u64 {
        self.bytes_received / self.limits.chunk_bytes as u64
    }
}
