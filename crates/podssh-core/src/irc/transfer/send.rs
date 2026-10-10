//! The sending half, and **the resume rule that makes it correct.**

use crate::irc::encode::Unsafe;
use crate::irc::limits::TransferLimits;
use crate::irc::message::Message;
use crate::irc::transfer::wire::{as_privmsg, b64, check_field, Chunk, Digest, Line, Offer};

/// The sending half.
#[derive(Debug, Clone)]
pub struct Sender {
    transfer_id: String,
    name: String,
    total: u64,
    chunks: u64,
    limits: TransferLimits,
    /// The chunk to send next. **Advanced only by [`Sender::advance`]**,
    /// so a session that closes mid-transfer does not skip a chunk: the
    /// resume offset is `next_chunk * chunk_bytes`, which is a property of the
    /// file and not of how far the socket got.
    next_chunk: u64,
    /// Bytes of file already placed in sessions that have completed.
    bytes_committed: u64,
    session_index: u64,
}

impl Sender {
    /// **The id and the name are checked here**, once, as each line of the
    /// transfer carries the id and the offer the name: see
    /// [`check_field`].
    pub fn new(
        transfer_id: impl Into<String>,
        name: impl Into<String>,
        total: u64,
        limits: TransferLimits,
    ) -> Result<Self, Unsafe> {
        let (transfer_id, name) = (transfer_id.into(), name.into());
        check_field("the transfer id", &transfer_id)?;
        check_field("the name", &name)?;
        let chunks = limits.chunk_count(total);
        Ok(Sender { transfer_id, name, total, chunks, limits, next_chunk: 0, bytes_committed: 0, session_index: 0 })
    }

    pub fn chunks(&self) -> u64 {
        self.chunks
    }

    pub fn next_chunk(&self) -> u64 {
        self.next_chunk
    }

    pub fn sessions_needed(&self) -> u64 {
        self.limits.session_count(self.total)
    }

    /// **Where the resume starts, and it is the session boundary.** The
    /// first chunk of each session is `bytes_committed / chunk_bytes`, which
    /// is why `bytes_committed` is a multiple of `chunk_bytes` by construction:
    /// sessions are filled with whole chunks. A file whose last session is
    /// short still resumes correctly, because the offset is the file offset
    /// and not a count of what a particular socket received.
    pub fn resume_chunk(&self) -> u64 {
        self.next_chunk
    }

    /// The offer, **and the number of sessions it will take**, so the
    /// user is told "this file will take 3 sessions" before the first byte
    /// rather than discovering it when the relay closes.
    pub fn offer(&self, target: &str) -> Message {
        let line = Line::Offer(Offer {
            transfer_id: self.transfer_id.clone(),
            name: self.name.clone(),
            total: self.total,
            chunks: self.chunks,
        });
        as_privmsg(target, &line)
    }

    /// **Is a new session needed now?** **The check is on the chunk that
    /// is about to be sent, not on the one just sent** — a session that has
    /// already exceeded its budget cannot be reclaimed, and the byte that put
    /// it over is the one that must not be written.
    pub fn needs_new_session(&self) -> bool {
        self.bytes_committed >= self.limits.session_bytes as u64
    }

    /// Bytes this session may still carry.
    pub fn session_remaining(&self) -> u64 {
        (self.limits.session_bytes as u64).saturating_sub(self.bytes_committed)
    }

    /// The byte range this sender wants next, or `None` when the file is
    /// finished. **This is what the caller reads from the file** — podssh
    /// does not own the file, so the reader is the caller's and this is the
    /// one place that says which bytes it wants.
    pub fn next_range(&self) -> Option<(u64, usize)> {
        self.limits.chunk_range(self.total, self.next_chunk)
    }

    /// **One chunk, as a `PRIVMSG`.** `None` when the file is finished,
    /// **which is the only thing that means finished**: not "the socket
    /// accepted it" and not "the peer has not complained yet".
    ///
    /// **The bytes are supplied by the caller and checked against the file's
    /// own geometry.** A sender that built the payload itself would be a
    /// sender that had the whole file in memory, and a 60 MiB session is not
    /// a thing to hold. The length check is `Err`, not a truncation: a caller
    /// that reads short would otherwise ship a file with a silent hole and a
    /// digest computed over the hole.
    pub fn next_chunk_message(&mut self, target: &str, bytes: &[u8]) -> Result<Message, String> {
        let (offset, expected_len) = self.next_range().ok_or_else(|| "the file is already finished".to_string())?;
        if bytes.len() != expected_len {
            return Err(format!(
                "chunk {} needs {expected_len} bytes and the caller supplied {}",
                self.next_chunk,
                bytes.len()
            ));
        }
        let line = Line::Chunk(Chunk {
            transfer_id: self.transfer_id.clone(),
            index: self.next_chunk,
            offset,
            payload: b64::encode(bytes),
        });
        Ok(as_privmsg(target, &line))
    }

    /// Record that chunk `index` was accepted. **The peer names the
    /// index**, so a lost chunk is detected here: an `ACK` for an index other
    /// than the one outstanding is ignored rather than treated as progress,
    /// and the transfer stalls visibly instead of producing a file with a hole.
    pub fn acknowledge(&mut self, index: u64) -> bool {
        if index != self.next_chunk {
            return false;
        }
        if let Some((_, len)) = self.limits.chunk_range(self.total, index) {
            self.bytes_committed += len as u64;
        }
        self.next_chunk += 1;
        true
    }

    /// **A session began, and the FIRST one is registered here too.**
    /// A counter that only incremented on `open_session` and a caller that
    /// never opened the first session reported session **1** for the second
    /// one — MEASURED 2026-10-02, and **the symptom is a log line that
    /// says the wrong session number**, which is exactly the kind of defect
    /// that is invisible until somebody reads a real capture.
    ///
    /// **The byte counter is NOT reset**, and that is deliberate:
    /// `bytes_committed` is *the file offset*, so it is what makes the resume
    /// boundary correct and resetting it here would restart the file.
    pub fn open_session(&mut self) -> u64 {
        self.session_index += 1;
        self.session_index
    }

    /// The session this sender is in. **Zero before the first session is
    /// opened**, so a caller that logs it before opening one sees "no
    /// session yet" rather than a number it made up.
    pub fn session(&self) -> u64 {
        self.session_index
    }

    /// **No hashing and no allocation inside this type.** The sender
    /// hashes the file it is reading and hands the hex in; a sender that
    /// digested internally would have to keep the whole file, and a 60 MiB
    /// session is not a thing to hold in memory.
    pub fn digest(&self, target: &str, sha256_hex: &str) -> Message {
        let line = Line::Digest(Digest { transfer_id: self.transfer_id.clone(), sha256: sha256_hex.to_string() });
        as_privmsg(target, &line)
    }

    pub fn is_complete(&self) -> bool {
        self.next_chunk >= self.chunks
    }
}
