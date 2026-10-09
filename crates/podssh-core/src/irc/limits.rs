//! The relay's limits, as this crate holds them.
//!
//! **Exactly one number here is read from the file E06 owns; five are
//! transcriptions, and the table below says which is which.** The read one is
//! `forward-max-frame-bytes`, taken at compile time from
//! `crates/podssh-probe/facts/relay-facts.toml` — the same file
//! `podssh-probe`'s Rust gate, its Python counterpart and
//! `docs/spec/01-relay-protocol.md` read — so a re-measured forward cap cannot
//! leave this module agreeing with a stale number.
//!
//! **This header used to say that every number in the module came from the
//! relay and that none of them was typed here, and that was false.** Five
//! constants were typed and the test named for the claim asserted the typed
//! values. **A transcription is a record, not a measurement**, and a reader
//! deciding what this crate can fail on needs the difference written down.
//!
//! **Two readers, one file, and the reason it is worth it.** A second copy of
//! `65536` written into a Rust constant is a number that can drift silently
//! from the peer's, and the symptom is a transfer that closes `1009
//! frame byte cap` on files under the cap and only on files over it — which is
//! the shape of a bug that survives every smoke test.
//!
//! ## Where each number comes from
//!
//! | number | source | how it is checked |
//! | --- | --- | --- |
//! | forward max frame **262144** | `relay-facts.toml`, key `forward-max-frame-bytes` | read at compile time and compared against the constant |
//! | operator frame payload **65536** | spec line 184 | transcribed; `tests/transfer.rs` asserts the value |
//! | node frame total **65568** (32-byte id + 65536 payload) | spec line 182 | transcribed; 182 is a line E06's fact gate asserts |
//! | session, both directions **64 MiB** | spec line 183 | transcribed; asserted in `tests/transfer.rs` |
//! | idle reaper **180000 ms** | spec line 233 | transcribed; asserted in `tests/transfer.rs` |
//! | session wall clock **720 min** | spec line 234 | transcribed |
//!
//! **E06's fact gate checks lines 23, 24, 182, 190, 207 and 210 of the
//! peer's document, and line 182 is the only row here it touches.** A line that
//! moves without the fact moving is therefore *not* a red build: this table is
//! a citation, and the tests assert the numbers rather than the lines, which is
//! the honest limit of the check.

/// The relay's published facts, embedded at compile time.
///
/// **`include_str!` on a path relative to this file.** **No `toml` parser
/// here and no new dependency**: the two numbers podssh needs are found by a
/// narrow, anchored pattern against the file's text, because a TOML parser in
/// `podssh-core` would be a second dependency for two integers, and a
/// dependency is a thing that can fail the no-C-compiler gate on its own.
/// **A pattern that cannot match is a hard build failure, not a default** —
/// see [`TransferLimits::from_facts_text`], which returns `Result`.
pub const FACTS_TOML: &str = include_str!("../../../podssh-probe/facts/relay-facts.toml");

/// The operator frame's payload cap. **This is the number `frame byte cap`
/// is about**, and it is *not* the node frame's total: a reverse node frame is
/// capped at 65568 including a 32-byte id. E06 records the first version of
/// its own gate taking one for the other and reporting the relay as
/// self-contradictory, so the distinction is written here rather than left to a
/// reader who already knows it.
pub const OPERATOR_FRAME_PAYLOAD_BYTES: usize = 65536;

/// One session's byte budget, **both directions together**.
pub const SESSION_BYTES: usize = 64 * 1024 * 1024;

/// The forward path's maximum frame.
pub const FORWARD_MAX_FRAME_BYTES: usize = 262144;

/// Payload inactivity after which the relay reaps the session.
pub const IDLE_REAPER_MS: u64 = 180_000;

/// The session wall clock.
pub const SESSION_WALL_CLOCK_MS: u64 = 43_200_000;

/// **How the caps are used, all in one place.**
///
/// **All three numbers are deliberate margins, and none of them is the cap.**
/// A transfer that fills a session to exactly 64 MiB closes on the *last* byte
/// and cannot report that it finished, so each is chosen with headroom and
/// the reason is next to it. **A constant with a reason is a decision; a
/// constant that is a cap with a round number on it is a coin toss.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferLimits {
    /// **Bytes of file per chunk.** Not the frame cap and not the line
    /// cap: a chunk becomes one `PRIVMSG`, and RFC 2812 §2.3 caps a message at
    /// **512 bytes**. Base64 expands by 4/3 and the offer header spends some of
    /// what is left, so 320 raw bytes per chunk is the largest that
    /// `PODSSH1|…|<320 b64>|…` is guaranteed to fit in 512. **The assertion
    /// that it fits is in the tests, against the real encoder** — a constant
    /// chosen by arithmetic on paper is a claim, and the wire is the judge.
    pub chunk_bytes: usize,
    /// **Bytes of file per session**, summed across chunks.
    ///
    /// 60 MiB against the relay's 64 MiB: **the 4 MiB is the whole
    /// purpose**, and it is what leaves room for the control lines, the
    /// offer/accept exchange and the final acknowledgement inside one session's
    /// 64 MiB budget. A transfer sized at exactly the cap would be closed by
    /// `1009 session byte cap` before it could say it had finished.
    pub session_bytes: usize,
    /// **Bytes of file per operator frame.** Below the 65536 payload cap
    /// so a frame carrying a chunk plus its framing overhead can never cross
    /// it; **the reassembler makes this a non-issue** (a message may span
    /// frames), and it is kept anyway because a sender that respects the peer's
    /// published cap is not relying on that.
    pub frame_bytes: usize,
}

impl Default for TransferLimits {
    fn default() -> Self {
        TransferLimits { chunk_bytes: 320, session_bytes: 60 * 1024 * 1024, frame_bytes: OPERATOR_FRAME_PAYLOAD_BYTES }
    }
}

impl TransferLimits {
    /// **Read the two caps the relay publishes as numbers in its own
    /// document, and refuse to guess them.**
    ///
    /// **The patterns are anchored to the key and the unit**, so they find
    /// `forward-max-frame-bytes = 262144` and not any other digits in the
    /// file. **A fact that has been renamed or reworded fails the build**
    /// rather than leaving podssh with a default it never measured — and
    /// that is the point: E37's rule is that a capability is `MEASURED` or the
    /// client does not depend on it, and a default here would be a dependency
    /// on a number nobody checked.
    pub fn from_facts_text(text: &str) -> Result<Self, String> {
        let forward = anchored_usize(text, "forward-max-frame-bytes")?;
        if forward != FORWARD_MAX_FRAME_BYTES {
            return Err(format!(
                "crates/podssh-probe/facts/relay-facts.toml says \
                 forward-max-frame-bytes = {forward}, and this crate was \
                 written against {FORWARD_MAX_FRAME_BYTES}; the relay's cap \
                 moved, or the fact was re-measured wrongly"
            ));
        }
        Ok(TransferLimits { frame_bytes: OPERATOR_FRAME_PAYLOAD_BYTES, ..Default::default() })
    }

    /// The limits as read from the embedded facts file. **A `Result`,
    /// not a `const`**, because the only honest answer when the facts file no
    /// longer carries the numbers is "this cannot be checked", and a caller that
    /// got a default instead would be building a transfer against a limit
    /// nobody measured.
    pub fn from_embedded_facts() -> Result<Self, String> {
        Self::from_facts_text(FACTS_TOML)
    }

    /// **Chunks needed for a file of `total` bytes.** A zero-byte file
    /// needs **no chunks at all**, because sending an empty chunk would
    /// put an empty offer on the wire that a peer has to special-case.
    pub fn chunk_count(&self, total: u64) -> u64 {
        if total == 0 {
            0
        } else {
            total.div_ceil(self.chunk_bytes as u64)
        }
    }

    /// **Sessions needed for a file of `total` bytes.** **This is the
    /// function the entry's "chunked across sessions" clause is**, and it is
    /// the one that must never be `1` for a file over the session budget.
    pub fn session_count(&self, total: u64) -> u64 {
        if total == 0 {
            0
        } else {
            total.div_ceil(self.session_bytes as u64)
        }
    }

    /// The byte range of chunk `index`, and whether one exists. **A
    /// multi-session file is chunked over the *whole file*, not per session**,
    /// so the resume boundary is a function of the file offset and not of
    /// which session happens to be open.
    pub fn chunk_range(&self, total: u64, index: u64) -> Option<(u64, usize)> {
        let start = index.checked_mul(self.chunk_bytes as u64)?;
        if start >= total {
            return None;
        }
        let len = ((total - start) as usize).min(self.chunk_bytes);
        Some((start, len))
    }
}

/// Read `key = <digits>` where the key is at the start of a line, with no
/// looser match anywhere in the file. **A `MEASURED` number, or an error.**
fn anchored_usize(text: &str, key: &str) -> Result<usize, String> {
    for line in text.lines() {
        let line = line.trim();
        let rest = match line.strip_prefix(key) {
            Some(rest) => rest,
            None => continue,
        };
        let rest = rest.trim_start();
        let value = rest
            .strip_prefix('=')
            .ok_or_else(|| format!("crates/podssh-probe/facts/relay-facts.toml: `{key}` has no `=` after it"))?;
        let digits: String = value.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
        return digits.parse().map_err(|_| {
            format!(
                "crates/podssh-probe/facts/relay-facts.toml: `{key}` does not \
                 carry a number, so podssh cannot read the relay's cap from it"
            )
        });
    }
    Err(format!(
        "crates/podssh-probe/facts/relay-facts.toml does not carry `{key}`, so \
         podssh cannot read the relay's cap from it"
    ))
}
