//! A file, as bytes over sessions. **No DCC, and that is not a choice.**
//!
//! **`DCC SEND` makes the receiving client dial the sender's address
//! directly.** Spec line 222: *"TCP only; no UDP, and no inbound TCP
//! (inbound raw TCP to a Worker is platform-impossible)."* Neither user in a
//! constrained environment can be reached, so a `DCC SEND` offer is a promise
//! neither end can keep. **There is no mode where it works and podssh is
//! tempted**, because the failure is silent on the sender and looks like a
//! firewall on the receiver.
//!
//! ## What this is instead
//!
//! **Bytes in `PRIVMSG`s, chunked at the limits in [`crate::irc::limits`].**
//! The offer, the accept, the chunks, the digest, the acknowledgement. **The
//! payload is base64** because a raw chunk is not line-safe: the byte layer
//! drops NUL and a `0x0a` inside a chunk would end the line and turn the rest
//! of the file into a second message. Base64 expands by 4/3 and that
//! expansion is **why the chunk is 320 bytes and not 512**, asserted against
//! the real encoder rather than arithmetic on paper.
//!
//! ## The transfer is resumable, and the boundary is a property of the file
//!
//! **Chunk `i` is always bytes `[i*320, i*320+320)` of the file.** Not
//! "the next chunk in this session", and not "the next chunk after whatever
//! arrived" — a resume that counted received chunks is a resume that silently
//! corrupts the file if one chunk was lost, because the count and the offsets
//! disagree and nothing notices. [`Receiver`] matches on the **offset**, and
//! a chunk that arrives at the wrong offset is refused rather than written.
//!
//! **A file over 64 MiB is chunked across sessions, never streamed through
//! one.** The relay closes at `1009 session byte cap`, and a transfer that
//! kept going would lose everything it had sent. [`Sender`] therefore counts
//! sessions and says so before the first byte of session 2.

pub mod recv;
pub mod send;
pub mod wire;

pub use recv::Receiver;
pub use send::Sender;
pub use wire::{as_privmsg, b64, chunk_line_length, deny, Accept, Ack, Chunk, Deny, Digest, Done, Line, Offer, MARKER};
