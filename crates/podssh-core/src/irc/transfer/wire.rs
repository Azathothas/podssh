//! The transfer's own wire: the marker line, its shapes, and base64.
//!
//! ⛔ **This is not IRC.** It is a `PODSSH1|…` payload inside a `PRIVMSG`, ⛔
//! and it has its own file so the base64 codec — which has nothing to do with
//! the IRC grammar — is not read every time somebody opens the protocol.

use crate::irc::limits::TransferLimits;
use crate::irc::message::{Command, Message, Middle, Trailing};

/// ⛔ **The marker, in every transfer line.** ⛔ It is a plain `PRIVMSG` and
/// not a `CTCP ACTION`, ⛔ **deliberately**: podssh is not required to speak to
/// a real ircd's clients, and a `PRIVMSG` is the one construct every IRC
/// implementation forwards, relays and stores.
pub const MARKER: &str = "PODSSH1";

/// ⛔ **Base64, without a dependency.** ⛔ `podssh-core` has no `base64` in its
/// manifest and ⛔ **adding one is not free**: every dependency is another thing
/// that can fail `CC=/nonexistent`, and this is a 40-line codec with vectors
/// from RFC 4648 in the tests. ⛔ **Standard alphabet, with padding** — the
/// padded form is what every other implementation emits, ⛔ so a peer that is
/// not podssh and a file produced elsewhere both decode.
pub mod b64 {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &[u8]) -> String {
        let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(triple >> 18 & 0x3f) as usize] as char);
            out.push(ALPHABET[(triple >> 12 & 0x3f) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(triple >> 6 & 0x3f) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(triple & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    /// ⛔ **Strict.** ⛔ A non-alphabet byte, a length that is not a multiple of
    /// four, padding in the middle, or padding before the last group are all
    /// errors, ⛔ because a lenient decoder silently drops the offending byte
    /// and the file that arrives is short by one with no word to anyone.
    pub fn decode(input: &str) -> Result<Vec<u8>, String> {
        if input.len() % 4 != 0 {
            return Err(format!(
                "base64 payload is {} bytes, which is not a multiple of four",
                input.len()
            ));
        }
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(input.len() / 4 * 3);
        for (group, quad) in bytes.chunks(4).enumerate() {
            let last = group == bytes.len() / 4 - 1;
            let mut values = [0u8; 4];
            let mut padding = 0usize;
            for (i, &c) in quad.iter().enumerate() {
                if c == b'=' {
                    if !last || i < 2 {
                        return Err("base64 padding appears before the final group".into());
                    }
                    padding += 1;
                    continue;
                }
                if padding > 0 {
                    return Err("base64 padding is followed by data".into());
                }
                match decode_byte(c) {
                    Some(v) => values[i] = v,
                    None => return Err(format!("base64 payload has a byte outside the alphabet: {:?}", c as char)),
                }
            }
            let triple =
                ((values[0] as u32) << 18) | ((values[1] as u32) << 12) | ((values[2] as u32) << 6) | values[3] as u32;
            out.push((triple >> 16) as u8);
            if padding < 2 {
                out.push((triple >> 8) as u8);
            }
            if padding < 1 {
                out.push(triple as u8);
            }
        }
        Ok(out)
    }

    fn decode_byte(c: u8) -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
}

/// ⛔ **The shapes a transfer line can take, named.**
///
/// ⛔ **They are types rather than only variants** ⛔ because a function that
/// takes "an offer" or "a chunk" says what it needs, ⛔ and `&Line::Offer` is
/// not a type at all — it is a variant, and a signature naming one does not
/// compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
pub transfer_id: String,
pub name: String,
pub total: u64,
pub chunks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accept {
pub transfer_id: String,
pub from_chunk: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
pub transfer_id: String,
pub index: u64,
/// ⛔ **The byte offset in the file, and it is the resume key.** ⛔ Not
/// an index into a session: ⛔ chunk `i` is always bytes
/// `[i*320, i*320+320)` of the *file*, ⛔ so a session boundary changes
/// which chunks are sent and never what a chunk means.
pub offset: u64,
pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
pub transfer_id: String,
pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
pub transfer_id: String,
pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
pub transfer_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deny {
pub transfer_id: String,
pub reason: String,
}

/// ⛔ **What one transfer line means.** ⛔ Parsed once, at the edge, ⛔ so no
/// downstream code ever re-reads a positional field out of a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// ⛔ `PODSSH1|offer|<transfer-id>|<name>|<total>|<chunks>`
    Offer(Offer),
    /// ⛔ `PODSSH1|accept|<transfer-id>|<from-chunk>`
    Accept(Accept),
    /// ⛔ `PODSSH1|chunk|<transfer-id>|<index>|<offset>|<base64>`
    Chunk(Chunk),
    /// ⛔ `PODSSH1|ack|<transfer-id>|<index>`
    Ack(Ack),
    /// ⛔ `PODSSH1|digest|<transfer-id>|<sha256-hex>`
    Digest(Digest),
    /// ⛔ `PODSSH1|done|<transfer-id>`
    Done(Done),
    /// ⛔ `PODSSH1|deny|<transfer-id>|<reason>`
    Deny(Deny),
    /// ⛔ A marker line podssh does not understand, kept whole.
    Unknown { verb: String, rest: String },
}

impl Line {
/// ⛔ Split a `PRIVMSG`'s text into a transfer line. ⛔ **`None` for a
    /// message that is not a transfer at all**, ⛔ which is the overwhelming
    /// majority of `PRIVMSG`s in a channel and must cost nothing.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix(MARKER)?;
        let rest = rest.strip_prefix('|')?;
        let mut fields = rest.splitn(2, '|');
        let verb = fields.next()?.to_ascii_uppercase();
        let rest = fields.next().unwrap_or("");
        Some(match verb.as_str() {
            "OFFER" => {
                let mut f = rest.split('|');
                Line::Offer(Offer {
                    transfer_id: f.next()?.to_string(),
                    name: f.next()?.to_string(),
                    total: f.next()?.parse().ok()?,
                    chunks: f.next()?.parse().ok()?,
                })
            }
            "ACCEPT" => {
                let mut f = rest.split('|');
                Line::Accept(Accept {
                    transfer_id: f.next()?.to_string(),
                    from_chunk: f.next()?.parse().ok()?,
                })
            }
            "CHUNK" => {
                let mut f = rest.split('|');
                Line::Chunk(Chunk {
                    transfer_id: f.next()?.to_string(),
                    index: f.next()?.parse().ok()?,
                    offset: f.next()?.parse().ok()?,
                    payload: f.next()?.to_string(),
                })
            }
            "ACK" => {
                let mut f = rest.split('|');
                Line::Ack(Ack {
                    transfer_id: f.next()?.to_string(),
                    index: f.next()?.parse().ok()?,
                })
            }
            "DIGEST" => {
                let mut f = rest.split('|');
                Line::Digest(Digest {
                    transfer_id: f.next()?.to_string(),
                    sha256: f.next()?.to_string(),
                })
            }
            "DONE" => Line::Done(Done { transfer_id: rest.trim().to_string() }),
            "DENY" => {
                let mut f = rest.split('|');
                Line::Deny(Deny {
                    transfer_id: f.next()?.to_string(),
                    reason: f.next().unwrap_or("").to_string(),
                })
            }
            _ => Line::Unknown { verb, rest: rest.to_string() },
        })
    }

    /// ⛔ Render to the text of a `PRIVMSG`. ⛔ **Byte-exact with
    /// [`Line::parse`]**, ⛔ and asserted over a round trip in the tests, ⛔ so
    /// the two halves of this protocol cannot drift apart.
    pub fn render(&self) -> String {
        match self {
            Line::Offer(Offer { transfer_id, name, total, chunks }) => {
                format!("{MARKER}|offer|{transfer_id}|{name}|{total}|{chunks}")
            }
            Line::Accept(Accept { transfer_id, from_chunk }) => {
                format!("{MARKER}|accept|{transfer_id}|{from_chunk}")
            }
            Line::Chunk(Chunk { transfer_id, index, offset, payload }) => {
                format!("{MARKER}|chunk|{transfer_id}|{index}|{offset}|{payload}")
            }
            Line::Ack(Ack { transfer_id, index }) => {
                format!("{MARKER}|ack|{transfer_id}|{index}")
            }
            Line::Digest(Digest { transfer_id, sha256 }) => {
                format!("{MARKER}|digest|{transfer_id}|{sha256}")
            }
            Line::Done(Done { transfer_id }) => format!("{MARKER}|done|{transfer_id}"),
            Line::Deny(Deny { transfer_id, reason }) => {
                format!("{MARKER}|deny|{transfer_id}|{reason}")
            }
            Line::Unknown { verb, rest } => format!("{MARKER}|{verb}|{rest}"),
        }
    }
}

/// ⛔ Wrap a transfer line in the `PRIVMSG` that carries it.
pub fn as_privmsg(target: &str, line: &Line) -> Message {
    Message {
        tags: Vec::new(),
        prefix: None,
        command: Command::Privmsg {
            target: Middle(target.to_string()),
            text: Trailing::new(line.render()),
        },
    }
}

/// ⛔ **The chunk size is a property of the encoder, and this is where it is
/// proved rather than asserted.** A chunk line's wire length is
/// `512 - header` at most; ⛔ [`TransferLimits::default`] says 320 raw bytes,
/// and this function is what makes that number checkable against the real
/// [`Message::to_wire`] rather than against arithmetic on paper.
pub fn chunk_line_length(limits: &TransferLimits, transfer_id: &str, index: u64, offset: u64) -> usize {
    let payload_len = (limits.chunk_bytes + 2) / 3 * 4;
    let line = Line::Chunk(Chunk {
        transfer_id: transfer_id.to_string(),
        index,
        offset,
        payload: "A".repeat(payload_len),
    });
    as_privmsg("#x", &line).to_wire().len()
}


/// ⛔ The refusal a peer sends, and ⛔ **the reason string is the only part
/// of this protocol a human reads**, ⛔ so a machine-generated reason reads
/// as a machine having no reason.
pub fn deny(target: &str, transfer_id: &str, reason: &str) -> Message {
    as_privmsg(
        target,
        &Line::Deny(Deny { transfer_id: transfer_id.to_string(), reason: reason.to_string() }),
    )
}
