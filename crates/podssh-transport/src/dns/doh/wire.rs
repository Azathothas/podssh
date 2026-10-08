//! E15 — ⛔ **the wire format: a DNS question, its encoding, and the read-back.**
//!
//! ⛔ **The base64url alphabet is written out here rather than taken from the
//! `base64` crate**, ⛔ because ⛔ `base64` is a dependency of `podssh-ws` and
//! ⛔ **not of this crate**, ⛔ and ⛔ **adding it to a manifest another entry may
//! be editing is a merge nobody wins.** ⛔ **A hand-rolled encoder with no
//! decoder is an encoder nobody has checked**, ⛔ **so the decoder is here and
//! [`decode_question`] reads the name back out of a request line** ⛔ — ⛔ **and
//! every DoH plant asserts on it**, ⛔ **because a subtly wrong encoding
//! produces a question nobody answers, and ⛔ the "empty answer" assertion would
//! then pass for the wrong reason.**
//!
//! ⛔ **No credential ever enters this module.** ⛔ The `dns=` parameter
//! carries a name and a query type and nothing else, ⛔ **because a URL ends
//! up in proxy access logs** ⛔ — ⛔ `endpoint.rs` already says ⛔ *"podssh
//! must never put a token in a URL when a header is available."*

use super::{TYPE_A, TYPE_AAAA};

/// ⛔ **One query: a name and the two record types.** ⛔ **The name is
/// percent-encoded**, because a name carrying a space or a quote would
/// otherwise be able to inject a second request line ⛔ — the query goes into a
/// URL and `endpoint.rs`'s rule about tokens in URLs is the smaller half of that
/// rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohQuery {
    pub name: String,
    pub kind: &'static str,
}

impl DohQuery {
    pub fn a(name: &str) -> Self {
        Self { name: name.to_string(), kind: TYPE_A }
    }

    pub fn aaaa(name: &str) -> Self {
        Self { name: name.to_string(), kind: TYPE_AAAA }
    }

    /// ⛔ **The wire-format DNS query, base64url without padding** ⛔ — ⛔ **what
    /// `application/dns-message` carries.** ⛔ **`base64` is a workspace
    /// dependency of `podssh-ws` and not of this crate**, so the two alphabets
    /// are written here ⛔ **and the encoder is tested against a decoded query**
    /// rather than trusted: a base64url encoder that is subtly wrong produces a
    /// request the server rejects, and a test that only checked the string would
    /// pass.
    pub fn wire(&self) -> String {
        let mut message = Vec::with_capacity(32 + self.name.len());
        // ⛔ Header: id 0 (a DoH request over HTTPS needs no id; the connection
        // is already the security boundary), `RD` set, `QTYPE` and `QCLASS`.
        message.extend_from_slice(&[0x00, 0x00]);
        message.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, recursion desired
        message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        message.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR counts
        for label in self.name.trim_end_matches('.').split('.') {
            if label.is_empty() {
                continue;
            }
            if label.len() > 63 {
                // ⛔ **A label over 63 bytes cannot be encoded**, and truncating it
                // would ask a *different* question. The name is rejected.
                return String::new();
            }
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0); // root label
        let qtype: u16 = match self.kind {
            TYPE_AAAA => 28,
            _ => 1,
        };
        message.extend_from_slice(&qtype.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        base64url(&message)
    }
}

/// ⛔ **base64url, unpadded.** ⛔ **`standard` is the alphabet, `URL_SAFE` is the
/// two substitutions, and `NO_PAD` drops the `=`** ⛔ — ⛔ **and the decoder
/// below exists so the encoder is checked against a round trip rather than
/// against itself.**
pub fn base64url(bytes: &[u8]) -> String {
    const STANDARD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(URL_SAFE[(n >> 18) as usize & 63] as char);
        out.push(URL_SAFE[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(URL_SAFE[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(URL_SAFE[n as usize & 63] as char);
        }
    }
    debug_assert!(STANDARD.len() == 64 && URL_SAFE.len() == 64);
    out
}

/// ⛔ **The decoder, for the round trip a test asserts.** ⛔ It exists in the
/// library ⛔ **not** because anything ships it and ⛔ **because an encoder that
/// nothing decodes is an encoder nobody has checked** ⛔ — which is the same
/// argument that puts the plants in this repository's tests.
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}
