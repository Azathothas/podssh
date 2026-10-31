//! A node's ticket on DERP: `derp:` and one word of base32 (RFC 4648, lower
//! case, no padding) that holds a version byte, the node's Ed25519 key, its
//! DERP key, and its home server's port and name. It is an address, not a
//! credential, as an iroh ticket is: the end-to-end channel above the layer
//! checks the Ed25519 key that it names, and the node's allowlist lets in
//! the clients that it names. The word has no `@` and no `/`, which a
//! destination of `podssh ssh` reads as a user and a route.

use std::fmt;

use super::key::Key;
use super::servers::Server;
use crate::identity::PublicKey;

/// The scheme of a ticket.
pub const SCHEME: &str = "derp:";
/// The version of this form.
const VERSION: u8 = 1;
/// The version, the two keys and the port.
const FIXED: usize = 1 + 32 + 32 + 2;

/// Where a node is on DERP, and who it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// The node's identity, which the end-to-end channel checks.
    pub node: PublicKey,
    /// The node's key on the server, to which a client sends.
    pub derp: Key,
    /// The node's home server.
    pub server: Server,
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::with_capacity(FIXED + self.server.host.len());
        bytes.push(VERSION);
        bytes.extend_from_slice(&self.node.0);
        bytes.extend_from_slice(&self.derp.0);
        bytes.extend_from_slice(&self.server.port.to_be_bytes());
        bytes.extend_from_slice(self.server.host.as_bytes());
        write!(f, "{SCHEME}{}", encode(&bytes))
    }
}

impl Ticket {
    /// A ticket as [`Ticket`]'s `Display` writes it, with or without its
    /// scheme.
    pub fn parse(text: &str) -> Result<Ticket, String> {
        let word = text.trim();
        let word = word.strip_prefix(SCHEME).unwrap_or(word);
        let bytes = decode(word).ok_or_else(|| format!("{}: not a ticket of the DERP road", shown(text)))?;
        if bytes.len() <= FIXED {
            return Err(format!("{}: a ticket too short", shown(text)));
        }
        if bytes[0] != VERSION {
            return Err(format!(
                "{}: a ticket of version {}, which this podssh does not read (it reads {VERSION})",
                shown(text),
                bytes[0]
            ));
        }
        let mut node = [0u8; 32];
        node.copy_from_slice(&bytes[1..33]);
        let mut derp = [0u8; 32];
        derp.copy_from_slice(&bytes[33..65]);
        let port = u16::from_be_bytes([bytes[65], bytes[66]]);
        // The host is not echoed: a ticket of a stranger's may be long.
        let not_host = || format!("{}: a ticket whose server is not a host name", shown(text));
        let host = std::str::from_utf8(&bytes[FIXED..]).map_err(|_| not_host())?;
        let server = Server::new(host, port).map_err(|_| not_host())?;
        Ok(Ticket { node: PublicKey(node), derp: Key(derp), server })
    }
}

/// A ticket in a message: its start, as it may be long.
fn shown(text: &str) -> String {
    let text = podssh_ws::text::one_line(text);
    match text.char_indices().nth(24) {
        Some((cut, _)) => format!("{}...", &text[..cut]),
        None => text,
    }
}

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lower case, with no padding.
fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The bytes of [`encode`]'s word, in either case; `None` for a character
/// that is not of the alphabet, or a last one with bits left over.
fn decode(word: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(word.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in word.bytes() {
        let value = match c.to_ascii_lowercase() {
            c @ b'a'..=b'z' => c - b'a',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    (acc == 0 && bits < 5).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(host: &str, port: u16) -> Ticket {
        Ticket { node: PublicKey([1; 32]), derp: Key([2; 32]), server: Server::new(host, port).unwrap() }
    }

    #[test]
    fn rfc_4648_s_vectors_of_base32_come_out_in_lower_case() {
        // RFC 4648, section 10, with no padding.
        for (plain, word) in [("", ""), ("f", "my"), ("fo", "mzxq"), ("foo", "mzxw6"), ("foob", "mzxw6yq")] {
            assert_eq!(encode(plain.as_bytes()), word);
            assert_eq!(decode(word).unwrap(), plain.as_bytes());
        }
        assert_eq!(encode(b"foobar"), "mzxw6ytboi");
        assert_eq!(decode("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(decode("mzxw6ytboj"), None, "a last character with bits left over");
        assert_eq!(decode("mzx@"), None);
    }

    #[test]
    fn a_ticket_comes_back_as_it_went_and_holds_no_user_or_route_mark() {
        for (host, port) in [("tc301a.ipn.dev", 443), ("127.0.0.1", 8443)] {
            let t = ticket(host, port);
            let text = t.to_string();
            assert!(text.starts_with(SCHEME));
            assert!(!text.contains('@') && !text.contains('/'), "{text}");
            assert_eq!(Ticket::parse(&text), Ok(t.clone()));
            assert_eq!(Ticket::parse(&text[SCHEME.len()..]), Ok(t.clone()));
            assert_eq!(Ticket::parse(&text.to_uppercase().replace("DERP:", "derp:")), Ok(t));
        }
    }

    #[test]
    fn a_ticket_of_another_version_or_shape_is_refused_with_its_start() {
        let text = ticket("tc301a.ipn.dev", 443).to_string();
        let mut bytes = decode(&text[SCHEME.len()..]).unwrap();
        bytes[0] = 2;
        let later = format!("{SCHEME}{}", encode(&bytes));
        assert!(Ticket::parse(&later).unwrap_err().contains("version 2"));
        assert!(Ticket::parse("derp:abc").is_err());
        assert!(Ticket::parse("derp:not base32!").is_err());
        let short = format!("{SCHEME}{}", encode(&bytes[..FIXED]));
        assert!(Ticket::parse(&short).is_err());
        let err = Ticket::parse(&format!("{text}{}", "a".repeat(400))).unwrap_err();
        assert!(err.len() < 200, "{err}");
    }
}
