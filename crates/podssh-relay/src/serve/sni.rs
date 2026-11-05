//! The name that a TLS client asks for, read from its ClientHello before any
//! handshake (T-649, GitHub #147): the role's listener sends a name that its
//! owner publishes to that pair's node by it ([`super::published`]), and the
//! bytes stay in the socket for whoever ends the TLS. One record of 16 KiB at
//! most is read, as TLS bounds a record (RFC 8446, section 5.1). A record
//! that is cut, one that is longer, a hello in two records, a name or a list
//! that its own lengths contradict, and anything that is no ClientHello are
//! [`Read::Not`], and go to the role's own TLS as before: a reader that
//! guessed could send a visitor to another node.

/// A record's head: its type, its version and its length.
const HEAD: usize = 5;
/// The most bytes that the reader waits for: the head and TLS's largest
/// record, 2^14 bytes.
pub const MOST: usize = HEAD + (1 << 14);
/// The record of a handshake, and the message of a ClientHello in it.
const HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: usize = 0x01;
/// The two extensions that the reader takes: server_name (RFC 6066, section
/// 3) and application_layer_protocol_negotiation (RFC 7301).
const SERVER_NAME: usize = 0;
const ALPN: usize = 16;
/// host_name, the one type of a server's name (RFC 6066, section 3).
const HOST_NAME: usize = 0;
/// The ALPN of TLS-ALPN-01's validation (RFC 8737, section 6.2).
pub const ACME_TLS_1: &[u8] = b"acme-tls/1";
/// The longest name: 253 characters, and a trailing dot.
const NAME_MOST: usize = 254;

/// What the first bytes of a connection are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    /// The start of a record of a handshake, whose rest has not come.
    More,
    /// A ClientHello, whole in its one record.
    Hello(Hello),
    /// No ClientHello that the reader takes: the role's own path.
    Not,
}

/// What a ClientHello asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// The host name of its server_name, as the client wrote it; none
    /// without one, as a client that dials an address sends none.
    pub name: Option<String>,
    /// Each protocol that it offers is `acme-tls/1`: a CA's validation, as
    /// the role's own TLS tells one (`podssh_ws::tls_server::Served`).
    pub acme: bool,
}

/// What `bytes`, the first of a connection, are: a ClientHello, a part of
/// one, or none.
pub fn read(bytes: &[u8]) -> Read {
    // A handshake's record of TLS 1.x, judged by as much of its head as came.
    match bytes {
        [] => return Read::More,
        [first, ..] if *first != HANDSHAKE => return Read::Not,
        [_, major, ..] if *major != 0x03 => return Read::Not,
        _ => {}
    }
    let Some(head) = bytes.get(..HEAD) else { return Read::More };
    let length = usize::from(u16::from_be_bytes([head[3], head[4]]));
    if length == 0 || length > MOST - HEAD {
        return Read::Not;
    }
    let Some(body) = bytes.get(HEAD..HEAD + length) else { return Read::More };
    hello(body).map_or(Read::Not, Read::Hello)
}

/// The ClientHello that fills the record `body`, or none.
fn hello(body: &[u8]) -> Option<Hello> {
    let mut record = Reader(body);
    if record.u8()? != CLIENT_HELLO {
        return None;
    }
    // The whole message in this record: a hello in two records is none.
    let length = record.u24()?;
    let mut message = Reader(record.take(length)?);
    if !record.is_empty() {
        return None;
    }
    // legacy_version and random, then legacy_session_id, cipher_suites and
    // legacy_compression_methods (RFC 8446, section 4.1.2).
    message.take(2 + 32)?;
    message.bytes8()?;
    message.bytes16()?;
    message.bytes8()?;
    let mut found = Hello { name: None, acme: false };
    // A hello of TLS 1.2 may end here, with no extensions.
    if message.is_empty() {
        return Some(found);
    }
    let mut extensions = Reader(message.bytes16()?);
    if !message.is_empty() {
        return None;
    }
    let (mut named, mut offered) = (false, false);
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.bytes16()?;
        // One of each (RFC 8446, section 4.2): a second could name another
        // node than the one that the client's TLS would take.
        match kind {
            SERVER_NAME if named => return None,
            SERVER_NAME => {
                named = true;
                found.name = Some(server_name(data)?);
            }
            ALPN if offered => return None,
            ALPN => {
                offered = true;
                found.acme = acme_alone(data)?;
            }
            _ => {}
        }
    }
    Some(found)
}

/// The host name of a server_name extension's `data`: a list that holds
/// one, of letters, digits, `-`, `_` and `.` (RFC 6066 has it ASCII); none
/// for anything else.
fn server_name(data: &[u8]) -> Option<String> {
    let mut list = Reader(data);
    let mut names = Reader(list.bytes16()?);
    let (kind, name) = (names.u8()?, names.bytes16()?);
    if !list.is_empty() || !names.is_empty() || kind != HOST_NAME {
        return None;
    }
    let fits = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.');
    if name.is_empty() || name.len() > NAME_MOST || !name.iter().all(fits) {
        return None;
    }
    std::str::from_utf8(name).ok().map(str::to_string)
}

/// Whether an ALPN extension's `data` offers `acme-tls/1` alone; none for a
/// list that its lengths contradict.
fn acme_alone(data: &[u8]) -> Option<bool> {
    let mut list = Reader(data);
    let mut protocols = Reader(list.bytes16()?);
    if !list.is_empty() {
        return None;
    }
    let (mut any, mut each) = (false, true);
    while !protocols.is_empty() {
        let protocol = protocols.bytes8()?;
        any = true;
        each &= protocol == ACME_TLS_1;
    }
    Some(any && each)
}

/// A cursor over bytes whose each read is bounded: a length past the end is
/// none, never a guess.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (taken, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(taken)
    }

    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| usize::from(b[0]))
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|b| (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }

    /// A vector with a length of one byte before it.
    fn bytes8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(n)
    }

    /// A vector with a length of two bytes before it.
    fn bytes16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
}

#[cfg(test)]
#[path = "sni_tests.rs"]
mod tests;
