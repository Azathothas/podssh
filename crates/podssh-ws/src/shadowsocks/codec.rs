//! The bytes of a stream, each way, with no I/O: the carry and the tests
//! feed them. A stream starts with its salt; then each chunk is the
//! payload's length, two bytes big-endian sealed on their own, then the
//! sealed payload. The nonce is a counter of 12 bytes, little-endian, from
//! zero, and each seal and each open takes one: a chunk takes two. A stream
//! of Shadowsocks 2022 (T-492, [`super::sip022`]) opens with its headers,
//! each one seal of the same counter, before its chunks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zeroize::Zeroizing;

use super::{sip022, stream_key, Method, TAG_LEN};
use crate::crypto::aead::{Aead, NONCE_LEN};

/// The largest payload of a chunk that podssh sends: the AEAD form's
/// length has its two high bits reserved and zero, and a chunk of SIP022,
/// whose limit is 0xFFFF, may be smaller.
pub const MAX_PAYLOAD: usize = 0x3FFF;

/// The bytes of a chunk's sealed length.
const SEALED_LEN: usize = 2 + TAG_LEN;

/// Why a stream's bytes could not be made or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkError {
    /// A sealed length did not open: another key, or bytes of no
    /// Shadowsocks server.
    Length,
    /// A length opened, and its reserved bits are set.
    TooLong(usize),
    /// A payload did not open.
    Payload,
    /// The cipher did not take its key, or a seal failed.
    Cipher,
    /// The OS gave no random bytes for a salt.
    Random,
    /// A response's fixed header of SIP022 did not open: another key, or
    /// bytes of no Shadowsocks 2022 server.
    Header,
    /// A fixed header of SIP022 opened, and its type is not a response's.
    Kind(u8),
    /// A response's timestamp is more than SIP022's window from this host's
    /// clock: `skew` seconds, the server's minus this host's, which read
    /// `now`.
    Clock { skew: i64, now: i64 },
    /// A response names another request's salt.
    Salt,
}

impl std::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkError::Length => write!(
                f,
                "its length did not open: the password or the method is not the server's, or what answered is no \
                 Shadowsocks server"
            ),
            ChunkError::TooLong(n) => write!(f, "its length {n} is above {MAX_PAYLOAD}"),
            ChunkError::Payload => write!(f, "its payload did not open"),
            ChunkError::Cipher => write!(f, "the cipher failed"),
            ChunkError::Random => write!(f, "the OS gave no random bytes for the salt"),
            ChunkError::Header => write!(
                f,
                "its header did not open: the key or the method is not the server's, or what answered is no \
                 Shadowsocks 2022 server"
            ),
            ChunkError::Kind(kind) => write!(f, "its header is of the type {kind}, not a response's"),
            ChunkError::Clock { skew, now } => write!(
                f,
                "its timestamp is {skew} s from this host's clock, which reads {}, and SIP022 takes {} s at most \
                 either way: one of the two clocks is wrong",
                crate::clock::http_date(*now),
                sip022::WINDOW_SECS
            ),
            ChunkError::Salt => write!(f, "its header names another request's salt: a replay, not this answer"),
        }
    }
}

impl std::error::Error for ChunkError {}

/// The cipher of one direction, and its counter.
struct Sealer {
    aead: Aead,
    nonce: [u8; NONCE_LEN],
}

impl Sealer {
    fn new(method: Method, master: &[u8], salt: &[u8]) -> Result<Sealer, ChunkError> {
        let key = stream_key(method, master, salt);
        let aead = Aead::new(method.aead_id(), &key).map_err(|_| ChunkError::Cipher)?;
        Ok(Sealer { aead, nonce: [0; NONCE_LEN] })
    }

    /// `plain`, sealed, after `out`.
    fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> Result<(), ChunkError> {
        let mut buffer = plain.to_vec();
        self.aead.seal_in_place(&self.nonce, &[], &mut buffer).ok_or(ChunkError::Cipher)?;
        step(&mut self.nonce);
        out.extend_from_slice(&buffer);
        Ok(())
    }

    /// `sealed`, opened in place: the plaintext's length.
    fn open(&mut self, sealed: &mut [u8]) -> Option<usize> {
        let n = self.aead.open_in_place(&self.nonce, &[], sealed)?;
        step(&mut self.nonce);
        Some(n)
    }
}

/// The next nonce: the counter plus one, as an integer of 12 bytes,
/// little-endian.
pub fn step(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

/// The sending side of a stream: its salt goes out before its first chunk.
pub struct Encoder {
    method: Method,
    sealer: Sealer,
    salt: Option<Vec<u8>>,
    /// The salt, kept: a response of SIP022 names it.
    request_salt: Vec<u8>,
}

impl Encoder {
    /// A stream whose salt comes from the OS's random source; a salt is
    /// never used twice with one key.
    pub fn new(method: Method, master: &[u8]) -> Result<Encoder, ChunkError> {
        let mut salt = vec![0u8; method.salt_len()];
        use rustls::crypto::SecureRandom as _;
        crate::crypto::random::OsRandom.fill(&mut salt).map_err(|_| ChunkError::Random)?;
        Encoder::with_salt(method, master, &salt)
    }

    /// A stream with this salt: for the tests, whose vectors fix it.
    pub fn with_salt(method: Method, master: &[u8], salt: &[u8]) -> Result<Encoder, ChunkError> {
        if salt.len() != method.salt_len() || master.len() != method.key_len() {
            return Err(ChunkError::Cipher);
        }
        let sealer = Sealer::new(method, master, salt)?;
        Ok(Encoder { method, sealer, salt: Some(salt.to_vec()), request_salt: salt.to_vec() })
    }

    /// The stream's salt, which a response of SIP022 names.
    pub fn request_salt(&self) -> &[u8] {
        &self.request_salt
    }

    /// The start of a request to the target at `address` (in SOCKS5's
    /// form), after `out`: its first chunk in the AEAD form; SIP022's fixed
    /// and variable headers, with random padding and this host's clock, in
    /// Shadowsocks 2022.
    pub fn first(&mut self, address: &[u8], out: &mut Vec<u8>) -> Result<(), ChunkError> {
        if !self.method.is_2022() {
            return self.seal(address, out);
        }
        self.first_at(address, &sip022::padding()?, sip022::now_secs(), out)
    }

    /// [`Encoder::first`] of Shadowsocks 2022 with this padding and this
    /// clock: for the tests.
    pub fn first_at(&mut self, address: &[u8], padding: &[u8], now: u64, out: &mut Vec<u8>) -> Result<(), ChunkError> {
        if let Some(salt) = self.salt.take() {
            out.extend_from_slice(&salt);
        }
        let variable = sip022::request_variable(address, padding);
        let len = u16::try_from(variable.len()).map_err(|_| ChunkError::Cipher)?;
        self.sealer.seal(&sip022::request_fixed(len, now), out)?;
        self.sealer.seal(&variable, out)
    }

    /// `data` as chunks of [`MAX_PAYLOAD`] at most, after `out`, and the
    /// salt before them the first time. No chunk is empty.
    pub fn seal(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), ChunkError> {
        if let Some(salt) = self.salt.take() {
            out.extend_from_slice(&salt);
        }
        for payload in data.chunks(MAX_PAYLOAD) {
            let len = (payload.len() as u16).to_be_bytes();
            self.sealer.seal(&len, out)?;
            self.sealer.seal(payload, out)?;
        }
        Ok(())
    }
}

/// The receiving side of a stream: the salt, then each chunk as its bytes
/// come.
pub struct Decoder {
    method: Method,
    master: Zeroizing<Vec<u8>>,
    opener: Option<Sealer>,
    buf: Vec<u8>,
    /// The payload's length, once its sealed length opened.
    pending: Option<usize>,
    /// The request's salt that a response of SIP022 must name; `None`
    /// reads a response's header and checks its type and clock alone.
    answer_to: Option<Vec<u8>>,
    /// Whether a response's fixed header of SIP022 was read.
    headed: bool,
}

impl Decoder {
    pub fn new(method: Method, master: &[u8]) -> Decoder {
        Decoder {
            method,
            master: Zeroizing::new(master.to_vec()),
            opener: None,
            buf: Vec::new(),
            pending: None,
            answer_to: None,
            headed: false,
        }
    }

    /// The decoder of the answer to the request whose salt is
    /// `request_salt`: in Shadowsocks 2022, its header must name it.
    pub fn answer(method: Method, master: &[u8], request_salt: &[u8]) -> Decoder {
        Decoder { answer_to: Some(request_salt.to_vec()), ..Decoder::new(method, master) }
    }

    /// More bytes of the peer.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Whether no byte of the peer came yet.
    pub fn untouched(&self) -> bool {
        self.opener.is_none() && self.buf.is_empty()
    }

    /// Whether the peer's salt came.
    pub fn has_salt(&self) -> bool {
        self.opener.is_some()
    }

    /// The bytes that came and are no whole chunk yet: at the end of a
    /// stream, a chunk cut short.
    pub fn buffered(&self) -> usize {
        self.buf.len() + usize::from(self.pending.is_some())
    }

    /// The plaintext of the next whole chunk; `None` until its bytes came.
    pub fn chunk(&mut self) -> Result<Option<Vec<u8>>, ChunkError> {
        if self.opener.is_none() {
            let n = self.method.salt_len();
            if self.buf.len() < n {
                return Ok(None);
            }
            let salt: Vec<u8> = self.buf.drain(..n).collect();
            self.opener = Some(Sealer::new(self.method, &self.master, &salt)?);
        }
        if self.method.is_2022() && !self.headed && !self.response_header()? {
            return Ok(None);
        }
        let Some(opener) = self.opener.as_mut() else { return Ok(None) };
        let len = match self.pending {
            Some(len) => len,
            None => {
                if self.buf.len() < SEALED_LEN {
                    return Ok(None);
                }
                let mut sealed = [0u8; SEALED_LEN];
                sealed.copy_from_slice(&self.buf[..SEALED_LEN]);
                if opener.open(&mut sealed) != Some(2) {
                    return Err(ChunkError::Length);
                }
                let len = usize::from(u16::from_be_bytes([sealed[0], sealed[1]]));
                // SIP022 takes each length of two bytes; the AEAD form keeps
                // two bits reserved.
                if len > MAX_PAYLOAD && !self.method.is_2022() {
                    return Err(ChunkError::TooLong(len));
                }
                self.buf.drain(..SEALED_LEN);
                self.pending = Some(len);
                len
            }
        };
        if self.buf.len() < len + TAG_LEN {
            return Ok(None);
        }
        let mut sealed: Vec<u8> = self.buf.drain(..len + TAG_LEN).collect();
        let n = opener.open(&mut sealed).ok_or(ChunkError::Payload)?;
        sealed.truncate(n);
        self.pending = None;
        Ok(Some(sealed))
    }

    /// A response's fixed header of SIP022, once its bytes came: checked,
    /// and the length of the first payload that follows it pending. `false`
    /// until its bytes came.
    fn response_header(&mut self) -> Result<bool, ChunkError> {
        let plain_len = sip022::response_fixed_len(self.method.salt_len());
        if self.buf.len() < plain_len + TAG_LEN {
            return Ok(false);
        }
        let Some(opener) = self.opener.as_mut() else { return Ok(false) };
        let mut sealed: Vec<u8> = self.buf[..plain_len + TAG_LEN].to_vec();
        if opener.open(&mut sealed) != Some(plain_len) {
            return Err(ChunkError::Header);
        }
        let response =
            sip022::parse_response(&sealed[..plain_len], self.method.salt_len()).ok_or(ChunkError::Header)?;
        let now = sip022::now_secs();
        match &self.answer_to {
            Some(salt) => sip022::check(&response, salt, now)?,
            None => sip022::check(&response, &response.request_salt, now)?,
        }
        self.buf.drain(..plain_len + TAG_LEN);
        self.pending = Some(usize::from(response.length));
        self.headed = true;
        Ok(true)
    }
}

/// The target in SOCKS5's form, which the first payload of a stream starts
/// with: 1 and four bytes for IPv4, 4 and sixteen for IPv6, or 3, the
/// name's length and the name; then the port, big-endian. A name is
/// checked as a target of the relay is.
pub fn address(host: &str, port: u16) -> Result<Vec<u8>, String> {
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let mut out = Vec::with_capacity(bare.len() + 4);
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(1);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(4);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            // At most 253 bytes, so its length fits the one byte.
            crate::names::check_host(bare)?;
            out.push(3);
            out.push(bare.len() as u8);
            out.extend_from_slice(bare.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// The address at the start of `bytes`: the host, the port, and the bytes
/// that it took; `None` when it is cut short, of no known type, or a name
/// that is not text. The server's side, for the tests.
pub fn parse_address(bytes: &[u8]) -> Option<(String, u16, usize)> {
    let (host, at) = match *bytes.first()? {
        1 => {
            let octets: [u8; 4] = bytes.get(1..5)?.try_into().ok()?;
            (Ipv4Addr::from(octets).to_string(), 5)
        }
        4 => {
            let octets: [u8; 16] = bytes.get(1..17)?.try_into().ok()?;
            (Ipv6Addr::from(octets).to_string(), 17)
        }
        3 => {
            let n = usize::from(*bytes.get(1)?);
            let name = bytes.get(2..2 + n)?;
            (String::from_utf8(name.to_vec()).ok()?, 2 + n)
        }
        _ => return None,
    };
    let port = bytes.get(at..at + 2)?;
    Some((host, u16::from_be_bytes([port[0], port[1]]), at + 2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::master_key;

    #[test]
    fn the_nonce_counts_little_endian_and_carries() {
        let mut nonce = [0u8; NONCE_LEN];
        step(&mut nonce);
        assert_eq!(nonce[..2], [1, 0]);
        let mut full = [0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        step(&mut full);
        assert_eq!(full[..3], [0, 0, 1]);
    }

    #[test]
    fn a_stream_comes_back_whole_in_pieces_of_any_size() {
        for method in Method::ALL {
            let master = master_key(b"pieces", method.key_len());
            let mut encoder = Encoder::new(method, &master).unwrap();
            let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
            let mut wire = Vec::new();
            encoder.seal(&data, &mut wire).unwrap();
            encoder.seal(b"more", &mut wire).unwrap();
            let mut decoder = Decoder::new(method, &master);
            let mut back = Vec::new();
            for piece in wire.chunks(7) {
                decoder.feed(piece);
                while let Some(plain) = decoder.chunk().unwrap() {
                    back.extend_from_slice(&plain);
                }
            }
            assert_eq!(back.len(), data.len() + 4, "{method:?}");
            assert!(back.starts_with(&data) && back.ends_with(b"more"), "{method:?}");
            assert_eq!(decoder.buffered(), 0);
        }
    }

    #[test]
    fn another_key_fails_at_the_length_of_the_first_chunk() {
        let method = Method::Aes256Gcm;
        let mut encoder = Encoder::new(method, &master_key(b"right", 32)).unwrap();
        let mut wire = Vec::new();
        encoder.seal(b"x", &mut wire).unwrap();
        let mut decoder = Decoder::new(method, &master_key(b"wrong", 32));
        decoder.feed(&wire);
        assert_eq!(decoder.chunk(), Err(ChunkError::Length));
    }

    #[test]
    fn a_2022_request_and_its_answer_go_through_their_headers() {
        for method in Method::SIP022 {
            let psk = vec![4u8; method.key_len()];
            let mut encoder = Encoder::new(method, &psk).unwrap();
            let mut wire = Vec::new();
            encoder.first_at(&[1, 10, 0, 0, 2, 0, 22], &[0; 5], 1_000, &mut wire).unwrap();
            // The server's side: the salt, the fixed header, the variable one.
            let n = method.salt_len();
            let mut reader = Sealer::new(method, &psk, &wire[..n]).unwrap();
            let mut fixed = wire[n..n + sip022::REQUEST_FIXED + TAG_LEN].to_vec();
            assert_eq!(reader.open(&mut fixed), Some(sip022::REQUEST_FIXED), "{method:?}");
            assert_eq!(sip022::parse_request(&fixed[..sip022::REQUEST_FIXED]), Some((sip022::REQUEST, 1_000, 14)));
            let at = n + sip022::REQUEST_FIXED + TAG_LEN;
            let mut variable = wire[at..].to_vec();
            assert_eq!(reader.open(&mut variable), Some(14));
            assert_eq!(variable[..14], [1, 10, 0, 0, 2, 0, 22, 0, 5, 0, 0, 0, 0, 0]);
            // Its answer: the fixed header names the request's salt, then
            // the first payload, then a chunk as the AEAD form makes it.
            let salt = vec![6u8; n];
            let mut writer = Sealer::new(method, &psk, &salt).unwrap();
            let mut answer = salt.clone();
            let head = sip022::response_fixed(encoder.request_salt(), 5, sip022::now_secs());
            writer.seal(&head, &mut answer).unwrap();
            writer.seal(b"hello", &mut answer).unwrap();
            writer.seal(&3u16.to_be_bytes(), &mut answer).unwrap();
            writer.seal(b"bye", &mut answer).unwrap();
            let mut decoder = Decoder::answer(method, &psk, encoder.request_salt());
            for piece in answer.chunks(5) {
                decoder.feed(piece);
            }
            assert_eq!(decoder.chunk(), Ok(Some(b"hello".to_vec())), "{method:?}");
            assert_eq!(decoder.chunk(), Ok(Some(b"bye".to_vec())), "{method:?}");
            // Another key: the header does not open.
            let mut other = Decoder::answer(method, &vec![5u8; method.key_len()], encoder.request_salt());
            other.feed(&answer);
            assert_eq!(other.chunk(), Err(ChunkError::Header), "{method:?}");
        }
    }

    #[test]
    fn an_address_has_its_type_its_bytes_and_its_port() {
        assert_eq!(address("10.0.0.2", 22).unwrap(), [1, 10, 0, 0, 2, 0, 22]);
        assert_eq!(address("example.com", 443).unwrap()[..2], [3, 11]);
        let v6 = address("[::1]", 2222).unwrap();
        assert_eq!((v6[0], v6.len()), (4, 19));
        assert_eq!(parse_address(&v6), Some(("::1".to_string(), 2222, 19)));
        assert!(address("a b", 22).is_err());
        assert_eq!(parse_address(&[3, 5, b'a']), None, "cut short");
    }
}
