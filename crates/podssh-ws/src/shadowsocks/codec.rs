//! The bytes of a stream, each way, with no I/O: the carry and the tests
//! feed them. A stream starts with its salt; then each chunk is the
//! payload's length, two bytes big-endian sealed on their own, then the
//! sealed payload. The nonce is a counter of 12 bytes, little-endian, from
//! zero, and each seal and each open takes one: a chunk takes two.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zeroize::Zeroizing;

use super::{subkey, Method, TAG_LEN};
use crate::crypto::aead::{Aead, NONCE_LEN};

/// The largest payload of a chunk: the length's two high bits are reserved
/// and zero.
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
        let key = subkey(master, salt);
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
    sealer: Sealer,
    salt: Option<Vec<u8>>,
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
        Ok(Encoder { sealer: Sealer::new(method, master, salt)?, salt: Some(salt.to_vec()) })
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
}

impl Decoder {
    pub fn new(method: Method, master: &[u8]) -> Decoder {
        Decoder { method, master: Zeroizing::new(master.to_vec()), opener: None, buf: Vec::new(), pending: None }
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
                if len > MAX_PAYLOAD {
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
