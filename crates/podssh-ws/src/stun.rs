//! STUN's messages (RFC 8489), the codec alone: a Binding Request, a Binding
//! response as a server writes it, and the reading of any message, each
//! attribute's length checked before its value is read. `podssh doctor`'s
//! line `nat` asks two servers with it (T-641); the TURN road (T-621) builds
//! its attributes and MESSAGE-INTEGRITY on the same reader. Pure Rust, no
//! I/O: the caller owns the socket.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The magic cookie of each message of RFC 5389 and later (RFC 8489, 5).
pub const MAGIC: u32 = 0x2112_a442;
/// The header: the type, the length, the cookie and the transaction's id.
pub const HEADER: usize = 20;

/// A Binding Request, and the two responses to it (RFC 8489, 6 and 18.2).
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_SUCCESS: u16 = 0x0101;
pub const BINDING_ERROR: u16 = 0x0111;

/// The attributes read here (RFC 8489, 18.3). MAPPED-ADDRESS is a server's of
/// RFC 3489's age, read only where no XOR-MAPPED-ADDRESS came.
pub const MAPPED_ADDRESS: u16 = 0x0001;
pub const ERROR_CODE: u16 = 0x0009;
pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const SOFTWARE: u16 = 0x8022;

/// The families of an address attribute (RFC 8489, 14.1).
const IPV4: u8 = 0x01;
const IPV6: u8 = 0x02;

/// A transaction's id: 96 bits, random, the same on each try of a request.
pub type TransactionId = [u8; 12];

/// A message as read: its type, its transaction's id, and each attribute in
/// order, its type and its value without the padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub kind: u16,
    pub id: TransactionId,
    pub attributes: Vec<(u16, &'a [u8])>,
}

/// A Binding Request with no attribute: a header alone, which each server
/// answers (RFC 8489, 6.1).
pub fn binding_request(id: &TransactionId) -> [u8; HEADER] {
    let mut out = [0u8; HEADER];
    out[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    out[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    out[8..].copy_from_slice(id);
    out
}

/// A message of `kind` with `attributes`, each value padded with zeros to a
/// multiple of 4 bytes, as RFC 8489 (14) lays it out.
pub fn message(kind: u16, id: &TransactionId, attributes: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (attribute, value) in attributes {
        body.extend_from_slice(&attribute.to_be_bytes());
        // An attribute of more than 64 KiB is no attribute: cut, as no
        // message of this codec carries one.
        let len = value.len().min(usize::from(u16::MAX));
        body.extend_from_slice(&(len as u16).to_be_bytes());
        body.extend_from_slice(&value[..len]);
        body.resize(body.len() + padding(len), 0);
    }
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(&(kind & 0x3fff).to_be_bytes());
    out.extend_from_slice(&(body.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&body);
    out
}

/// A Binding success response that names `mapped` in XOR-MAPPED-ADDRESS, as
/// a server answers: the stand-ins of the tests write it.
pub fn binding_success(id: &TransactionId, mapped: SocketAddr) -> Vec<u8> {
    let value = write_address(mapped, Some(id));
    message(BINDING_SUCCESS, id, &[(XOR_MAPPED_ADDRESS, value.as_slice())])
}

/// The bytes that pad a value of `len` to a multiple of 4.
fn padding(len: usize) -> usize {
    (4 - len % 4) % 4
}

/// The message in `bytes`, a whole datagram: the first two bits zero, the
/// magic cookie, a length that is the rest of the datagram and a multiple of
/// 4, and each attribute with its padding inside that length. Anything else
/// is no STUN message (RFC 8489, 6.3), and why.
pub fn parse(bytes: &[u8]) -> Result<Message<'_>, String> {
    if bytes.len() < HEADER {
        return Err(format!("{} bytes, fewer than a header's 20", bytes.len()));
    }
    let kind = u16::from_be_bytes([bytes[0], bytes[1]]);
    if kind & 0xc000 != 0 {
        return Err("the first two bits are not zero".to_string());
    }
    let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != MAGIC {
        return Err("no magic cookie".to_string());
    }
    if length % 4 != 0 {
        return Err(format!("a length of {length}, not a multiple of 4"));
    }
    if HEADER + length != bytes.len() {
        return Err(format!("a length of {length} for {} bytes after the header", bytes.len() - HEADER));
    }
    let mut id = [0u8; 12];
    id.copy_from_slice(&bytes[8..HEADER]);
    let mut attributes = Vec::new();
    let mut rest = &bytes[HEADER..];
    while !rest.is_empty() {
        // The length goes with its header: neither is read past the message.
        if rest.len() < 4 {
            return Err(format!("an attribute's header cut at {} bytes", rest.len()));
        }
        let attribute = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        let whole = 4 + len + padding(len);
        if whole > rest.len() {
            return Err(format!("the attribute 0x{attribute:04x} says {len} bytes, past the message"));
        }
        attributes.push((attribute, &rest[4..4 + len]));
        rest = &rest[whole..];
    }
    Ok(Message { kind, id, attributes })
}

impl Message<'_> {
    /// The value of the first attribute of `kind`: a later one of the same
    /// type is ignored (RFC 8489, 14).
    pub fn attribute(&self, kind: u16) -> Option<&[u8]> {
        self.attributes.iter().find(|(k, _)| *k == kind).map(|(_, v)| *v)
    }

    /// The address that the server saw: XOR-MAPPED-ADDRESS, else the plain
    /// MAPPED-ADDRESS of an older server; `None` with neither, and the fault
    /// of one that does not read.
    pub fn mapped(&self) -> Option<Result<SocketAddr, String>> {
        if let Some(value) = self.attribute(XOR_MAPPED_ADDRESS) {
            return Some(read_address(value, Some(&self.id)));
        }
        self.attribute(MAPPED_ADDRESS).map(|value| read_address(value, None))
    }

    /// The error of an error response (RFC 8489, 14.8): its code, the class
    /// times 100 and the number, and its reason; `None` with no ERROR-CODE.
    pub fn error(&self) -> Option<Result<(u16, String), String>> {
        let value = self.attribute(ERROR_CODE)?;
        if value.len() < 4 {
            return Some(Err(format!("an ERROR-CODE of {} bytes", value.len())));
        }
        let (class, number) = (u16::from(value[2] & 0x07), u16::from(value[3]));
        if !(3..=6).contains(&class) || number > 99 {
            return Some(Err(format!("an ERROR-CODE of class {class} and number {number}")));
        }
        Some(Ok((class * 100 + number, String::from_utf8_lossy(&value[4..]).into_owned())))
    }
}

/// An address attribute's value (RFC 8489, 14.1 and 14.2): XORed with the
/// cookie, and for IPv6 with the transaction's id too, when `xor` names the
/// id; plain with none. The length is the family's, exactly.
pub fn read_address(value: &[u8], xor: Option<&TransactionId>) -> Result<SocketAddr, String> {
    if value.len() < 4 {
        return Err(format!("an address attribute of {} bytes", value.len()));
    }
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    let mut address = value[4..].to_vec();
    let want = match value[1] {
        IPV4 => 4,
        IPV6 => 16,
        other => return Err(format!("an address of the family {other}")),
    };
    if address.len() != want {
        return Err(format!("an address of {} bytes for the family {}", address.len(), value[1]));
    }
    if let Some(id) = xor {
        port ^= (MAGIC >> 16) as u16;
        for (byte, k) in address.iter_mut().zip(key(id)) {
            *byte ^= k;
        }
    }
    let ip = match <[u8; 16]>::try_from(address.as_slice()) {
        Ok(v6) => IpAddr::V6(Ipv6Addr::from(v6)),
        Err(_) => IpAddr::V4(Ipv4Addr::new(address[0], address[1], address[2], address[3])),
    };
    Ok(SocketAddr::new(ip, port))
}

/// An address attribute's value for `addr`, XORed as [`read_address`] reads
/// it when `xor` names the id.
pub fn write_address(addr: SocketAddr, xor: Option<&TransactionId>) -> Vec<u8> {
    let (family, mut address) = match addr.ip() {
        IpAddr::V4(v4) => (IPV4, v4.octets().to_vec()),
        IpAddr::V6(v6) => (IPV6, v6.octets().to_vec()),
    };
    let mut port = addr.port();
    if let Some(id) = xor {
        port ^= (MAGIC >> 16) as u16;
        for (byte, k) in address.iter_mut().zip(key(id)) {
            *byte ^= k;
        }
    }
    let mut out = vec![0, family];
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&address);
    out
}

/// The XOR key of an address: the cookie, then the transaction's id, of
/// which an IPv4 address takes the first 4 bytes alone.
fn key(id: &TransactionId) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&MAGIC.to_be_bytes());
    key[4..].copy_from_slice(id);
    key
}

#[cfg(test)]
#[path = "stun_tests.rs"]
mod tests;
