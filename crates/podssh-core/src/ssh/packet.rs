//! RFC 4253 §6: the binary packet protocol.
//!
//! ```text
//! uint32    packet_length
//! byte      padding_length
//! byte[n1]  payload; n1 = packet_length - padding_length - 1
//! byte[n2]  random padding; n2 = padding_length
//! byte[m]   mac (not here — `cipher.rs` owns everything after NEWKEYS)
//! ```
//!
//! ⛔ This codec is plaintext-only. After NEWKEYS the length field is
//! encrypted and the MAC covers the sequence number, so a plaintext decoder
//! pointed at ciphertext misframes *silently* — `cipher.rs` (Task 3) owns the
//! encrypted path and this decoder is never called past the KEXINIT exchange.

use rand::RngCore;

/// A decoded packet: the payload the MAC (if any) already covered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub payload: Vec<u8>,
}

/// Transport-layer message numbers this crate speaks (RFC 4253 §11).
/// Grown per task; unknown ids are refused by the caller, never guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgId {
    ServiceRequest = 5,
    ServiceAccept = 6,
    KexInit = 20,
    NewKeys = 21,
}

impl MsgId {
    pub fn of(byte: u8) -> Option<Self> {
        Some(match byte {
            5 => Self::ServiceRequest,
            6 => Self::ServiceAccept,
            20 => Self::KexInit,
            21 => Self::NewKeys,
            _ => return None,
        })
    }
}

/// Why a byte stream is not packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// Fewer bytes than a length field: wait for more, do not guess.
    NeedMore,
    /// `padding_length` below 4 or past the packet end (RFC 4253 §6, and
    /// OpenSSH enforces >= 4 — a shorter padding under-reports the payload
    /// end, which is how a peer smuggles bytes past the MAC).
    BadPadding { padding_length: u8, packet_length: u32 },
    /// The total is not a multiple of the cipher block size.
    BadAlignment { total: usize, block_size: usize },
    /// A length field bigger than any packet this client accepts (64 KiB —
    /// RFC 4253 §6.1 caps implementations at 35000, and anything above that
    /// is a peer violating the SHOULD, not a packet to buffer).
    LengthTooLarge { packet_length: u32 },
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedMore => write!(f, "fewer bytes than a packet header; need more"),
            Self::BadPadding { padding_length, packet_length } => write!(
                f,
                "padding_length {padding_length} illegal for packet_length {packet_length}"
            ),
            Self::BadAlignment { total, block_size } => {
                write!(f, "packet of {total} bytes is not a multiple of block size {block_size}")
            }
            Self::LengthTooLarge { packet_length } => {
                write!(f, "packet_length {packet_length} exceeds the 64 KiB cap")
            }
        }
    }
}

impl std::error::Error for PacketError {}

/// Largest `packet_length` accepted: 65535 (the field is u32, the peer SHOULD
/// stay under 35000 — buffering more is a memory decision, not a parse).
pub const MAX_PACKET_LENGTH: u32 = 65535;

/// Encode one plaintext packet. `block_size` is 8 pre-kex (RFC 4253 §6:
/// "the total length ... MUST be a multiple of the cipher block size or 8,
/// whichever is larger") and the cipher's block size after NEWKEYS — the
/// caller names it, because this codec refuses to guess which side of the
/// boundary it is on.
///
/// ⛔ This aligns the TOTAL (length field included): correct for every
/// cipher that encrypts the length. Ciphers that leave the length open
/// (AES-GCM per RFC 5647 §7.2, where the PT itself must be the multiple)
/// use [`encode_packet_open_length`] instead — calling this one for GCM
/// produces a PT that is 4 mod 16, which a strict server refuses.
pub fn encode_packet(payload: &[u8], block_size: usize) -> Vec<u8> {
    let block = block_size.max(8);
    // 4 (length) + 1 (padding_length) + payload + padding ≡ 0 (mod block),
    // with padding >= 4. Solve for the smallest such padding.
    let mut padding_length = block - ((4 + 1 + payload.len()) % block);
    if padding_length < 4 {
        padding_length += block;
    }
    let packet_length = (1 + payload.len() + padding_length) as u32;
    let mut out = Vec::with_capacity(4 + packet_length as usize);
    out.extend_from_slice(&packet_length.to_be_bytes());
    out.push(padding_length as u8);
    out.extend_from_slice(payload);
    let mut pad = vec![0u8; padding_length];
    rand::thread_rng().fill_bytes(&mut pad);
    out.extend_from_slice(&pad);
    out
}

/// Encode one packet whose length field stays OPEN (AES-GCM, RFC 5647 §7.2):
/// here it is `1 + payload + padding ≡ 0 (mod block)` with padding >= 4 —
/// the PT, not the total, is the multiple. Two functions because they are
/// two rules; a flag choosing between them would let a caller pick GCM
/// framing for a length-encrypting cipher by typo.
pub fn encode_packet_open_length(payload: &[u8], block_size: usize) -> Vec<u8> {
    let block = block_size.max(8);
    let mut padding_length = block - ((1 + payload.len()) % block);
    if padding_length < 4 {
        padding_length += block;
    }
    let packet_length = (1 + payload.len() + padding_length) as u32;
    let mut out = Vec::with_capacity(4 + packet_length as usize);
    out.extend_from_slice(&packet_length.to_be_bytes());
    out.push(padding_length as u8);
    out.extend_from_slice(payload);
    let mut pad = vec![0u8; padding_length];
    rand::thread_rng().fill_bytes(&mut pad);
    out.extend_from_slice(&pad);
    out
}

/// A push-buffer framing plaintext packets. `NeedMore` is not an error to
/// propagate — it is the caller told to read more bytes.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes; returns every complete packet now available. A corrupt
    /// header aborts the stream (the bytes are dropped with it) because a
    /// decoder that skips ahead re-syncs on attacker-chosen bytes.
    pub fn push(&mut self, bytes: &[u8], block_size: usize) -> Result<Vec<Packet>, PacketError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                return Ok(out);
            }
            let packet_length =
                u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]);
            if packet_length > MAX_PACKET_LENGTH {
                self.buf.clear();
                return Err(PacketError::LengthTooLarge { packet_length });
            }
            let total = 4 + packet_length as usize;
            if self.buf.len() < total {
                return Ok(out);
            }
            let padding_length = self.buf[4];
            // RFC 4253 §6: padding_length MUST be at least 4 in practice —
            // OpenSSH enforces >= 4, and a 0..3 padding under-reports the
            // payload end, which is how a peer smuggles bytes past the MAC.
            if padding_length < 4 || (padding_length as usize) + 1 > packet_length as usize {
                self.buf.clear();
                return Err(PacketError::BadPadding { padding_length, packet_length });
            }
            let block = block_size.max(8);
            if total % block != 0 {
                self.buf.clear();
                return Err(PacketError::BadAlignment { total, block_size: block });
            }
            let payload_end = 4 + packet_length as usize - padding_length as usize;
            out.push(Packet { payload: self.buf[5..payload_end].to_vec() });
            self.buf.drain(..total);
        }
    }

    /// Bytes held waiting for the rest of a packet.
    pub fn pending_len(&self) -> usize {
        self.buf.len()
    }
}
