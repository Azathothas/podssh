//! The encrypted transport (NEWKEYS onward): chacha20-poly1305@openssh.com
//! and aes128-gcm@openssh.com (RFC 5647, fetched verbatim 2026-10-08).
//!
//! ⛔ No crypto is implemented here. AEAD comes from `aes-gcm`; the chacha
//! construction is assembled from `ChaCha20Legacy` (64-bit nonce) + `Poly1305`
//! because no crate ships OpenSSH's layout. The layout below is the
//! security-critical content of this file:
//!
//! - chacha: 64 direction bytes from KDF `C`/`D`; K1 = `[0..32]` encrypts the
//!   payload, K2 = `[32..64]` encrypts the 4-byte length (each its own
//!   counter-0 stream under nonce BE64(seqno)); the Poly1305 one-time key is
//!   the first 32 bytes of the K1 stream; the tag covers encrypted-length ||
//!   encrypted-payload. The K1/K2 assignment and the nonce order are the two
//!   facts Task 6 verifies live against OpenSSH — a wrong guess fails closed
//!   (auth failure), never silently.
//! - GCM-128: enc key KDF `C`/`D` (16 B), IV KDF `A`/`B` (12 B); nonce =
//!   fixed[0..4] || BE64(counter), counter starting at the IV's last 8 bytes
//!   (RFC 5647 §7.1's plain reading); length stays plaintext and is the AAD.
//!
//! ⛔ Rekeying is refused in v1 — but the refusal lives in the session driver
//! (Task 6), which is the only layer that sees message ids: a KEXINIT
//! arriving after NEWKEYS is an error, never a silent second handshake. This
//! file never sees ids, so it cannot enforce that; the driver test will.

use crate::ssh::keys::derive_key;
use crate::ssh::packet::PacketError;

/// Which AEAD protects a direction pair. Both directions of one session
/// share the kind (selected once, in `kex::select`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Chacha20Poly1305,
    Aes128Gcm,
}

impl CipherKind {
    pub fn for_name(name: &str) -> Option<Self> {
        Some(match name {
            "chacha20-poly1305@openssh.com" => Self::Chacha20Poly1305,
            "aes128-gcm@openssh.com" => Self::Aes128Gcm,
            _ => return None,
        })
    }
}

/// Why an encrypted stream is not packets. Auth failure is one variant with
/// no detail — distinguishing "wrong key" from "wrong nonce" is an oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    Packet(PacketError),
    /// Tag mismatch, short tag, or undecryptable length: one variant.
    AuthFailed,
    /// A direction key is not the length its cipher needs — a programming
    /// error surfaced as an error, never a panic.
    BadKeyLength { cipher: &'static str, bytes: usize },
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Packet(e) => write!(f, "{e}"),
            Self::AuthFailed => write!(f, "authenticated decryption failed"),
            Self::BadKeyLength { cipher, bytes } => {
                write!(f, "{cipher} key is {bytes} bytes")
            }
        }
    }
}

impl std::error::Error for CipherError {}

impl From<PacketError> for CipherError {
    fn from(e: PacketError) -> Self {
        Self::Packet(e)
    }
}

const TAG_LEN: usize = 16;

/// Which side of the session this state speaks. Key letters are defined
/// from the client's perspective (RFC 4253 §7.2: C/D are client-to-server
/// and server-to-client), so the two ends MUST construct opposite roles —
/// two client roles in one session never agree, and the failure is an auth
/// failure, not an error naming the mixup. The round-trip test pins this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Both directions' key material, derived once at NEWKEYS.
pub struct CipherState {
    kind: CipherKind,
    send_key: Vec<u8>,
    send_fixed: [u8; 4],
    send_ctr: u64,
    send_seq: u32,
    recv_key: Vec<u8>,
    recv_fixed: [u8; 4],
    recv_ctr: u64,
    recv_seq: u32,
}

impl CipherState {
    /// Derive every key from K, H, session_id (RFC 4253 §7.2 letters),
    /// crossed by role: the client's send keys are the server's receive keys.
    pub fn new(kind: CipherKind, k: &[u8], h: &[u8; 32], session_id: &[u8], role: Role) -> Self {
        let (key_len, iv_len) = match kind {
            CipherKind::Chacha20Poly1305 => (64, 0),
            CipherKind::Aes128Gcm => (16, 12),
        };
        let (send_letter, recv_letter) = match role {
            Role::Client => (b'C', b'D'),
            Role::Server => (b'D', b'C'),
        };
        let (send_iv_letter, recv_iv_letter) = match role {
            Role::Client => (b'A', b'B'),
            Role::Server => (b'B', b'A'),
        };
        let send_key = derive_key(k, h, send_letter, session_id, key_len);
        let recv_key = derive_key(k, h, recv_letter, session_id, key_len);
        let (send_fixed, send_ctr, recv_fixed, recv_ctr) = if iv_len == 0 {
            ([0u8; 4], 0, [0u8; 4], 0)
        } else {
            let siv = derive_key(k, h, send_iv_letter, session_id, iv_len);
            let riv = derive_key(k, h, recv_iv_letter, session_id, iv_len);
            (
                [siv[0], siv[1], siv[2], siv[3]],
                u64::from_be_bytes(siv[4..12].try_into().expect("12-byte IV")),
                [riv[0], riv[1], riv[2], riv[3]],
                u64::from_be_bytes(riv[4..12].try_into().expect("12-byte IV")),
            )
        };
        Self {
            kind,
            send_key,
            send_fixed,
            send_ctr,
            send_seq: 0,
            recv_key,
            recv_fixed,
            recv_ctr,
            recv_seq: 0,
        }
    }

    /// Seal one payload: frame it, encrypt it, tag it. Returns the complete
    /// wire bytes (length || ciphertext || tag).
    pub fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>, CipherError> {
        use crate::ssh::packet::{encode_packet, encode_packet_open_length};
        let packet = match self.kind {
            CipherKind::Chacha20Poly1305 => encode_packet(payload, 8),
            CipherKind::Aes128Gcm => encode_packet_open_length(payload, 16),
        };
        let out = match self.kind {
            CipherKind::Chacha20Poly1305 => seal_chacha(&self.send_key, self.send_seq, &packet)?,
            CipherKind::Aes128Gcm => {
                seal_gcm(&self.send_key, &self.send_fixed, self.send_ctr, &packet)?
            }
        };
        self.send_seq = self.send_seq.wrapping_add(1);
        self.send_ctr = self.send_ctr.wrapping_add(1);
        Ok(out)
    }

    /// Open one decrypted packet body into its payload. Alignment follows
    /// the cipher's framing rule (length-inside for chacha, length-open
    /// for GCM) — the same rule `seal` framed with, checked here.
    fn strip(&self, packet: &[u8]) -> Result<Vec<u8>, CipherError> {
        if packet.len() < 5 {
            return Err(CipherError::Packet(PacketError::BadAlignment {
                total: packet.len(),
                block_size: 8,
            }));
        }
        let packet_length =
            u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
        let padding_length = packet[4] as usize;
        if packet_length + 4 != packet.len() || padding_length < 4 || padding_length + 1 > packet_length
        {
            return Err(CipherError::Packet(PacketError::BadPadding {
                padding_length: packet[4],
                packet_length: packet_length as u32,
            }));
        }
        let aligned = match self.kind {
            CipherKind::Chacha20Poly1305 => packet.len() % 8 == 0,
            CipherKind::Aes128Gcm => (packet.len() - 4) % 16 == 0,
        };
        if !aligned {
            return Err(CipherError::Packet(PacketError::BadAlignment {
                total: packet.len(),
                block_size: 16,
            }));
        }
        Ok(packet[5..5 + packet_length - padding_length - 1].to_vec())
    }
}

/// A push-buffer that decrypts and frames: bytes in, verified payloads out.
/// Length handling differs per cipher (encrypted for chacha, plaintext AAD
/// for GCM), so this cannot reuse `packet::Decoder` until after decryption.
pub struct SecureDecoder {
    state: CipherState,
    buf: Vec<u8>,
}

impl SecureDecoder {
    pub fn new(state: CipherState) -> Self {
        Self { state, buf: Vec::new() }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, CipherError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            match self.state.kind {
                CipherKind::Chacha20Poly1305 => {
                    if self.buf.len() < 4 {
                        return Ok(out);
                    }
                    // Length decrypt needs no tag: solve for packet_length
                    // from the first 4 bytes, then demand the whole packet.
                    let mut len_ct = [0u8; 4];
                    len_ct.copy_from_slice(&self.buf[..4]);
                    let packet_length = open_chacha_length(
                        &self.state.recv_key,
                        self.state.recv_seq,
                        &len_ct,
                    )? as usize;
                    if packet_length > crate::ssh::packet::MAX_PACKET_LENGTH as usize {
                        return Err(CipherError::Packet(PacketError::LengthTooLarge {
                            packet_length: packet_length as u32,
                        }));
                    }
                    let total = 4 + packet_length + TAG_LEN;
                    if self.buf.len() < total {
                        return Ok(out);
                    }
                    let packet: Vec<u8> = self.buf.drain(..total).collect();
                    let plain = open_chacha_packet(
                        &self.state.recv_key,
                        self.state.recv_seq,
                        &packet,
                        packet_length,
                    )?;
                    self.state.recv_seq = self.state.recv_seq.wrapping_add(1);
                    out.push(self.state.strip(&plain)?);
                }
                CipherKind::Aes128Gcm => {
                    if self.buf.len() < 4 {
                        return Ok(out);
                    }
                    let packet_length = u32::from_be_bytes([
                        self.buf[0], self.buf[1], self.buf[2], self.buf[3],
                    ]) as usize;
                    if packet_length > crate::ssh::packet::MAX_PACKET_LENGTH as usize {
                        return Err(CipherError::Packet(PacketError::LengthTooLarge {
                            packet_length: packet_length as u32,
                        }));
                    }
                    let total = 4 + packet_length + TAG_LEN;
                    if self.buf.len() < total {
                        return Ok(out);
                    }
                    let packet: Vec<u8> = self.buf.drain(..total).collect();
                    let plain = open_gcm_packet(
                        &self.state.recv_key,
                        &self.state.recv_fixed,
                        self.state.recv_ctr,
                        &packet,
                        packet_length,
                    )?;
                    self.state.recv_seq = self.state.recv_seq.wrapping_add(1);
                    self.state.recv_ctr = self.state.recv_ctr.wrapping_add(1);
                    out.push(self.state.strip(&plain)?);
                }
            }
        }
    }
}

// ── chacha20-poly1305@openssh.com ──────────────────────────────────────────

use chacha20::ChaCha20Legacy;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

fn chacha_key(key: &[u8]) -> Result<[u8; 32], CipherError> {
    key.try_into().map_err(|_| CipherError::BadKeyLength { cipher: "chacha", bytes: key.len() })
        .map(|b: &[u8; 32]| *b)
}

/// Fresh stream per packet: no cross-packet counter state to corrupt, and
/// key setup is microseconds next to a network round trip. The nonce is the
/// seqno zero-extended to 64 bits big-endian (OpenSSH `POKE_U64(seqnr)`).
fn chacha_stream(key32: &[u8; 32], seq: u32) -> ChaCha20Legacy {
    use cipher::generic_array::GenericArray;
    let key = GenericArray::from(*key32);
    let nonce = GenericArray::from((seq as u64).to_be_bytes());
    ChaCha20Legacy::new(&key, &nonce)
}

fn poly_tag(poly_key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    use cipher::KeyInit;
    let mac = poly1305::Poly1305::new_from_slice(poly_key).expect("32-byte poly key");
    // ⛔ `compute_unpadded` consumes: one call, one tag, no streaming state.
    mac.compute_unpadded(data).into()
}

fn seal_chacha(key64: &[u8], seq: u32, packet: &[u8]) -> Result<Vec<u8>, CipherError> {
    if key64.len() != 64 {
        return Err(CipherError::BadKeyLength { cipher: "chacha", bytes: key64.len() });
    }
    let (k1, k2) = (chacha_key(&key64[..32])?, chacha_key(&key64[32..])?);
    let mut poly_src = [0u8; 32];
    chacha_stream(&k1, seq).apply_keystream(&mut poly_src);
    let mut ct_len = [0u8; 4];
    ct_len.copy_from_slice(&packet[..4]);
    chacha_stream(&k2, seq).apply_keystream(&mut ct_len);
    let mut ct_rest = packet[4..].to_vec();
    let mut pay = chacha_stream(&k1, seq);
    pay.seek(64u64);
    pay.apply_keystream(&mut ct_rest);
    let mut mac_input = Vec::with_capacity(4 + ct_rest.len());
    mac_input.extend_from_slice(&ct_len);
    mac_input.extend_from_slice(&ct_rest);
    let tag = poly_tag(&poly_src, &mac_input);
    let mut out = Vec::with_capacity(4 + ct_rest.len() + TAG_LEN);
    out.extend_from_slice(&ct_len);
    out.extend_from_slice(&ct_rest);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn open_chacha_length(key64: &[u8], seq: u32, len_ct: &[u8; 4]) -> Result<u32, CipherError> {
    if key64.len() != 64 {
        return Err(CipherError::BadKeyLength { cipher: "chacha", bytes: key64.len() });
    }
    let k2 = chacha_key(&key64[32..])?;
    let mut len = *len_ct;
    chacha_stream(&k2, seq).apply_keystream(&mut len);
    Ok(u32::from_be_bytes(len))
}

fn open_chacha_packet(
    key64: &[u8],
    seq: u32,
    packet: &[u8],
    packet_length: usize,
) -> Result<Vec<u8>, CipherError> {
    if key64.len() != 64 || packet.len() != 4 + packet_length + TAG_LEN {
        return Err(CipherError::AuthFailed);
    }
    let (k1, _) = (chacha_key(&key64[..32])?, chacha_key(&key64[32..])?);
    let body = &packet[..4 + packet_length];
    let tag: [u8; 16] = packet[4 + packet_length..].try_into().map_err(|_| CipherError::AuthFailed)?;
    let mut poly_src = [0u8; 32];
    chacha_stream(&k1, seq).apply_keystream(&mut poly_src);
    let expect = poly_tag(&poly_src, body);
    // ⛔ Constant-time compare by construction: XOR-fold, no early exit.
    if expect.iter().zip(tag.iter()).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {
        return Err(CipherError::AuthFailed);
    }
    // Length under K2 (like the probe), payload under K1 from block 1 (like
    // the seal) — the two streams are independent, so decrypt separately.
    let k2 = chacha_key(&key64[32..])?;
    let mut len_plain = [packet[0], packet[1], packet[2], packet[3]];
    chacha_stream(&k2, seq).apply_keystream(&mut len_plain);
    let mut rest = packet[4..4 + packet_length].to_vec();
    let mut pay = chacha_stream(&k1, seq);
    pay.seek(64u64);
    pay.apply_keystream(&mut rest);
    let mut full = len_plain.to_vec();
    full.extend_from_slice(&rest);
    Ok(full)
}

// ── aes128-gcm@openssh.com (RFC 5647) ──────────────────────────────────────

fn gcm_nonce(fixed: &[u8; 4], ctr: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(fixed);
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    n
}

fn seal_gcm(key16: &[u8], fixed: &[u8; 4], ctr: u64, packet: &[u8]) -> Result<Vec<u8>, CipherError> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key16)
        .map_err(|_| CipherError::BadKeyLength { cipher: "aes128-gcm", bytes: key16.len() })?;
    let mut out = packet.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&gcm_nonce(fixed, ctr).into(), &packet[..4], &mut out[4..])
        .map_err(|_| CipherError::AuthFailed)?;
    out.extend_from_slice(tag.as_slice());
    Ok(out)
}

fn open_gcm_packet(
    key16: &[u8],
    fixed: &[u8; 4],
    ctr: u64,
    packet: &[u8],
    packet_length: usize,
) -> Result<Vec<u8>, CipherError> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    if packet.len() != 4 + packet_length + TAG_LEN {
        return Err(CipherError::AuthFailed);
    }
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key16)
        .map_err(|_| CipherError::BadKeyLength { cipher: "aes128-gcm", bytes: key16.len() })?;
    let mut plain = packet[..4 + packet_length].to_vec();
    let tag = aes_gcm::Tag::from_slice(&packet[4 + packet_length..]);
    cipher
        .decrypt_in_place_detached(&gcm_nonce(fixed, ctr).into(), &packet[..4], &mut plain[4..], tag)
        .map_err(|_| CipherError::AuthFailed)?;
    Ok(plain)
}
