//! RFC 6455 framing, byte-exact.
//!
//! **Client→server frames MUST be masked** (RFC 6455 §5.3): "The masking key
//! is a 32-bit value chosen at random by the client. When preparing a masked
//! frame, the client MUST pick a fresh masking key from the set of allowed
//! 32-bit values. The masking key needs to be unpredictable; thus, the masking
//! key MUST be derived from a strong source of entropy, and the masking key
//! for a given frame MUST NOT make it simple for a server/proxy to predict the
//! masking key for a subsequent frame."
//!
//! **The mask is `transformed[i] = original[i] XOR key[i % 4]`, in that
//! order**, and getting the order wrong produces frames a server decodes
//! without error and a proxy decodes into something else — the failure mode
//! the byte-exact framing tests of `tests/rfc6455.rs` exist to catch.

use crate::error::WsError;

pub const OPCODE_CONTINUATION: u8 = 0x0;
pub const OPCODE_TEXT: u8 = 0x1;
pub const OPCODE_BINARY: u8 = 0x2;
pub const OPCODE_CLOSE: u8 = 0x8;
pub const OPCODE_PING: u8 = 0x9;
pub const OPCODE_PONG: u8 = 0xa;

/// The relay's own caps, re-measured from `/relays.json` on 2026-10-02 and
/// asserted by `podssh-probe`. **They are not the same number**: the forward
/// path caps a frame at 262144 bytes and a reverse node frame is 65568 on the
/// wire. Conflating them is the single easiest way to build the wrong client,
/// so both are named here rather than one `MAX_FRAME` constant.
pub const FORWARD_MAX_FRAME: usize = 262_144;
pub const NODE_MAX_FRAME: usize = 65_568;

/// RFC 6455 §5.5: *"All control frames MUST have a payload length of 125
/// bytes or less."* It is the cap the reader checks before it answers a
/// Ping: a larger Ping is already the peer's violation, and echoing it would
/// make podssh the side that sent an illegal control frame.
pub const MAX_CONTROL_PAYLOAD: usize = 125;

/// RFC 6455 §5.2: the length field is 7 bits, 7+16, or 7+64. 126 and 127
/// are the two values that mean "the real length is in the following 2 or 8
/// bytes", and treating either as a length is how a decoder reads a 65535-byte
/// frame as a 4 GiB one.
pub const LENGTH_16_MARKER: u8 = 126;
pub const LENGTH_64_MARKER: u8 = 127;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// **Which side is writing.** RFC 6455 §5.1: a client-to-server frame MUST
/// be masked and a server-to-client frame MUST NOT be. The direction is a
/// parameter rather than an assumption, because a decoder that assumes it can
/// accept an unmasked client frame — the exact thing §5.3 forbids — and a
/// relay that copies bytes in both directions has to know which is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// **Encode a frame for the given direction.** `masking_key` is ignored for
/// [`Role::Server`], because a masked server frame is a protocol violation and
/// producing one is worse than ignoring a key a caller happened to pass.
pub fn encode(frame: &Frame, role: Role, masking_key: [u8; 4]) -> Vec<u8> {
    let len = frame.payload.len();
    let mut out = Vec::with_capacity(len + 14);
    out.push((if frame.fin { 0x80 } else { 0x00 }) | (frame.opcode & 0x0f));

    let mask_bit = match role {
        // The mask bit is set unconditionally on the client path. RFC 6455
        // §5.3 requires it and a server tolerates its absence while every
        // proxy in between does not.
        Role::Client => 0x80u8,
        Role::Server => 0x00,
    };

    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | LENGTH_16_MARKER);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | LENGTH_64_MARKER);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }

    match role {
        Role::Server => {
            out.extend_from_slice(&frame.payload);
        }
        Role::Client => {
            out.extend_from_slice(&masking_key);
            for (i, byte) in frame.payload.iter().enumerate() {
                // **`i % 4`, and the key is applied to the payload only.**
                // Applying it to the header is the other common mistake, and
                // the server tolerates that while every proxy does not.
                out.push(byte ^ masking_key[i % 4]);
            }
        }
    }
    out
}

/// **Decode one frame from `input`, returning it and the bytes consumed.**
///
/// A short input is `Ok(None)`, not an error: a stream arrives in pieces and a
/// decoder that errored on a partial frame would break every read. A frame
/// that is *malformed* is `Err`, and that is the distinction the third plant
/// of `tests/rfc6455.rs` turns on.
pub fn decode(input: &[u8], role: Role) -> Result<Option<(Frame, usize)>, WsError> {
    if input.len() < 2 {
        return Ok(None);
    }
    let first = input[0];
    let second = input[1];
    let fin = first & 0x80 != 0;
    // RSV1-3 must be zero unless an extension negotiated them. podssh
    // negotiates no extension, so a set RSV bit is a protocol violation and is
    // refused rather than ignored — ignoring it is how a compressed frame is
    // read as raw bytes.
    if first & 0x70 != 0 {
        return Err(WsError::Frame(format!("reserved bits set (0x{first:02x}) with no extension negotiated")));
    }
    let opcode = first & 0x0f;
    if !matches!(opcode, OPCODE_CONTINUATION | OPCODE_TEXT | OPCODE_BINARY | OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG) {
        return Err(WsError::Frame(format!("opcode 0x{opcode:x} is not defined")));
    }
    let masked = second & 0x80 != 0;
    // **Direction is enforced, not assumed.** A server-to-client frame must
    // NOT be masked and a client-to-server frame MUST be, and this is the
    // check that makes "every client frame is masked" a property of the wire
    // rather than a claim about the encoder.
    if role == Role::Client && !masked {
        return Err(WsError::Frame("client-to-server frame is not masked (RFC 6455 5.3)".into()));
    }
    if role == Role::Server && masked {
        return Err(WsError::Frame("server-to-client frame is masked (RFC 6455 5.1)".into()));
    }

    let mut cursor = 2usize;
    let len7 = (second & 0x7f) as usize;
    let payload_len = match len7 {
        // The markers are compared as `usize` because `len7` is, and a
        // `u8` marker in a `usize` match arm does not compile — which is the
        // type system refusing to let the 7-bit field be read as a length.
        n if n == LENGTH_16_MARKER as usize => {
            if input.len() < cursor + 2 {
                return Ok(None);
            }
            let v = u16::from_be_bytes([input[cursor], input[cursor + 1]]) as usize;
            cursor += 2;
            v
        }
        n if n == LENGTH_64_MARKER as usize => {
            if input.len() < cursor + 8 {
                return Ok(None);
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&input[cursor..cursor + 8]);
            let v = u64::from_be_bytes(buf);
            cursor += 8;
            // A 64-bit length is checked before it is cast. Truncating it to
            // a `usize` and then allocating is how a peer turns four bytes of
            // its own output into an allocation of gigabytes.
            if v > usize::MAX as u64 {
                return Err(WsError::Frame(format!("frame length {v} exceeds this platform")));
            }
            if v > FORWARD_MAX_FRAME as u64 {
                return Err(WsError::Frame(format!("frame length {v} exceeds the forward cap of {FORWARD_MAX_FRAME}")));
            }
            v as usize
        }
        other => other,
    };

    if payload_len > FORWARD_MAX_FRAME {
        return Err(WsError::Frame(format!(
            "frame length {payload_len} exceeds the forward cap of {FORWARD_MAX_FRAME}"
        )));
    }

    // Checked as soon as the length is known, before the payload arrives.
    // RFC 6455 section 5.5: a control frame (Close, Ping, Pong) is never
    // fragmented and carries 125 bytes or less. Section 5.5.1: a Close carries
    // nothing, or a 2-byte code and a reason; 1 byte is half a code.
    if opcode >= OPCODE_CLOSE {
        if !fin {
            return Err(WsError::Frame(format!("control frame 0x{opcode:x} is fragmented; RFC 6455 5.5 forbids it")));
        }
        if payload_len > MAX_CONTROL_PAYLOAD {
            return Err(WsError::Frame(format!(
                "control frame 0x{opcode:x} carries {payload_len} bytes; RFC 6455 5.5 allows {MAX_CONTROL_PAYLOAD}"
            )));
        }
        if opcode == OPCODE_CLOSE && payload_len == 1 {
            return Err(WsError::Frame(
                "a Close frame of 1 byte holds half a status code; RFC 6455 5.5.1 forbids it".into(),
            ));
        }
    }

    let masking_key = if masked {
        if input.len() < cursor + 4 {
            return Ok(None);
        }
        let mut key = [0u8; 4];
        key.copy_from_slice(&input[cursor..cursor + 4]);
        cursor += 4;
        Some(key)
    } else {
        None
    };

    if input.len() < cursor + payload_len {
        return Ok(None);
    }
    let mut payload = input[cursor..cursor + payload_len].to_vec();
    if let Some(key) = masking_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }
    Ok(Some((Frame { fin, opcode, payload }, cursor + payload_len)))
}

/// **The mask is a bijection, so encode-then-decode is the identity.** This
/// is what makes masking testable without a peer: if `apply_mask` were not its
/// own inverse the relay would receive different bytes than podssh sent, and
/// nothing in a unit test would notice.
pub fn apply_mask(data: &mut [u8], key: [u8; 4]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }
}
