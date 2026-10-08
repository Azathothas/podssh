//! The three leg codecs. ⛔ **Three functions, not one function with a flag.**
//!
//! `reverse-operator.md:174-177` states the reason and podssh adopts it verbatim:
//! *"A shared `send_frame(bytes)` with an `Option<SessionId>` is how a prefix
//! gets added by accident. The operator's send path takes `&[u8]`, and the type
//! has no field that could hold an id."*
//!
//! ⛔ **So there is no `Option<SessionId>` anywhere in this module.** The only
//! function that can produce a prefixed frame is `encode_node_frame`, it takes a
//! `SessionId` and not a `Option` of one, and `encode_operator_frame` and
//! `encode_forward_frame` have no parameter that could carry one at all.

use super::{
    CodecError, SessionId, CONTROL_FRAME_MAX, NODE_FRAME_MAX_WIRE, NODE_PAYLOAD_MAX,
    OPERATOR_PAYLOAD_MAX, SESSION_ID_LEN,
};

/// ⛔ **The node leg's send path. The only place in podssh that writes a 32-byte
/// prefix, and the one place a mistake is silent.**
///
/// **READ**, spec line 140: *"Each node binary frame starts with the 32 ASCII
/// hex characters of the session id, followed by up to 64 KiB of bytes."*
/// ⛔ **And it must be ONE frame** — **READ**, `dropssh` `src/serve.c:387-391`:
/// *"Sending the id and the payload as two frames delivers the id as session data
/// to the operator and the payload with no id, which the relay closes 1009."*
pub fn encode_node_frame(id: &SessionId, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    if payload.len() > NODE_PAYLOAD_MAX {
        return Err(CodecError::FrameTooLong {
            got: SESSION_ID_LEN + payload.len(),
            max: NODE_FRAME_MAX_WIRE,
        });
    }
    let mut out = Vec::with_capacity(SESSION_ID_LEN + payload.len());
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// ⛔ **The node leg's receive path.** Every binary frame the relay forwards
/// *from* an operator is `id || payload`, and the relay adds the id itself —
/// ⛔ **the operator half is what carries no framing** (spec lines 145-148).
///
/// ⛔ **The id is validated before the caller looks anything up.** `reverse-node.md`
/// step 2 requires this: a malformed prefix is a node-side fault reported as
/// `1003 bad multiplex id`, not a hash miss that silently drops the frame.
pub fn decode_node_frame(wire: &[u8]) -> Result<(SessionId, &[u8]), CodecError> {
    if wire.len() < SESSION_ID_LEN {
        return Err(CodecError::FrameTooShort { got: wire.len() });
    }
    if wire.len() > NODE_FRAME_MAX_WIRE {
        return Err(CodecError::FrameTooLong {
            got: wire.len(),
            max: NODE_FRAME_MAX_WIRE,
        });
    }
    let id = SessionId::parse(&wire[..SESSION_ID_LEN])?;
    Ok((id, &wire[SESSION_ID_LEN..]))
}

/// ⛔ **The operator's send path. Bare payload, and there is no parameter that
/// could hold an id.**
///
/// ⛔ **A prefix invented here is not rejected by the relay — it is delivered.**
/// Spec lines 112-115, verbatim: *"the relay never reads an id out of an operator
/// frame, treats the whole frame as payload, and prepends the session's real id.
/// An id an operator sends is rewritten, not honoured."* For SSH that is 32
/// bytes of garbage ahead of the version banner, and the relay will not warn.
pub fn encode_operator_frame(payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    if payload.len() > OPERATOR_PAYLOAD_MAX {
        return Err(CodecError::OperatorPayloadTooLong {
            got: payload.len(),
            max: OPERATOR_PAYLOAD_MAX,
        });
    }
    Ok(payload.to_vec())
}

/// ⛔ **The forward path. Bare payload, and no `hello` frame exists to tell a
/// client the cap** — so the cap arrives as a value and the frame is built from
/// the payload alone.
///
/// ⛔ **Prepending the 32-byte reverse id here injects 32 bytes of garbage into
/// the SSH banner**, and this function has no id parameter to do it with.
pub fn encode_forward_frame(payload: &[u8], max_frame: usize) -> Result<Vec<u8>, CodecError> {
    if payload.len() > max_frame {
        return Err(CodecError::FrameTooLong {
            got: payload.len(),
            max: max_frame,
        });
    }
    Ok(payload.to_vec())
}

/// ⛔ **Chunk a byte stream for a leg that carries no framing of its own.**
///
/// ⛔ **Frame boundaries carry no meaning** — the relay copies payload bytes and
/// SSH is a framed protocol above it, which is what saves us (spec line 210 and
/// `01-relay-protocol.md:419-421`). So this splits on a size and never on a
/// message boundary.
///
/// **INFERRED** the choice of `CHUNK_BYTES`: it must sit under every cap at once,
/// because a single chunk goes out on whichever leg happens to be carrying the
/// stream. 65504 is under the node wire cap (65568), the operator payload cap
/// (65536) and the forward cap (262144), and ⛔ **65568 + 32 does not overflow
/// anything — 65536 + 32 *equals* 65568**; 65504 is a consequence of clamping
/// under the published payload cap, not of an overflow. `05-risk-and-open.md` R3
/// records the earlier claim that it was one.
pub const CHUNK_BYTES: usize = 65504;

/// ⛔ **Chunk for the node leg specifically.** Each chunk repeats the full 32-byte
/// id, because the relay strips exactly one prefix **per frame**
/// (`dropssh` `src/serve.c:387-391`).
pub fn chunk_for_node(id: &SessionId, bytes: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
    let mut out = Vec::new();
    if bytes.is_empty() {
        out.push(encode_node_frame(id, bytes)?);
        return Ok(out);
    }
    for chunk in bytes.chunks(NODE_PAYLOAD_MAX) {
        out.push(encode_node_frame(id, chunk)?);
    }
    Ok(out)
}

/// ⛔ **Chunk for a leg that carries bare payload.** The operator's cap is a
/// *payload* cap (spec line 184), so the bound is on the payload and there is no
/// id to account for.
pub fn chunk_for_bare(payload: &[u8], max_payload: usize) -> Result<Vec<Vec<u8>>, CodecError> {
    if max_payload == 0 {
        return Err(CodecError::OperatorPayloadTooLong { got: 1, max: 0 });
    }
    Ok(payload.chunks(max_payload).map(<[u8]>::to_vec).collect())
}

/// ⛔ **The bound a control frame is checked against, exposed so the control
/// module and the tests name the same number.**
pub const CONTROL_MAX: usize = CONTROL_FRAME_MAX;