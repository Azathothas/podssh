//! The codec of each leg: one function for each, and no function with an
//! optional id. A send path that took an `Option<SessionId>` is how a prefix
//! gets added by accident (dropssh's notes); the operator's path has no
//! parameter that could carry one.

use super::{
    CodecError, SessionId, CONTROL_FRAME_MAX, NODE_FRAME_MAX_WIRE, NODE_PAYLOAD_MAX, OPERATOR_PAYLOAD_MAX,
    SESSION_ID_LEN,
};

/// A node frame: the id, then the payload, in ONE frame. Sent as two frames,
/// the id reaches the operator as data, and the payload has no id, which the
/// relay closes with `1009` (dropssh, `src/serve.c`).
pub fn encode_node_frame(id: &SessionId, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    if payload.len() > NODE_PAYLOAD_MAX {
        return Err(CodecError::FrameTooLong { got: SESSION_ID_LEN + payload.len(), max: NODE_FRAME_MAX_WIRE });
    }
    let mut out = Vec::with_capacity(SESSION_ID_LEN + payload.len());
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// A frame that the relay sent to a node: its id, checked before anything is
/// looked up by it, and its payload. A bad prefix is a fault to name, not a
/// session to miss.
pub fn decode_node_frame(wire: &[u8]) -> Result<(SessionId, &[u8]), CodecError> {
    if wire.len() < SESSION_ID_LEN {
        return Err(CodecError::FrameTooShort { got: wire.len() });
    }
    if wire.len() > NODE_FRAME_MAX_WIRE {
        return Err(CodecError::FrameTooLong { got: wire.len(), max: NODE_FRAME_MAX_WIRE });
    }
    let id = SessionId::parse(&wire[..SESSION_ID_LEN])?;
    Ok((id, &wire[SESSION_ID_LEN..]))
}

/// An operator frame: the payload alone. The relay never reads an id out of
/// an operator frame; it delivers the whole frame, so an id sent here would
/// reach the node as 32 bytes of data before the SSH banner.
pub fn encode_operator_frame(payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    if payload.len() > OPERATOR_PAYLOAD_MAX {
        return Err(CodecError::OperatorPayloadTooLong { got: payload.len(), max: OPERATOR_PAYLOAD_MAX });
    }
    Ok(payload.to_vec())
}

/// The bytes read from a local side for one frame. Frame boundaries mean
/// nothing on the relay, so a stream is cut by size alone; this size is under
/// the cap of every leg.
pub const CHUNK_BYTES: usize = 65504;

/// Node frames for `bytes`: each chunk with the whole id, as the relay strips
/// one prefix for each frame.
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

/// Frames of bare payload, as the operator leg carries them: its cap is on the
/// payload, and there is no id to count.
pub fn chunk_for_bare(payload: &[u8], max_payload: usize) -> Result<Vec<Vec<u8>>, CodecError> {
    if max_payload == 0 {
        return Err(CodecError::OperatorPayloadTooLong { got: 1, max: 0 });
    }
    Ok(payload.chunks(max_payload).map(<[u8]>::to_vec).collect())
}

/// The cap of a control frame, under the name that the control module and
/// the tests use.
pub const CONTROL_MAX: usize = CONTROL_FRAME_MAX;
