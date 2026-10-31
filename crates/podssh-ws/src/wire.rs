//! Frames on a stream, as each side writes them and reads the other's
//! (RFC 6455 section 5.1): a client masks each frame with a fresh key, a
//! server masks none, and each side takes only the other's kind. A session
//! is a client's unless it is made a server's (T-368, `podssh pipe
//! ws-listen:`).

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::client::Event;
use crate::error::{SessionError, WsError};
use crate::frame::{self, Frame, Role};

/// Decode at most one frame of `sender`'s from the front of `buf`, leaving
/// exactly the bytes not yet consumed (one read can carry several frames).
/// A Ping is an event to answer, not a frame to return.
pub fn next_event_from(buf: &mut Vec<u8>, sender: Role, cap: usize) -> Result<Option<Event>, WsError> {
    let Some((frame, used)) = frame::decode_capped(buf, sender, cap)? else {
        return Ok(None);
    };
    buf.drain(..used);
    if frame.opcode == frame::OPCODE_PING {
        return Ok(Some(Event::Pong(frame.payload)));
    }
    Ok(Some(Event::Frame(frame)))
}

/// Write one frame as `role` writes it: a client's masked with a fresh key
/// (RFC 6455 section 5.3 requires a new key for each frame, and a client has
/// no unmasked path), a server's with no mask (section 5.1).
pub async fn write_frame_as<S>(stream: &mut S, role: Role, opcode: u8, payload: &[u8]) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    let key = match role {
        // No bytes for a masking key: the frame cannot be sent (RFC 6455 5.3).
        Role::Client => crate::handshake::masking_key().map_err(no_key)?,
        // `encode` writes no key for a server.
        Role::Server => [0; 4],
    };
    let bytes = frame::encode(&Frame { fin: true, opcode, payload: payload.to_vec() }, role, key);
    stream.write_all(&bytes).await.map_err(|e| SessionError::io(&e))?;
    stream.flush().await.map_err(|e| SessionError::io(&e))
}

fn no_key(e: WsError) -> SessionError {
    SessionError::Io { kind: std::io::ErrorKind::Other, text: e.to_string() }
}
