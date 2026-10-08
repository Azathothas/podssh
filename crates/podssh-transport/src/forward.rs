//! ⛔ **C4: the forward runner — a forward session driven over any [`Socket`].**
//!
//! The runner owns no socket and no token: it is constructed over an
//! already-connected [`Socket`] (a [`FrameQueue`] in tests, a
//! [`WsSocket`] over the C1 adapter live) and pumps bytes in both
//! directions. Dialing is `podssh-ws`'s (`connect` + the token header, E02/E12)
//! and the close-code decision is `closes`' — this file is the byte pump
//! between them, and it is deliberately the only thing here.
//!
//! ⛔ **Sends are chunked at the wire cap, never refused by it.** A payload
//! bigger than `max_wire_frame` becomes several frames; frame boundaries
//! carry no meaning on this leg (the relay copies payload bytes, and SSH
//! frames above it), so the split is on size only. An over-cap *frame* never
//! exists to be refused — [`Leg::send_data`] would refuse it, and the chunker
//! runs first so that refusal is unreachable, not merely unhit.
//!
//! ⛔ **Receives are binary or an error.** A text frame where data was
//! expected is `1003`-shaped on the wire; [`Leg::recv_data`] refuses it, and
//! this runner surfaces that rather than decoding it as data.

use crate::framing::legs::chunk_for_bare;
use crate::socket::{Leg, Socket};
use crate::transport::{LegShape, Limits};
use crate::TransportError;

/// A forward session: bare bytes out, bare bytes back.
pub struct ForwardRunner<S> {
    leg: Leg<S>,
    /// The cap sends are chunked at. Kept beside the leg (which holds its own
    /// copy) because the chunker runs *before* [`Leg::send_data`], and it
    /// needs the number without a round trip through the socket.
    limits: Limits,
}

impl<S: Socket> ForwardRunner<S> {
    /// A runner over a connected socket, with the forward cap from
    /// `/relays.json` (`Limits::forward`) or the measured record
    /// (`Limits::unmeasured_floor`) when the document could not be read.
    pub fn new(socket: S, limits: Limits) -> Self {
        Self { leg: Leg::new(socket, LegShape::Forward, limits), limits }
    }

    /// Send bytes, chunked at the wire cap. Returns the frame count, so a
    /// test can assert the split rather than "something was sent".
    pub async fn send_bytes(&mut self, bytes: &[u8]) -> Result<usize, TransportError> {
        let mut frames = 0;
        for chunk in chunk_for_bare(bytes, self.limits.max_wire_frame)? {
            self.leg.send_data(None, &chunk).await?;
            frames += 1;
        }
        Ok(frames)
    }

    /// Read one payload off the session.
    pub async fn recv_bytes(&mut self) -> Result<Vec<u8>, TransportError> {
        Ok(self.leg.recv_data().await?.payload)
    }

    /// Frames this runner has put on the wire. A refused frame is not a sent
    /// frame, and the only way to know is to count.
    pub fn sent_frames(&self) -> usize {
        self.leg.sent_frames()
    }
}
