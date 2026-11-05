//! The channel after its handshake. Each message is encrypted with the next
//! nonce of its direction, counted by each end from 0: a message that is
//! changed, dropped, repeated or out of order fails its check, and ends the
//! session.
//!
//! Each direction ends with `END`. The stream under the channel is shut only
//! when both directions have ended: the resumable layer ends a session when
//! one side's bytes end, so a shut at the first `END` would end the session
//! before the other direction's last bytes. A session over the channel thus
//! has the half-close of TCP, and a stream that ends with no `END` is a cut.
//!
//! Between two ends that said they read the net's document (T-429), a
//! message `NET` carries one; it goes to the binary's [`Docs`], never to
//! the session's bytes. A verdict that lets in may carry the seed of the
//! session's tokens of one leg (T-615), which the operator's end keeps.
//!
//! A node's carry stops between two messages when a handover asks
//! ([`carry`], T-668), and the next binary goes on from the same nonces,
//! with the keys that the handshake split.

mod carry;

use std::sync::Arc;

use snow::StatelessTransportState;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub use carry::{Carried, Held, Start};

use super::frame::{self, END, NET, VERDICT};
use super::net::Docs;
use super::{Error, Refusal, MAX_DATA, MAX_MESSAGE, TAG};
use crate::identity::PublicKey;

/// The channel over `transport`, after its handshake.
pub struct Channel<T> {
    transport: T,
    state: StatelessTransportState,
    /// The nonce of the next message out.
    sent: u64,
    /// The nonce of the next message in.
    received: u64,
    /// Where a document of the net from the peer goes, and the peer's key,
    /// when both ends read them.
    net: Option<(Arc<dyn Docs>, PublicKey)>,
    /// The seed of the session's tokens of one leg that the node's verdict
    /// gave (T-615), at the operator's end.
    seed: Option<Zeroizing<[u8; 32]>>,
    /// The keys that the handshake split, the initiator's then the
    /// responder's, at a node's end: what a handover gives the next binary
    /// (T-668).
    keys: Option<Zeroizing<[u8; 64]>>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Channel<T> {
    pub(super) fn new(transport: T, state: StatelessTransportState) -> Self {
        Channel { transport, state, sent: 0, received: 0, net: None, seed: None, keys: None }
    }

    /// This channel, with the keys of its handshake (T-668).
    pub(super) fn with_keys(mut self, keys: Zeroizing<[u8; 64]>) -> Self {
        self.keys = Some(keys);
        self
    }

    /// A channel that the binary before this one handed over (T-668): its
    /// transport from the keys, and its nonces where they were.
    pub(super) fn restored(
        transport: T,
        state: StatelessTransportState,
        nonces: (u64, u64),
        keys: Zeroizing<[u8; 64]>,
    ) -> Self {
        let (sent, received) = nonces;
        Channel { transport, state, sent, received, net: None, seed: None, keys: Some(keys) }
    }

    /// Both ends read the net's documents: one from the peer goes to `docs`.
    pub(super) fn set_net(&mut self, docs: Arc<dyn Docs>, peer: PublicKey) {
        self.net = Some((docs, peer));
    }

    /// Send this end's document of the net, of [`MAX_DATA`] bytes at most.
    pub(super) async fn send_net(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > MAX_DATA {
            return Err(Error::Malformed(format!("a document of the net of {} bytes", bytes.len())));
        }
        send(&self.state, &mut self.sent, &mut self.transport, NET, bytes).await
    }

    /// The peer's document of the net, which its proof said would follow.
    pub(super) async fn read_net(&mut self) -> Result<Vec<u8>, Error> {
        let (mut cipher, mut plain) = (Vec::new(), vec![0u8; MAX_MESSAGE]);
        match receive(&self.state, &mut self.received, &mut self.transport, &mut cipher, &mut plain).await? {
            None => Err(Error::Cut),
            Some((NET, n)) => Ok(plain[1..n].to_vec()),
            Some((kind, _)) => Err(Error::Malformed(format!("a message of type {kind} where the net's document was"))),
        }
    }

    pub(super) async fn send_verdict(&mut self, answer: &Result<(), Refusal>) -> Result<(), Error> {
        self.send_verdict_with(answer, None).await
    }

    /// [`Channel::send_verdict`], with `seed` in a verdict that lets in: the
    /// seed of the session's tokens of one leg (T-615).
    pub(super) async fn send_verdict_with(
        &mut self,
        answer: &Result<(), Refusal>,
        seed: Option<&[u8; 32]>,
    ) -> Result<(), Error> {
        send(&self.state, &mut self.sent, &mut self.transport, VERDICT, &frame::verdict_with(answer, seed)).await
    }

    /// The node's verdict, the first message after the handshake.
    pub(super) async fn read_verdict(&mut self) -> Result<(), Error> {
        let (mut cipher, mut plain) = (Vec::new(), vec![0u8; MAX_MESSAGE]);
        match receive(&self.state, &mut self.received, &mut self.transport, &mut cipher, &mut plain).await? {
            None => Err(Error::Cut),
            Some((VERDICT, n)) => {
                // The seed of the session's tokens of one leg (T-615), where
                // the node gave one.
                self.seed = frame::seed_of(&plain[1..n]).map(Zeroizing::new);
                frame::answer(&plain[1..n])?.map_err(Error::Refused)
            }
            Some((kind, _)) => Err(Error::Malformed(format!("a message of type {kind} before the verdict"))),
        }
    }

    /// The seed of the session's tokens of one leg that the node's verdict
    /// gave (T-615), for the legs that resume the session.
    pub fn leg_seed(&self) -> Option<[u8; 32]> {
        self.seed.as_deref().copied()
    }

    /// End both directions at once: a refused session.
    pub(super) async fn close(mut self) {
        if send(&self.state, &mut self.sent, &mut self.transport, END, &[]).await.is_ok() {
            let _ = self.transport.shutdown().await;
        }
    }

    /// Carry `app` over the channel until both directions end: each byte that
    /// `app` gives goes out encrypted, and each message in is checked, then
    /// goes to `app`, whose writing side is shut at the peer's `END`. An
    /// error of either direction ends both.
    pub async fn carry<A: AsyncRead + AsyncWrite + Unpin>(self, app: A) -> Result<(), Error> {
        // With no hold, the carry ends only when both directions did.
        self.carry_held(app, None, Start::default()).await.map(|_| ())
    }
}

/// Encrypt one message of `kind` with the next nonce out, and write its frame.
async fn send<W: AsyncWrite + Unpin>(
    state: &StatelessTransportState,
    nonce: &mut u64,
    w: &mut W,
    kind: u8,
    body: &[u8],
) -> Result<(), Error> {
    let mut plain = Vec::with_capacity(1 + body.len());
    plain.push(kind);
    plain.extend_from_slice(body);
    let mut cipher = vec![0u8; plain.len() + TAG];
    let n = state.write_message(*nonce, &plain, &mut cipher).map_err(|e| Error::Malformed(e.to_string()))?;
    *nonce += 1;
    frame::write_frame(w, &cipher[..n]).await
}

/// Read one frame, and check and decrypt it with the next nonce in: its type
/// and its length in `plain`, type byte included; `None` when the stream
/// ended where a frame would start.
async fn receive<R: AsyncRead + Unpin>(
    state: &StatelessTransportState,
    nonce: &mut u64,
    r: &mut R,
    cipher: &mut Vec<u8>,
    plain: &mut [u8],
) -> Result<Option<(u8, usize)>, Error> {
    if !frame::read_frame(r, cipher).await? {
        return Ok(None);
    }
    if cipher.len() <= TAG {
        return Err(Error::Malformed("a message no longer than its tag".into()));
    }
    // A failed check is all that can be said: the relay may have changed,
    // dropped, repeated or moved the message, and nothing of it is used.
    let n = state.read_message(*nonce, cipher, plain).map_err(|_| Error::Tampered)?;
    *nonce += 1;
    Ok(Some((plain[0], n)))
}
