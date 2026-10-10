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

use snow::StatelessTransportState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::frame::{self, DATA, END, VERDICT};
use super::{Error, Refusal, MAX_DATA, MAX_MESSAGE, TAG};

/// The channel over `transport`, after its handshake.
pub struct Channel<T> {
    transport: T,
    state: StatelessTransportState,
    /// The nonce of the next message out.
    sent: u64,
    /// The nonce of the next message in.
    received: u64,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Channel<T> {
    pub(super) fn new(transport: T, state: StatelessTransportState) -> Self {
        Channel { transport, state, sent: 0, received: 0 }
    }

    pub(super) async fn send_verdict(&mut self, answer: &Result<(), Refusal>) -> Result<(), Error> {
        send(&self.state, &mut self.sent, &mut self.transport, VERDICT, &frame::verdict(answer)).await
    }

    /// The node's verdict, the first message after the handshake.
    pub(super) async fn read_verdict(&mut self) -> Result<(), Error> {
        let (mut cipher, mut plain) = (Vec::new(), vec![0u8; MAX_MESSAGE]);
        match receive(&self.state, &mut self.received, &mut self.transport, &mut cipher, &mut plain).await? {
            None => Err(Error::Cut),
            Some((VERDICT, n)) => frame::answer(&plain[1..n])?.map_err(Error::Refused),
            Some((kind, _)) => Err(Error::Malformed(format!("a message of type {kind} before the verdict"))),
        }
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
        let Channel { transport, state, mut sent, mut received } = self;
        let (mut from_peer, mut to_peer) = tokio::io::split(transport);
        let (mut from_app, mut to_app) = tokio::io::split(app);
        let state = &state;
        let outbound = async {
            let mut buf = vec![0u8; MAX_DATA];
            loop {
                let n = from_app.read(&mut buf).await.map_err(Error::Io)?;
                if n == 0 {
                    // The stream stays open: the peer's bytes may still come.
                    return send(state, &mut sent, &mut to_peer, END, &[]).await;
                }
                send(state, &mut sent, &mut to_peer, DATA, &buf[..n]).await?;
            }
        };
        let inbound = async {
            let (mut cipher, mut plain) = (Vec::new(), vec![0u8; MAX_MESSAGE]);
            loop {
                match receive(state, &mut received, &mut from_peer, &mut cipher, &mut plain).await? {
                    None => return Err(Error::Cut),
                    Some((DATA, n)) => {
                        to_app.write_all(&plain[1..n]).await.map_err(Error::Io)?;
                        to_app.flush().await.map_err(Error::Io)?;
                    }
                    Some((END, _)) => {
                        let _ = to_app.shutdown().await;
                        return Ok(());
                    }
                    Some((kind, _)) => return Err(Error::Malformed(format!("a message of type {kind} in a session"))),
                }
            }
        };
        tokio::try_join!(outbound, inbound)?;
        let _ = to_peer.shutdown().await;
        Ok(())
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
