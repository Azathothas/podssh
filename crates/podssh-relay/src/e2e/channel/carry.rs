//! The carry of a session over the channel, which a handover can hold
//! (T-668). Each direction stops between two messages: the one out after a
//! whole message, never inside one, and the one in after it wrote each
//! message that came whole, keeping the bytes of one cut short. So the next
//! binary takes the channel at the same nonces, and the peer, which never
//! knew, goes on. The bytes in come into a buffer of their own, not a read
//! of one frame, as a read that a hold cut would lose what it had read.

use snow::StatelessTransportState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::super::frame::{DATA, END, NET};
use super::super::hold::{held, Hold};
use super::super::{Error, MAX_DATA, MAX_MESSAGE, TAG};
use super::{send, Channel};

/// The most bytes read from the peer at once.
const CHUNK: usize = 64 * 1024;

/// Where a carry starts: at the session's start, or where a handover held
/// it in the binary before this one.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Start {
    /// This end's `END` went out: its application's bytes are over.
    pub out_ended: bool,
    /// The peer's `END` came, and the application's write side is shut.
    pub in_ended: bool,
    /// Bytes from the peer that no whole message took yet.
    pub unread: Vec<u8>,
    /// Bytes of this end's messages, sealed in the binary before this one,
    /// that the stream under the channel had not taken: they go first.
    pub to_layer: Vec<u8>,
}

/// How a carry ended.
pub enum Carried<T, A> {
    /// Both directions ended.
    Ended,
    /// A handover held it between messages.
    Held(Held<T, A>),
}

/// A carry that a handover held: the stream and the application, as they
/// were, the nonces of the next message each way, where each direction
/// stands, the keys, and whether the net's documents ride.
pub struct Held<T, A> {
    pub transport: T,
    pub app: A,
    pub sent: u64,
    pub received: u64,
    pub start: Start,
    pub keys: Option<zeroize::Zeroizing<[u8; 64]>>,
    pub net: Option<crate::identity::PublicKey>,
}

/// The first whole frame of `buf`, taken out of it; `None` while it is cut
/// short. An empty frame is none that the channel has.
fn take_frame(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
    let Some(len) = buf.get(..2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]]))) else { return Ok(None) };
    if len == 0 {
        return Err(Error::Malformed("an empty frame".into()));
    }
    if buf.len() < 2 + len {
        return Ok(None);
    }
    let message = buf[2..2 + len].to_vec();
    buf.drain(..2 + len);
    Ok(Some(message))
}

/// Check and decrypt one message with the next nonce in: its type and its
/// length in `plain`, type byte included.
fn open(
    state: &StatelessTransportState,
    nonce: &mut u64,
    cipher: &[u8],
    plain: &mut [u8],
) -> Result<(u8, usize), Error> {
    if cipher.len() <= TAG {
        return Err(Error::Malformed("a message no longer than its tag".into()));
    }
    // A failed check is all that can be said: the relay may have changed,
    // dropped, repeated or moved the message, and nothing of it is used.
    let n = state.read_message(*nonce, cipher, plain).map_err(|_| Error::Tampered)?;
    *nonce += 1;
    if n == 0 {
        return Err(Error::Malformed("a message with no type".into()));
    }
    Ok((plain[0], n))
}

/// The direction out: whether it ended, or a hold stopped it. `first` are
/// whole messages sealed before, which go out before any new one.
async fn outbound<T, A>(
    state: &StatelessTransportState,
    sent: &mut u64,
    from_app: &mut ReadHalf<A>,
    to_peer: &mut WriteHalf<T>,
    hold: Option<&Hold>,
    (ended, first): (bool, Vec<u8>),
) -> Result<bool, Error>
where
    T: AsyncWrite,
    A: AsyncRead,
{
    if !first.is_empty() {
        to_peer.write_all(&first).await.map_err(Error::Io)?;
        to_peer.flush().await.map_err(Error::Io)?;
    }
    if ended {
        return Ok(true);
    }
    let mut buf = vec![0u8; MAX_DATA];
    loop {
        // A read that the hold cuts took nothing: a read is the one await
        // that a hold ends, and a message, once read, goes out whole.
        let n = tokio::select! {
            biased;
            () = held(hold) => return Ok(false),
            read = from_app.read(&mut buf) => read.map_err(Error::Io)?,
        };
        if n == 0 {
            // The stream stays open: the peer's bytes may still come.
            send(state, sent, to_peer, END, &[]).await?;
            return Ok(true);
        }
        send(state, sent, to_peer, DATA, &buf[..n]).await?;
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Channel<T> {
    /// [`Channel::carry`], from `start`, until both directions end or `hold`
    /// is asked: then each direction stops at its next boundary, and the
    /// carry gives back what the next binary takes.
    pub async fn carry_held<A>(self, app: A, hold: Option<&Hold>, start: Start) -> Result<Carried<T, A>, Error>
    where
        A: AsyncRead + AsyncWrite + Unpin,
    {
        let Channel { transport, state, mut sent, mut received, net, keys, .. } = self;
        let peer = net.as_ref().map(|(_, peer)| *peer);
        let (mut from_peer, mut to_peer) = tokio::io::split(transport);
        let (mut from_app, mut to_app) = tokio::io::split(app);
        let Start { out_ended, in_ended, unread, to_layer } = start;
        let state = &state;
        let out = outbound(state, &mut sent, &mut from_app, &mut to_peer, hold, (out_ended, to_layer));
        let inbound = async {
            let mut buf = unread;
            if in_ended {
                return Ok((true, buf));
            }
            let (mut chunk, mut plain) = (vec![0u8; CHUNK], vec![0u8; MAX_MESSAGE]);
            loop {
                while let Some(message) = take_frame(&mut buf)? {
                    match open(state, &mut received, &message, &mut plain)? {
                        (DATA, n) => {
                            to_app.write_all(&plain[1..n]).await.map_err(Error::Io)?;
                            to_app.flush().await.map_err(Error::Io)?;
                        }
                        (END, _) => {
                            let _ = to_app.shutdown().await;
                            return Ok((true, buf));
                        }
                        // The binary says what it did with the document; the
                        // session goes on either way.
                        (NET, n) if net.is_some() => {
                            if let Some((docs, peer)) = &net {
                                let _ = docs.take(peer, &plain[1..n]);
                            }
                        }
                        (kind, _) => return Err(Error::Malformed(format!("a message of type {kind} in a session"))),
                    }
                }
                let n = tokio::select! {
                    biased;
                    () = held(hold) => return Ok((false, buf)),
                    read = from_peer.read(&mut chunk) => read.map_err(Error::Io)?,
                };
                // An end where a frame would start, or inside one: a cut.
                if n == 0 {
                    return Err(Error::Cut);
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        };
        let (out_done, (in_done, unread)) = tokio::try_join!(out, inbound)?;
        let (mut transport, app) = (from_peer.unsplit(to_peer), from_app.unsplit(to_app));
        if out_done && in_done {
            let _ = transport.shutdown().await;
            return Ok(Carried::Ended);
        }
        let start = Start { out_ended: out_done, in_ended: in_done, unread, to_layer: Vec::new() };
        Ok(Carried::Held(Held { transport, app, sent, received, start, keys, net: peer }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_is_taken_whole_or_waits() {
        let mut buf = vec![0, 3, 1, 2];
        assert_eq!(take_frame(&mut buf).unwrap(), None, "cut short");
        assert_eq!(buf, vec![0, 3, 1, 2], "nothing taken");
        buf.extend_from_slice(&[3, 0, 1]);
        assert_eq!(take_frame(&mut buf).unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(buf, vec![0, 1], "the next frame's start stays");
        let mut empty = vec![0, 0, 9];
        assert!(matches!(take_frame(&mut empty), Err(Error::Malformed(_))));
    }
}
