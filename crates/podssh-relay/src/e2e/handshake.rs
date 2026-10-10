//! The channel's handshake: Noise XX, each end's proof of its key in the
//! encrypted payloads of the second and third messages, then the node's
//! verdict. The operator learns the node's key before it proves its own, so
//! a node that it refuses learns nothing of it.

use std::future::Future;

use snow::params::NoiseParams;
use snow::{Builder, HandshakeState};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::channel::Channel;
use super::frame::{read_frame, read_magic, write_frame};
use super::{Error, Refusal, HANDSHAKE_LIMIT, MAGIC, MAX_MESSAGE, PATTERN, PROLOGUE};
use crate::identity::{Identity, PublicKey};

/// The version of a proof of a key, its first byte.
const PROOF_VERSION: u8 = 1;
/// A proof: its version, the sender's Ed25519 key, and that key's signature
/// of the sender's Noise static key.
const PROOF_LEN: usize = 1 + 32 + 64;

/// The operator's side after the node's message: the node's key, to check
/// before this end proves its own.
pub struct Offered<T> {
    transport: T,
    state: HandshakeState,
    peer: PublicKey,
    proof: [u8; PROOF_LEN],
}

/// The node's side after the operator's proof: the operator's key, which the
/// node lets in or refuses.
pub struct Asked<T> {
    channel: Channel<T>,
    peer: PublicKey,
}

/// Start the channel on `transport` as its initiator, an operator: the
/// magic and the first message, then the node's message, which proves the
/// node's key.
pub async fn initiate<T: AsyncRead + AsyncWrite + Unpin>(mut transport: T, me: &Identity) -> Result<Offered<T>, Error> {
    let mut state = builder(me)?.build_initiator().map_err(noise)?;
    let mut out = vec![0u8; MAX_MESSAGE];
    let n = state.write_message(&[], &mut out).map_err(noise)?;
    transport.write_all(MAGIC).await.map_err(Error::Io)?;
    write_frame(&mut transport, &out[..n]).await?;
    let mut message = Vec::new();
    within("the node's answer to the channel's handshake", async {
        read_magic(&mut transport).await?;
        whole(read_frame(&mut transport, &mut message).await?)
    })
    .await?;
    let mut payload = vec![0u8; MAX_MESSAGE];
    let k = state.read_message(&message, &mut payload).map_err(not_noise("the node's message"))?;
    let peer = peer_of(&payload[..k], state.get_remote_static())?;
    Ok(Offered { transport, state, peer, proof: proof(me) })
}

impl<T: AsyncRead + AsyncWrite + Unpin> Offered<T> {
    /// The node's key, which its message proved.
    pub fn peer(&self) -> PublicKey {
        self.peer
    }

    /// Prove this end's key, then wait for the node's verdict: the channel,
    /// or why the node refused.
    pub async fn accept(self) -> Result<Channel<T>, Error> {
        let Offered { mut transport, mut state, proof, .. } = self;
        let mut out = vec![0u8; MAX_MESSAGE];
        let n = state.write_message(&proof, &mut out).map_err(noise)?;
        write_frame(&mut transport, &out[..n]).await?;
        let state = state.into_stateless_transport_mode().map_err(noise)?;
        let mut channel = Channel::new(transport, state);
        within("the node's verdict", channel.read_verdict()).await?;
        Ok(channel)
    }

    /// Refuse the node: the stream ends, and this end's key stays unsaid.
    pub async fn reject(self) {
        let mut transport = self.transport;
        let _ = transport.shutdown().await;
    }
}

/// Answer the channel on `transport` as its responder, a node: the
/// operator's first message, this node's proof, then the operator's.
pub async fn respond<T: AsyncRead + AsyncWrite + Unpin>(mut transport: T, me: &Identity) -> Result<Asked<T>, Error> {
    let mut state = builder(me)?.build_responder().map_err(noise)?;
    // The node speaks first, as the operator does: a client of the layer
    // waits for the far end's first byte before it sends (T-153), so a node
    // with no layer that waited for the operator would wait for ever.
    transport.write_all(MAGIC).await.map_err(Error::Io)?;
    transport.flush().await.map_err(Error::Io)?;
    let mut message = Vec::new();
    within("the operator's first message of the channel", async {
        read_magic(&mut transport).await?;
        whole(read_frame(&mut transport, &mut message).await?)
    })
    .await?;
    let mut payload = vec![0u8; MAX_MESSAGE];
    // The first message carries nothing yet; what it may carry later is
    // read, and set aside.
    state.read_message(&message, &mut payload).map_err(not_noise("the operator's first message"))?;
    let mut out = vec![0u8; MAX_MESSAGE];
    let n = state.write_message(&proof(me), &mut out).map_err(noise)?;
    write_frame(&mut transport, &out[..n]).await?;
    within("the operator's proof of its key", async { whole(read_frame(&mut transport, &mut message).await?) }).await?;
    let k = state.read_message(&message, &mut payload).map_err(not_noise("the operator's proof"))?;
    let peer = peer_of(&payload[..k], state.get_remote_static())?;
    let state = state.into_stateless_transport_mode().map_err(noise)?;
    Ok(Asked { channel: Channel::new(transport, state), peer })
}

impl<T: AsyncRead + AsyncWrite + Unpin> Asked<T> {
    /// The operator's key, which its proof proved.
    pub fn peer(&self) -> PublicKey {
        self.peer
    }

    /// Let the operator in: the verdict, then the channel.
    pub async fn admit(mut self) -> Result<Channel<T>, Error> {
        self.channel.send_verdict(&Ok(())).await?;
        Ok(self.channel)
    }

    /// Refuse the operator, with `why`, and end the stream.
    pub async fn refuse(mut self, why: Refusal) {
        if self.channel.send_verdict(&Err(why)).await.is_ok() {
            self.channel.close().await;
        }
    }
}

fn builder(me: &Identity) -> Result<Builder<'_>, Error> {
    let params: NoiseParams = PATTERN.parse().map_err(noise)?;
    Builder::new(params).local_private_key(me.dh_secret()).and_then(|b| b.prologue(PROLOGUE)).map_err(noise)
}

/// This end's proof of its key.
fn proof(me: &Identity) -> [u8; PROOF_LEN] {
    let mut out = [0u8; PROOF_LEN];
    out[0] = PROOF_VERSION;
    out[1..33].copy_from_slice(&me.public().0);
    out[33..].copy_from_slice(me.binding());
    out
}

/// The peer's key, from its proof: the key must sign the Noise static key
/// that the handshake proved the peer holds.
fn peer_of(payload: &[u8], remote_static: Option<&[u8]>) -> Result<PublicKey, Error> {
    let unread = || Error::Handshake("the peer's proof of its key is not one that this podssh reads".into());
    if payload.len() != PROOF_LEN || payload[0] != PROOF_VERSION {
        return Err(unread());
    }
    let key = PublicKey(payload[1..33].try_into().map_err(|_| unread())?);
    let binding: [u8; 64] = payload[33..].try_into().map_err(|_| unread())?;
    let noise_key: [u8; 32] = remote_static
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::Handshake("the peer sent no Noise static key".into()))?;
    if !key.signed(&noise_key, &binding) {
        return Err(Error::Handshake(format!("the key {key} does not sign the peer's Noise key")));
    }
    Ok(key)
}

/// A frame that must be there: the stream's end in its place is a cut.
fn whole(read: bool) -> Result<(), Error> {
    read.then_some(()).ok_or(Error::Cut)
}

async fn within<R>(step: &'static str, step_future: impl Future<Output = Result<R, Error>>) -> Result<R, Error> {
    tokio::time::timeout(HANDSHAKE_LIMIT, step_future).await.map_err(|_| Error::Timeout(step))?
}

fn noise(e: snow::Error) -> Error {
    Error::Handshake(e.to_string())
}

fn not_noise(what: &'static str) -> impl Fn(snow::Error) -> Error {
    move |e| Error::Handshake(format!("{what} failed Noise's check ({e})"))
}
