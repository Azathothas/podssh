//! The channel's handshake: Noise XX, each end's proof of its key in the
//! encrypted payloads of the second and third messages, then the node's
//! verdict. The operator learns the node's key before it proves its own, so
//! a node that it refuses learns nothing of it. The operator's proof may
//! name a route of the node (T-089), or the target of an exit (T-431), as
//! its word ([`super::Ask`]), encrypted with it, so that the relay never
//! sees which. Two ends that hold the net's document say which, and the
//! newer one travels (T-429, [`super::net`]). The operator's proof may carry
//! a grant used once (T-226), around the proof of each form, so that a node
//! checks it with what the proof asks. The verdict that lets in may give the
//! seed of the session's tokens of one leg (T-615).

use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;

use snow::params::NoiseParams;
use snow::{Builder, HandshakeState};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::channel::Channel;
use super::frame::{read_frame, read_magic, write_frame};
use super::net::{self, Docs, Held};
use super::{Ask, Error, Refusal, HANDSHAKE_LIMIT, MAGIC, MAX_DATA, MAX_GRANT, MAX_MESSAGE, PATTERN, PROLOGUE};
use crate::identity::{Identity, PublicKey};

/// The version of a proof of a key, its first byte.
const PROOF_VERSION: u8 = 1;
/// The version of a proof that names a route after it: its length in one
/// byte, then its name (T-089). A node of an earlier podssh refuses it, as a
/// proof that it does not read.
const ROUTED_PROOF: u8 = 2;
/// The version of a proof of the net's form (T-429): the route, the
/// document held and whether it follows, as [`net::encode`] writes them;
/// sent only to an end that said that it reads it.
const NET_PROOF: u8 = 3;
/// The version of a proof that carries a grant (T-226): the key and its
/// binding, the grant's length in two bytes and the grant, then the version
/// of the proof that it carries and what follows that one's binding. Sent
/// only when the user gave a grant: a node of before T-226 refuses it whole,
/// as a proof that it does not read.
const GRANT_PROOF: u8 = 4;
/// A proof: its version, the sender's Ed25519 key, and that key's signature
/// of the sender's Noise static key.
const PROOF_LEN: usize = 1 + 32 + 64;

/// What the two ends of a handshake said of the net: this end's documents,
/// and what the peer holds.
pub(super) struct Talk {
    pub docs: Arc<dyn Docs>,
    pub peer: Option<Held>,
}

impl Talk {
    /// This end's document, when it is newer than the peer's and the peer
    /// is a member of it; within one message of the channel.
    fn gift(&self, peer: &PublicKey) -> Option<Vec<u8>> {
        let (held, bytes) = self.docs.held()?;
        let newer = self.peer.is_some_and(|theirs| held.newer_than(&theirs));
        (newer && bytes.len() <= MAX_DATA && self.docs.shares_with(peer)).then_some(bytes)
    }
}

/// The operator's side after the node's message: the node's key, to check
/// before this end proves its own.
pub struct Offered<T> {
    transport: T,
    state: HandshakeState,
    peer: PublicKey,
    proof: [u8; PROOF_LEN],
    net: Option<Talk>,
    /// This end offered the net's document, and the node's proof took no
    /// part of it (T-643).
    unanswered: bool,
}

/// The node's side after the operator's proof: the operator's key, which the
/// node lets in or refuses, and what it asked: a route, or an exit's target.
pub struct Asked<T> {
    channel: Channel<T>,
    peer: PublicKey,
    ask: Ask,
    net: Option<Talk>,
    grant: Option<Vec<u8>>,
}

/// A proof, read: the key, what its word asks, in the net's form what the
/// sender holds and whether its document follows, and the grant it carries.
struct Proof {
    key: PublicKey,
    ask: Ask,
    net: Option<(Option<Held>, bool)>,
    grant: Option<Vec<u8>>,
}

/// Start the channel on `transport` as its initiator, an operator: the
/// magic and the first message, then the node's message, which proves the
/// node's key. The net's documents are this process's ([`net::installed`]).
pub async fn initiate<T: AsyncRead + AsyncWrite + Unpin>(transport: T, me: &Identity) -> Result<Offered<T>, Error> {
    initiate_with(transport, me, net::installed()).await
}

/// [`initiate`] with the net's documents given, or none.
pub async fn initiate_with<T: AsyncRead + AsyncWrite + Unpin>(
    mut transport: T,
    me: &Identity,
    docs: Option<Arc<dyn Docs>>,
) -> Result<Offered<T>, Error> {
    // Only an end that holds a document offers: the offer goes in clear.
    let docs = docs.filter(|docs| docs.held().is_some());
    let mut state = builder(me)?.build_initiator().map_err(noise)?;
    let mut out = vec![0u8; MAX_MESSAGE];
    let first = if docs.is_some() { net::OFFER } else { &[][..] };
    let n = state.write_message(first, &mut out).map_err(noise)?;
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
    let read = proof_of(&payload[..k], state.get_remote_static(), docs.is_some())?;
    // T-429 lets such a node in by its own door; its caller says it once.
    let unanswered = docs.is_some() && read.net.is_none();
    let net = match (docs, read.net) {
        (Some(docs), Some((peer, _))) => Some(Talk { docs, peer }),
        _ => None,
    };
    Ok(Offered { transport, state, peer: read.key, proof: proof(me), net, unanswered })
}

impl<T: AsyncRead + AsyncWrite + Unpin> Offered<T> {
    /// The node's key, which its message proved.
    pub fn peer(&self) -> PublicKey {
        self.peer
    }

    /// Whether this end offered the net's document and the node answered
    /// with a plain proof: it holds none, or is a podssh of before (T-643).
    /// The session goes on without the document, as T-429 lets such a node
    /// in by its own door; the caller says it.
    pub fn net_unanswered(&self) -> bool {
        self.unanswered
    }

    /// Prove this end's key, with `route` of the node when one is asked
    /// (T-089), or the word of an exit's target (T-431, [`Ask::word`]), and
    /// this end's document of the net when it is the newer one, then wait
    /// for the node's verdict: the channel, or why the node refused.
    pub async fn accept(self, route: Option<&str>) -> Result<Channel<T>, Error> {
        self.accept_granted(route, None).await
    }

    /// [`Offered::accept`] with `grant`, a grant used once (T-226), in the
    /// proof: it goes to the node whose key this end checked, encrypted.
    pub async fn accept_granted(self, route: Option<&str>, grant: Option<&[u8]>) -> Result<Channel<T>, Error> {
        let Offered { mut transport, mut state, peer, proof, net, .. } = self;
        let gift = net.as_ref().and_then(|talk| talk.gift(&peer));
        let payload = match &net {
            Some(talk) => {
                let held = talk.docs.held().map(|(held, _)| held);
                in_net_form(&proof, route, held, gift.is_some())?
            }
            None => routed(&proof, route)?,
        };
        let payload = granted(payload, grant)?;
        let mut out = vec![0u8; MAX_MESSAGE];
        let n = state.write_message(&payload, &mut out).map_err(noise)?;
        write_frame(&mut transport, &out[..n]).await?;
        let state = state.into_stateless_transport_mode().map_err(noise)?;
        let mut channel = Channel::new(transport, state);
        if let Some(bytes) = gift {
            channel.send_net(&bytes).await?;
        }
        if let Some(talk) = net {
            channel.set_net(talk.docs, peer);
        }
        verdict_within(channel.read_verdict()).await?;
        Ok(channel)
    }

    /// Refuse the node: the stream ends, and this end's key stays unsaid.
    pub async fn reject(self) {
        let mut transport = self.transport;
        let _ = transport.shutdown().await;
    }
}

/// Answer the channel on `transport` as its responder, a node: the
/// operator's first message, this node's proof, then the operator's. The
/// net's documents are this process's ([`net::installed`]).
pub async fn respond<T: AsyncRead + AsyncWrite + Unpin>(transport: T, me: &Identity) -> Result<Asked<T>, Error> {
    respond_with(transport, me, net::installed()).await
}

/// [`respond`] with the net's documents given, or none.
pub async fn respond_with<T: AsyncRead + AsyncWrite + Unpin>(
    mut transport: T,
    me: &Identity,
    docs: Option<Arc<dyn Docs>>,
) -> Result<Asked<T>, Error> {
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
    // The first message carries the net's offer, or nothing; what else it
    // may carry later is read, and set aside.
    let k = state.read_message(&message, &mut payload).map_err(not_noise("the operator's first message"))?;
    let offered = &payload[..k] == net::OFFER;
    let docs = docs.filter(|docs| offered && docs.held().is_some());
    let mine = match &docs {
        Some(docs) => in_net_form(&proof(me), None, docs.held().map(|(held, _)| held), false)?,
        None => proof(me).to_vec(),
    };
    let mut out = vec![0u8; MAX_MESSAGE];
    let n = state.write_message(&mine, &mut out).map_err(noise)?;
    write_frame(&mut transport, &out[..n]).await?;
    within("the operator's proof of its key", async { whole(read_frame(&mut transport, &mut message).await?) }).await?;
    let k = state.read_message(&message, &mut payload).map_err(not_noise("the operator's proof"))?;
    let read = proof_of(&payload[..k], state.get_remote_static(), docs.is_some())?;
    // The node keeps the keys, which the binary after it takes (T-668).
    let keys = super::hold::state::split(&mut state);
    let state = state.into_stateless_transport_mode().map_err(noise)?;
    let mut channel = Channel::new(transport, state).with_keys(keys);
    let net = match (docs, read.net) {
        (Some(docs), Some((peer, follows))) => {
            // The operator's newer document comes before the verdict, so
            // that it holds for this session; one that does not hold is the
            // binary's to say, and the session goes on.
            if follows {
                let bytes = within("the operator's document of the net", channel.read_net()).await?;
                let _ = docs.take(&read.key, &bytes);
            }
            Some(Talk { docs, peer })
        }
        _ => None,
    };
    Ok(Asked { channel, peer: read.key, ask: read.ask, net, grant: read.grant })
}

impl<T: AsyncRead + AsyncWrite + Unpin> Asked<T> {
    /// The operator's key, which its proof proved.
    pub fn peer(&self) -> PublicKey {
        self.peer
    }

    /// The route of this node that the operator named, if one (T-089).
    pub fn route(&self) -> Option<&str> {
        self.ask.route()
    }

    /// What the operator asked: the target with no route, a route, or an
    /// exit's target (T-431).
    pub fn ask(&self) -> &Ask {
        &self.ask
    }

    /// The grant that the operator's proof carried, unchecked (T-226): the
    /// node's door reads it before anything is dialed.
    pub fn grant(&self) -> Option<&[u8]> {
        self.grant.as_deref()
    }

    /// Let the operator in: the verdict, then this node's document of the
    /// net when it is the newer one, then the channel.
    pub async fn admit(self) -> Result<Channel<T>, Error> {
        self.admit_with(None).await
    }

    /// [`Asked::admit`], with `seed` in the verdict: the seed of the
    /// session's tokens of one leg (T-615), which only this operator learns.
    pub async fn admit_with(mut self, seed: Option<&[u8; 32]>) -> Result<Channel<T>, Error> {
        self.channel.send_verdict_with(&Ok(()), seed).await?;
        if let Some(talk) = self.net {
            if let Some(bytes) = talk.gift(&self.peer) {
                self.channel.send_net(&bytes).await?;
            }
            self.channel.set_net(talk.docs, self.peer);
        }
        Ok(self.channel)
    }

    /// Refuse the operator, with `why`, and end the stream: a refused end
    /// gets no document of the net.
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

/// The proof of this end, with `route` after it when one is named.
fn routed(proof: &[u8; PROOF_LEN], route: Option<&str>) -> Result<Vec<u8>, Error> {
    let Some(route) = route else { return Ok(proof.to_vec()) };
    let len = route_len(route)?;
    let mut payload = proof.to_vec();
    payload[0] = ROUTED_PROOF;
    payload.push(len);
    payload.extend_from_slice(route.as_bytes());
    Ok(payload)
}

/// The proof of this end in the net's form: the route, the document held,
/// and whether it follows.
fn in_net_form(
    proof: &[u8; PROOF_LEN],
    route: Option<&str>,
    held: Option<Held>,
    follows: bool,
) -> Result<Vec<u8>, Error> {
    if let Some(route) = route {
        route_len(route)?;
    }
    let mut payload = proof.to_vec();
    payload[0] = NET_PROOF;
    payload.extend_from_slice(&net::encode(route, held, follows));
    Ok(payload)
}

/// The length of a word, a route's name or an exit's target, which fits one
/// byte.
fn route_len(route: &str) -> Result<u8, Error> {
    let bad = || Error::Handshake(format!("{route:?} is neither a route's name nor an exit's target HOST:PORT"));
    Ask::read(Some(route)).ok_or_else(bad)?;
    u8::try_from(route.len()).map_err(|_| bad())
}

/// The peer's proof: the key must sign the Noise static key that the
/// handshake proved the peer holds. The net's form is read only where this
/// end said that it reads it (`net_ok`), as an end of before would not.
fn proof_of(payload: &[u8], remote_static: Option<&[u8]>, net_ok: bool) -> Result<Proof, Error> {
    let unread = || Error::Handshake("the peer's proof of its key is not one that this podssh reads".into());
    // A grant wraps a proof of each other form (T-226).
    let (inner, grant) = match payload.first() {
        Some(&GRANT_PROOF) => {
            let (inner, grant) = ungranted(payload).ok_or_else(unread)?;
            (Cow::Owned(inner), Some(grant))
        }
        _ => (Cow::Borrowed(payload), None),
    };
    let payload: &[u8] = &inner;
    // A word is a route's name or an exit's target (T-431).
    let named = |bytes: &[u8]| std::str::from_utf8(bytes).ok().and_then(|r| Ask::read(Some(r))).ok_or_else(unread);
    let (ask, net) = match payload.first() {
        Some(&PROOF_VERSION) if payload.len() == PROOF_LEN => (Ask::Target, None),
        Some(&ROUTED_PROOF) if payload.len() > PROOF_LEN + 1 => {
            let route = &payload[PROOF_LEN + 1..];
            if route.len() != usize::from(payload[PROOF_LEN]) {
                return Err(unread());
            }
            (named(route)?, None)
        }
        Some(&NET_PROOF) if net_ok && payload.len() > PROOF_LEN => {
            let (route, held, follows) = net::decode(&payload[PROOF_LEN..]).ok_or_else(unread)?;
            (route.map(named).transpose()?.unwrap_or(Ask::Target), Some((held, follows)))
        }
        _ => return Err(unread()),
    };
    let key = PublicKey(payload[1..33].try_into().map_err(|_| unread())?);
    let binding: [u8; 64] = payload[33..PROOF_LEN].try_into().map_err(|_| unread())?;
    let noise_key: [u8; 32] = remote_static
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::Handshake("the peer sent no Noise static key".into()))?;
    if !key.signed(&noise_key, &binding) {
        return Err(Error::Handshake(format!("the key {key} does not sign the peer's Noise key")));
    }
    Ok(Proof { key, ask, net, grant })
}

/// `proof`, a proof of another form, with `grant` around it (T-226).
fn granted(proof: Vec<u8>, grant: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let Some(grant) = grant else { return Ok(proof) };
    if grant.is_empty() || grant.len() > MAX_GRANT {
        return Err(Error::Handshake(format!("a grant of {} bytes, where one has 1 to {MAX_GRANT}", grant.len())));
    }
    let mut out = Vec::with_capacity(proof.len() + 3 + grant.len());
    out.push(GRANT_PROOF);
    out.extend_from_slice(&proof[1..PROOF_LEN]);
    // MAX_GRANT fits two bytes.
    out.extend_from_slice(&(grant.len() as u16).to_be_bytes());
    out.extend_from_slice(grant);
    out.push(proof[0]);
    out.extend_from_slice(&proof[PROOF_LEN..]);
    Ok(out)
}

/// The proof that a grant's proof carries, in its own form, and the grant;
/// `None` for bytes of no such form, a grant around a grant among them.
fn ungranted(payload: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (head, rest) = payload.split_at_checked(PROOF_LEN)?;
    let (len, rest) = rest.split_at_checked(2)?;
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    if len == 0 || len > MAX_GRANT {
        return None;
    }
    let (grant, rest) = rest.split_at_checked(len)?;
    let (&version, tail) = rest.split_first()?;
    if version == GRANT_PROOF {
        return None;
    }
    let mut inner = Vec::with_capacity(PROOF_LEN + tail.len());
    inner.push(version);
    inner.extend_from_slice(&head[1..]);
    inner.extend_from_slice(tail);
    Some((inner, grant.to_vec()))
}

/// A frame that must be there: the stream's end in its place is a cut.
fn whole(read: bool) -> Result<(), Error> {
    read.then_some(()).ok_or(Error::Cut)
}

async fn within<R>(step: &'static str, step_future: impl Future<Output = Result<R, Error>>) -> Result<R, Error> {
    tokio::time::timeout(HANDSHAKE_LIMIT, step_future).await.map_err(|_| Error::Timeout(step))?
}

/// The wait for the node's verdict, which a node's person may answer first
/// (T-638): longer than a step's.
async fn verdict_within<R>(step_future: impl Future<Output = Result<R, Error>>) -> Result<R, Error> {
    tokio::time::timeout(super::VERDICT_LIMIT, step_future).await.map_err(|_| Error::Timeout(super::VERDICT_STEP))?
}

fn noise(e: snow::Error) -> Error {
    Error::Handshake(e.to_string())
}

fn not_noise(what: &'static str) -> impl Fn(snow::Error) -> Error {
    move |e| Error::Handshake(format!("{what} failed Noise's check ({e})"))
}
