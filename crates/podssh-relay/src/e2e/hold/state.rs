//! The state of a session's channel at a node, as the next binary takes it
//! (T-668): the keys that the handshake split, the nonces of the next
//! message each way, where each direction stands, the bytes cut short each
//! way, the operator's key, and the seed of its tokens of one leg. Its
//! transport comes back from the keys: snow builds none from keys, so a
//! handshake between two keys of this process makes one of the node's side,
//! which then takes the session's keys.

use snow::params::NoiseParams;
use snow::{Builder, HandshakeState, StatelessTransportState};
use zeroize::{Zeroize, Zeroizing};

use super::super::{PATTERN, PROLOGUE};
use crate::session::handover::wire::{Get, Put, Unreadable};

/// The version of the bytes of a channel that this build writes, and the
/// only one that it reads.
pub const VERSION: u8 = 1;
/// The most bytes cut short each way: a pipe's room, and a message.
const MAX_CUT: usize = 64 << 20;

/// A session's channel at a node, between two binaries.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelState {
    /// The initiator's key, then the responder's.
    pub keys: Zeroizing<[u8; 64]>,
    /// The nonce of the next message out, and of the next one in.
    pub sent: u64,
    pub received: u64,
    pub out_ended: bool,
    pub in_ended: bool,
    /// Bytes from the operator that no whole message took yet.
    pub unread: Vec<u8>,
    /// Bytes of the channel's messages that the layer had not taken yet:
    /// the next binary gives them to the layer first.
    pub to_layer: Vec<u8>,
    /// The operator's key, for the node's lines.
    pub peer: [u8; 32],
    /// Whether the net's documents ride on the channel.
    pub net: bool,
    /// The seed of the session's tokens of one leg, and the first leg of
    /// its window (T-615).
    pub lease: Option<([u8; 32], u64)>,
}

impl std::fmt::Debug for ChannelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ChannelState {{ sent: {}, received: {}, ended: ({}, {}), {} unread, {} to the layer }}",
            self.sent,
            self.received,
            self.out_ended,
            self.in_ended,
            self.unread.len(),
            self.to_layer.len()
        )
    }
}

impl ChannelState {
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut put = Put::new();
        put.u8(VERSION);
        put.fixed(&self.keys[..]);
        put.u64(self.sent);
        put.u64(self.received);
        put.bool(self.out_ended);
        put.bool(self.in_ended);
        put.bytes(&self.unread);
        put.bytes(&self.to_layer);
        put.fixed(&self.peer);
        put.bool(self.net);
        match &self.lease {
            Some((seed, low)) => {
                put.bool(true);
                put.fixed(seed);
                put.u64(*low);
            }
            None => put.bool(false),
        }
        put.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<ChannelState, Unreadable> {
        let mut get = Get::new(bytes);
        let version = get.u8("the channel's version")?;
        if version != VERSION {
            return Err(Unreadable(format!("a channel of version {version}, where this binary reads {VERSION}")));
        }
        let keys = Zeroizing::new(get.fixed::<64>("the channel's keys")?);
        let (sent, received) = (get.u64("the nonce out")?, get.u64("the nonce in")?);
        let (out_ended, in_ended) = (get.bool("the end out")?, get.bool("the end in")?);
        let unread = get.bytes("the bytes cut short", MAX_CUT)?.to_vec();
        let to_layer = get.bytes("the bytes for the layer", MAX_CUT)?.to_vec();
        let peer = get.fixed("the operator's key")?;
        let net = get.bool("the net")?;
        let lease = match get.bool("the seed")? {
            true => Some((get.fixed("the seed")?, get.u64("the window")?)),
            false => None,
        };
        get.end("the channel")?;
        Ok(ChannelState { keys, sent, received, out_ended, in_ended, unread, to_layer, peer, net, lease })
    }
}

/// The keys that a finished handshake splits into, the initiator's first.
pub fn split(state: &mut HandshakeState) -> Zeroizing<[u8; 64]> {
    let (mut initiator, mut responder) = state.dangerously_get_raw_split();
    let mut keys = Zeroizing::new([0u8; 64]);
    keys[..32].copy_from_slice(&initiator);
    keys[32..].copy_from_slice(&responder);
    initiator.zeroize();
    responder.zeroize();
    keys
}

/// A transport of the responder's side, a node's, that seals and opens with
/// `keys`, as the one of the session's handshake did.
pub fn transport_of(keys: &[u8; 64]) -> Result<StatelessTransportState, String> {
    let noise = |e: snow::Error| format!("the channel's transport: {e}");
    let params: NoiseParams = PATTERN.parse().map_err(noise)?;
    let mut initiator = throwaway(&params, true).map_err(noise)?;
    let mut responder = throwaway(&params, false).map_err(noise)?;
    let (mut message, mut payload) = (vec![0u8; 1024], vec![0u8; 1024]);
    // `-> e`, `<- e, ee, s, es`, `-> s, se`, with nothing in them.
    for initiator_writes in [true, false, true] {
        let (from, to) = match initiator_writes {
            true => (&mut initiator, &mut responder),
            false => (&mut responder, &mut initiator),
        };
        let n = from.write_message(&[], &mut message).map_err(noise)?;
        to.read_message(&message[..n], &mut payload).map_err(noise)?;
    }
    let mut transport = responder.into_stateless_transport_mode().map_err(noise)?;
    let mut ours = [[0u8; 32]; 2];
    ours[0].copy_from_slice(&keys[..32]);
    ours[1].copy_from_slice(&keys[32..]);
    transport.rekey_manually(Some(&ours[0]), Some(&ours[1]));
    ours.zeroize();
    Ok(transport)
}

/// One side of a handshake with a key of its own, drawn now.
fn throwaway(params: &NoiseParams, initiator: bool) -> Result<HandshakeState, snow::Error> {
    let pair = Builder::new(params.clone()).generate_keypair()?;
    let builder = Builder::new(params.clone()).local_private_key(&pair.private)?.prologue(PROLOGUE)?;
    match initiator {
        true => builder.build_initiator(),
        false => builder.build_responder(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ChannelState {
        ChannelState {
            keys: Zeroizing::new([5u8; 64]),
            sent: 41,
            received: 17,
            out_ended: false,
            in_ended: true,
            unread: vec![0, 9, 1, 2],
            to_layer: vec![7; 300],
            peer: [8u8; 32],
            net: true,
            lease: Some(([4u8; 32], 6)),
        }
    }

    #[test]
    fn a_channel_comes_back_whole_and_another_version_is_refused() {
        let bytes = state().encode();
        assert_eq!(ChannelState::decode(&bytes).unwrap(), state());
        let mut other = bytes.to_vec();
        other[0] = VERSION + 1;
        assert!(ChannelState::decode(&other).unwrap_err().0.contains("version"));
        assert!(ChannelState::decode(&bytes[..bytes.len() - 2]).is_err());
    }

    /// A message that the session's handshake sealed opens with the
    /// transport that the keys made, and the other way.
    #[test]
    fn the_transport_from_the_keys_is_the_session_s() {
        let params: NoiseParams = PATTERN.parse().unwrap();
        let mut operator = throwaway(&params, true).unwrap();
        let mut node = throwaway(&params, false).unwrap();
        let (mut message, mut payload) = (vec![0u8; 1024], vec![0u8; 1024]);
        let n = operator.write_message(&[], &mut message).unwrap();
        node.read_message(&message[..n], &mut payload).unwrap();
        let n = node.write_message(&[], &mut message).unwrap();
        operator.read_message(&message[..n], &mut payload).unwrap();
        let n = operator.write_message(&[], &mut message).unwrap();
        node.read_message(&message[..n], &mut payload).unwrap();
        let split_keys = split(&mut node);
        let operator = operator.into_stateless_transport_mode().unwrap();
        let restored = transport_of(&split_keys).unwrap();
        let (mut sealed, mut plain) = (vec![0u8; 64], vec![0u8; 64]);
        let n = operator.write_message(3, b"to the node", &mut sealed).unwrap();
        let k = restored.read_message(3, &sealed[..n], &mut plain).unwrap();
        assert_eq!(&plain[..k], b"to the node");
        let n = restored.write_message(9, b"to the operator", &mut sealed).unwrap();
        let k = operator.read_message(9, &sealed[..n], &mut plain).unwrap();
        assert_eq!(&plain[..k], b"to the operator");
        // Another nonce does not open.
        assert!(operator.read_message(10, &sealed[..n], &mut plain).is_err());
    }
}
