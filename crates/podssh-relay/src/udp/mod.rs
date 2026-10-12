//! UDP over a byte stream (T-168). The relay carries TCP only, so a
//! datagram travels in a stream to a podssh that may send UDP: a node, on a
//! host that allows it. One stream carries one flow, each datagram after
//! its length in two bytes ([`codec`]); at the far end the flow is a UDP
//! socket connected to the target ([`flow`]).
//!
//! Over TCP, datagrams wait for each other: a lost segment delays each
//! later datagram, where UDP would lose the one datagram and go on.

pub mod codec;
pub mod flow;

pub use codec::{encode, framed, Decoder, FrameError, Frames, LENGTH, MAX_DATAGRAM};
