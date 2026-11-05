//! The bytes that a node hands to the binary that takes its place (T-668):
//! a mark of their own, their version, the line of the binary that wrote
//! them, then each session: its layer's state, the descriptor of its
//! target's connection where it moved, and its channel's state where one
//! runs above it. A binary that reads another version refuses them whole,
//! and says so: no session is taken half.

use podssh_relay::session::handover::wire::{Get, Put, Unreadable};
use zeroize::Zeroizing;

/// The first bytes, which no other file begins with.
pub const MAGIC: &[u8] = b"podssh-node-handover\n";
/// The version that this build writes, and the only one that it reads.
pub const VERSION: u8 = 1;
/// The most sessions: the relay's 64 for each socket, on each road.
const MAX_SESSIONS: u32 = 4096;
/// The most bytes of one session's state: two buffers and what waits.
const MAX_SESSION: usize = 128 << 20;

/// One session in the bytes.
pub struct Session {
    pub layer: Zeroizing<Vec<u8>>,
    /// The descriptor of its target's connection, in the process that
    /// reads the bytes; none for a session that ends at its resume.
    pub socket: Option<i32>,
    pub channel: Option<Zeroizing<Vec<u8>>>,
}

pub fn encode(from: &str, sessions: &[Session]) -> Zeroizing<Vec<u8>> {
    let mut put = Put::new();
    put.fixed(MAGIC);
    put.u8(VERSION);
    put.text(from);
    put.u32(sessions.len() as u32);
    for session in sessions {
        put.bytes(&session.layer);
        match session.socket {
            Some(fd) => {
                put.bool(true);
                put.u32(fd as u32);
            }
            None => put.bool(false),
        }
        match &session.channel {
            Some(channel) => {
                put.bool(true);
                put.bytes(channel);
            }
            None => put.bool(false),
        }
    }
    put.into_bytes()
}

/// The line of the binary that wrote `bytes`, and each session.
pub fn decode(bytes: &[u8]) -> Result<(String, Vec<Session>), Unreadable> {
    if !bytes.starts_with(MAGIC) {
        return Err(Unreadable("they are no handover of a node".into()));
    }
    let mut get = Get::new(&bytes[MAGIC.len()..]);
    let version = get.u8("the version")?;
    if version != VERSION {
        return Err(Unreadable(format!("a handover of version {version}, where this binary reads {VERSION}")));
    }
    let from = get.text("the line of the binary before", 256)?;
    let count = get.u32("the count of the sessions")?;
    if count > MAX_SESSIONS {
        return Err(Unreadable(format!("{count} sessions")));
    }
    let mut sessions = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let layer = Zeroizing::new(get.bytes("a session", MAX_SESSION)?.to_vec());
        let socket = match get.bool("whether a connection moved")? {
            true => Some(get.u32("a descriptor")? as i32),
            false => None,
        };
        let channel = match get.bool("whether a channel moved")? {
            true => Some(Zeroizing::new(get.bytes("a channel", MAX_SESSION)?.to_vec())),
            false => None,
        };
        sessions.push(Session { layer, socket, channel });
    }
    get.end("the sessions")?;
    Ok((from, sessions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sessions_come_back_in_order_and_another_mark_or_version_is_refused() {
        let sessions = vec![
            Session { layer: Zeroizing::new(vec![1, 2, 3]), socket: Some(7), channel: Some(Zeroizing::new(vec![9])) },
            Session { layer: Zeroizing::new(vec![4]), socket: None, channel: None },
        ];
        let bytes = encode("podssh 1.1.0", &sessions);
        let (from, back) = decode(&bytes).unwrap();
        assert_eq!(from, "podssh 1.1.0");
        assert_eq!(back.len(), 2);
        assert_eq!(
            (&back[0].layer[..], back[0].socket, back[0].channel.as_deref().map(|c| &c[..])),
            (&[1u8, 2, 3][..], Some(7), Some(&[9u8][..]))
        );
        assert_eq!((&back[1].layer[..], back[1].socket, back[1].channel.is_none()), (&[4u8][..], None, true));
        let mut other = bytes.to_vec();
        other[MAGIC.len()] = VERSION + 1;
        assert!(matches!(decode(&other), Err(e) if e.0.contains("version")));
        assert!(matches!(decode(b"#!/bin/sh\n"), Err(e) if e.0.contains("no handover")));
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    }
}
