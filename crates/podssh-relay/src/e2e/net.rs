//! The net's document between two ends (T-429): of two ends that hold a
//! document of one owner, the one with the higher serial gives it to the
//! other inside the channel, as Tailnet Lock's nodes pass on the state that
//! the signing keys signed. This crate carries the bytes and compares two
//! serials; the binary checks the owner's signature and keeps the document
//! (`podssh net`), so that no SSH code comes into this crate.
//!
//! An end of before must never meet a form that it does not read. So the
//! operator's first message of the handshake carries [`OFFER`] as its
//! payload, in clear, which a podssh of before reads and sets aside; only a
//! node that saw it answers with a proof of the net's form, which names the
//! owner and the serial that it holds, encrypted; and only an operator that
//! got such a proof sends one. The owner and the serial travel encrypted,
//! so the relay learns no more than that both ends read documents.
//!
//! The operator's document goes before the node's verdict, so that a newer
//! one is in force for the session that brought it; the node's goes after
//! its verdict, to an operator that it let in. Each end gives its document
//! only to a peer whose key is a member of it ([`Docs::shares_with`]): a
//! key that the owner removed learns nothing more of the net.

use std::sync::{Arc, OnceLock};

use crate::identity::PublicKey;

/// The payload of the operator's first message: this end holds a document
/// of a net, and reads the net's form of a proof.
pub const OFFER: &[u8] = b"podssh-net/1";

/// What an end holds of a net: its owner, as the SHA-256 of the owner key's
/// fingerprint, and the document's serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Held {
    pub owner: [u8; 32],
    pub serial: u64,
}

impl Held {
    /// Whether this is a document of the owner of `other`, with a higher
    /// serial: the one that two ends keep.
    pub fn newer_than(&self, other: &Held) -> bool {
        self.owner == other.owner && self.serial > other.serial
    }
}

/// The net's documents of an end, as the binary keeps them. Each call reads
/// the document anew, so that one taken during a session counts at once.
pub trait Docs: Send + Sync {
    /// The document held, checked, and its bytes as they travel; `None`
    /// when this end holds none that it trusts.
    fn held(&self) -> Option<(Held, Vec<u8>)>;
    /// Whether the document held names `peer` as a member, so that it may
    /// have the document.
    fn shares_with(&self, peer: &PublicKey) -> bool;
    /// A document that `from` gave: kept when its owner signed it and its
    /// serial is higher than the one held; why not, else. The binary says
    /// what it did on its own lines, and the session goes on either way.
    fn take(&self, from: &PublicKey, bytes: &[u8]) -> Result<(), String>;
}

static INSTALLED: OnceLock<Arc<dyn Docs>> = OnceLock::new();

/// The documents of this process, for each channel that it runs; the first
/// call wins, as a process has one user's net.
pub fn install(docs: Arc<dyn Docs>) {
    let _ = INSTALLED.set(docs);
}

/// The documents of this process, when it installed them.
pub fn installed() -> Option<Arc<dyn Docs>> {
    INSTALLED.get().cloned()
}

/// What follows the key and its binding in a proof of the net's form: the
/// route's length and the route, then whether a document is held (1) and
/// its owner and serial, then whether the sender's document follows the
/// proof (1).
pub(super) fn encode(route: Option<&str>, held: Option<Held>, follows: bool) -> Vec<u8> {
    let route = route.unwrap_or_default();
    let mut out = Vec::with_capacity(2 + route.len() + 41);
    // The caller checked that the route fits its one byte.
    out.push(route.len() as u8);
    out.extend_from_slice(route.as_bytes());
    match held {
        Some(held) => {
            out.push(1);
            out.extend_from_slice(&held.owner);
            out.extend_from_slice(&held.serial.to_be_bytes());
        }
        None => out.push(0),
    }
    out.push(u8::from(follows));
    out
}

/// The parts of [`encode`]: the route's bytes, unchecked, what the peer
/// holds, and whether its document follows; `None` for bytes of no such
/// form.
pub(super) fn decode(rest: &[u8]) -> Option<(Option<&[u8]>, Option<Held>, bool)> {
    let (&len, rest) = rest.split_first()?;
    let (route, rest) = rest.split_at_checked(usize::from(len))?;
    let (&has, rest) = rest.split_first()?;
    let (held, rest) = match has {
        0 => (None, rest),
        1 => {
            let (owner, rest) = rest.split_at_checked(32)?;
            let (serial, rest) = rest.split_at_checked(8)?;
            let owner: [u8; 32] = owner.try_into().ok()?;
            let serial = u64::from_be_bytes(serial.try_into().ok()?);
            (Some(Held { owner, serial }), rest)
        }
        _ => return None,
    };
    let follows = match rest {
        [0] => false,
        [1] => true,
        _ => return None,
    };
    Some(((len > 0).then_some(route), held, follows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proof_s_net_part_reads_back_whole() {
        let held = Held { owner: [7; 32], serial: 0x0102_0304_0506_0708 };
        for (route, held, follows) in [(None, None, false), (Some("web"), Some(held), true), (None, Some(held), false)]
        {
            let bytes = encode(route, held, follows);
            let (got, got_held, got_follows) = decode(&bytes).expect("it reads");
            assert_eq!((got.map(|r| std::str::from_utf8(r).unwrap()), got_held, got_follows), (route, held, follows));
        }
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0, 2, 0]), None, "neither held nor not");
        assert_eq!(decode(&[0, 0, 0, 9]), None, "a byte after the end");
        assert_eq!(decode(&[0, 1, 1, 2]), None, "a held document cut short");
    }

    #[test]
    fn only_a_higher_serial_of_the_same_owner_is_newer() {
        let (a, b) = (Held { owner: [1; 32], serial: 3 }, Held { owner: [1; 32], serial: 2 });
        assert!(a.newer_than(&b) && !b.newer_than(&a) && !a.newer_than(&a));
        assert!(!Held { owner: [2; 32], serial: 9 }.newer_than(&b), "another owner's document is never newer");
    }
}
