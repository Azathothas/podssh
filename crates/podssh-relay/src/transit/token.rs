//! The words of a meeting at the transit relay (T-436), from the pair's
//! secret: the token by which the relay pairs two sides, and the key of
//! podssh's own proof of the pair, each by HKDF-SHA256 from the pair's
//! connect token and name, which both ends hold; and this end's side, at
//! random. The token is the transit relay's to see: it lets a side meet
//! the node and no more, as the proof key cannot be had from it.

use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::session::secret::{Entropy, NoRandom};

/// The salt of both derivations: a new version of the words is a new salt.
pub const SALT: &[u8] = b"podssh transit, version 1";
const TOKEN_LABEL: &[u8] = b"podssh transit token";
const PROOF_KEY_LABEL: &[u8] = b"podssh transit proof key";
const PROOF_LABEL: &[u8] = b"podssh transit proof";
/// The bytes of the token, written as 64 hex digits, as the relay reads it.
pub const TOKEN_BYTES: usize = 32;
/// The bytes of a side, written as 16 hex digits.
pub const SIDE_BYTES: usize = 8;
/// The bytes of a proof: HMAC-SHA256.
pub const PROOF_BYTES: usize = 32;

/// The pair's words at the relay: its token, and its proof key.
#[derive(Clone)]
pub struct Keys {
    token: String,
    proof: Zeroizing<[u8; 32]>,
}

impl Keys {
    /// The words of the pair `name` whose connect token is `connect_token`:
    /// the node's whole pair and the operator's part give the same.
    pub fn of_pair(name: &str, connect_token: &str) -> Keys {
        let hkdf = Hkdf::<Sha256>::new(Some(SALT), connect_token.as_bytes());
        let mut token = [0u8; TOKEN_BYTES];
        let mut proof = Zeroizing::new([0u8; 32]);
        // 32 bytes is far below HKDF-SHA256's 8160, so neither can fail; a
        // failure would leave zeros, which meet nobody's proof.
        let _ = hkdf.expand(&info(TOKEN_LABEL, name), &mut token);
        let _ = hkdf.expand(&info(PROOF_KEY_LABEL, name), &mut proof[..]);
        Keys { token: hex(&token), proof }
    }

    /// A side that knows the token alone, as the transit relay does: its
    /// proof key is none of the pair's. For a test of the door.
    pub fn knowing_only(token: &str) -> Keys {
        Keys { token: token.to_string(), proof: Zeroizing::new([0u8; 32]) }
    }

    /// The token, in the line to the relay. It is no credential of the
    /// pair's, but a meeting point: it is never printed.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The proof of the side whose role is `role`, which sent `sender`'s
    /// nonce and got `receiver`'s: each role and each order is its own, so
    /// the relay cannot send a proof back to the one who made it.
    pub fn prove(&self, role: u8, sender: &[u8], receiver: &[u8]) -> [u8; PROOF_BYTES] {
        self.mac(role, sender, receiver).finalize().into_bytes().into()
    }

    /// Whether `proof` is [`Keys::prove`]'s, compared in constant time.
    pub fn verify(&self, role: u8, sender: &[u8], receiver: &[u8], proof: &[u8]) -> bool {
        self.mac(role, sender, receiver).verify_slice(proof).is_ok()
    }

    fn mac(&self, role: u8, sender: &[u8], receiver: &[u8]) -> Hmac<Sha256> {
        // A key of any length is valid for HMAC; 32 bytes always are.
        let mut mac = match Hmac::<Sha256>::new_from_slice(&self.proof[..]) {
            Ok(mac) => mac,
            Err(_) => <Hmac<Sha256> as KeyInit>::new(&Default::default()),
        };
        mac.update(PROOF_LABEL);
        mac.update(&[0, role]);
        mac.update(sender);
        mac.update(receiver);
        mac
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither the token nor the key goes into a line.
        f.write_str("Keys(..)")
    }
}

/// A side of the relay's line: 16 hex digits. The relay pairs two sides of
/// one token that differ, so each end keeps one for its run: two links of
/// one end never meet each other.
#[derive(Clone, PartialEq, Eq)]
pub struct Side(String);

impl Side {
    /// A side at random.
    pub fn random(entropy: &mut dyn Entropy) -> Result<Side, NoRandom> {
        let mut bytes = [0u8; SIDE_BYTES];
        entropy.fill(&mut bytes)?;
        Ok(Side(hex(&bytes)))
    }

    /// The side of these 16 hex digits, for a test; `None` for another text.
    pub fn parse(text: &str) -> Option<Side> {
        let ok = text.len() == 2 * SIDE_BYTES && text.bytes().all(|b| b.is_ascii_hexdigit());
        ok.then(|| Side(text.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Side({})", self.0)
    }
}

/// The line that opens a connection to the relay, newline included:
/// `please relay TOKEN for side SIDE`, the form with a side
/// (magic-wormhole/magic-wormhole-transit-relay:
/// src/wormhole_transit_relay/transit_server.py), which a relay matches
/// only with another side.
pub fn line(keys: &Keys, side: &Side) -> String {
    format!("please relay {} for side {}\n", keys.token(), side.as_str())
}

fn info(label: &[u8], name: &str) -> Vec<u8> {
    [label, &[0], name.as_bytes()].concat()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "0123456789abcdef0123456789abcdef";
    const CONNECT: &str = "connect-token-of-a-test-0123456789abcdef";

    // Computed with Python's hmac and hashlib (HKDF by RFC 5869 written out),
    // software that podssh did not write.
    const TOKEN: &str = "6afbdee96c50e22b2b8909831bb054cc0cd822f84563d2a4cae67552ab1f1ae0";
    const PROOF_KEY: &str = "679a267eeb49939a7e39adbef08576e7e4ba798e4afd136d406f2c6f66b12eba";
    const PROOF_OF_C: &str = "843a0eb5c6c8386c1ce814c01dc952dfd1b3222b1a4d7558ce96fbdbc1689f67";

    #[test]
    fn the_token_and_the_proof_key_are_hkdf_sha256_of_the_pair_as_python_computes_them() {
        let keys = Keys::of_pair(NAME, CONNECT);
        assert_eq!(keys.token(), TOKEN);
        assert_eq!(hex(&keys.proof[..]), PROOF_KEY);
        let proof = keys.prove(b'C', &[1; 32], &[2; 32]);
        assert_eq!(hex(&proof), PROOF_OF_C);
        assert!(keys.verify(b'C', &[1; 32], &[2; 32], &proof));
    }

    #[test]
    fn a_proof_holds_for_its_role_and_order_alone_and_never_for_the_token_alone() {
        let keys = Keys::of_pair(NAME, CONNECT);
        let proof = keys.prove(b'N', &[1; 32], &[2; 32]);
        assert!(keys.verify(b'N', &[1; 32], &[2; 32], &proof));
        assert!(!keys.verify(b'C', &[1; 32], &[2; 32], &proof), "another role");
        assert!(!keys.verify(b'N', &[2; 32], &[1; 32], &proof), "the nonces swapped");
        assert!(!keys.verify(b'N', &[1; 32], &[2; 32], &proof[..31]), "a proof cut short");
        let stranger = Keys::knowing_only(keys.token());
        assert_eq!(stranger.token(), keys.token());
        assert!(!keys.verify(b'N', &[1; 32], &[2; 32], &stranger.prove(b'N', &[1; 32], &[2; 32])));
        let other_pair = Keys::of_pair(NAME, "another connect token");
        assert_ne!(other_pair.token(), keys.token());
        assert_ne!(Keys::of_pair("another-name", CONNECT).token(), keys.token());
    }

    #[test]
    fn the_line_is_the_relay_s_form_with_a_side_and_nothing_prints_a_key() {
        let keys = Keys::of_pair(NAME, CONNECT);
        let side = Side::parse("0123456789ABCDEF").unwrap();
        assert_eq!(line(&keys, &side), format!("please relay {TOKEN} for side 0123456789abcdef\n"));
        assert_eq!(keys.token().len(), 64);
        assert!(Side::parse("0123").is_none() && Side::parse("0123456789abcdeg").is_none());
        let random = Side::random(&mut crate::session::OsEntropy).unwrap();
        assert_eq!(random.as_str().len(), 16);
        assert!(!format!("{keys:?}").contains(TOKEN));
    }
}
