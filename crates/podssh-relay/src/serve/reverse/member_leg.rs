//! A leg for a member of the owner's net to a node that it reaches by no
//! other road (T-434): `POST /v1/leg/<KEY>`, KEY the node's key, finds the
//! live pair that KEY made here (its `maker`, T-630), and draws a token of one
//! leg of it, which the role registers as a node registers its own (T-615).
//! The asker proves its key as the mint asks (`serve::keys::prove`); only a
//! key that the role mints for gets a token. The node is told which token an
//! upgrade took, as for each token of one leg; it holds no such token, so it
//! keeps its own window as it was. The end-to-end channel above still holds
//! the node's allowlist: the role lets a member reach the node's socket, and
//! the node decides who gets in.

use std::sync::Arc;

use super::super::{digest, hex, random, Pair, Pairs};
use super::LEG_LIFE_MS;
use crate::identity::PublicKey;

/// The bytes of a drawn token: as many as a node's token of one leg carries.
const TOKEN_BYTES: usize = 32;

/// Why no leg was drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoLeg {
    /// No live pair was made by that key, or its node is not joined.
    NoPair,
    /// The system gave no randomness.
    Failed(String),
}

impl Pairs {
    /// The live pair that `maker` made, with its node joined: the one that
    /// ends last, when the key made more than one.
    pub fn of_maker(&self, maker: &PublicKey, now_ms: u64) -> Option<Arc<Pair>> {
        let wanted = maker.fingerprint();
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.values()
            .filter(|pair| pair.maker.as_deref() == Some(wanted.as_str()))
            .filter(|pair| pair.expires_ms() > now_ms)
            .filter(|pair| {
                let state = pair.lock();
                !state.ended && state.node_outbox().is_some()
            })
            .max_by_key(|pair| pair.expires_ms())
            .cloned()
    }

    /// A token of one leg of the pair that `maker` made, drawn and
    /// registered here: the pair's name, the token, and its end.
    pub fn draw_leg(&self, maker: &PublicKey, now_ms: u64) -> Result<(String, String, u64), NoLeg> {
        let pair = self.of_maker(maker, now_ms).ok_or(NoLeg::NoPair)?;
        let token = hex(&random(TOKEN_BYTES).map_err(NoLeg::Failed)?);
        // Never past its pair; registered as a node registers its own, so
        // that one upgrade takes it, and only while the node is joined.
        let ends = now_ms.saturating_add(LEG_LIFE_MS).min(pair.expires_ms());
        if !pair.register_leg(&hex(&digest(&token)), ends, now_ms) {
            return Err(NoLeg::Failed("the drawn token's digest was refused".into()));
        }
        Ok((pair.name.clone(), token, ends))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    #[test]
    fn a_key_with_no_pair_gets_none() {
        let pairs = Pairs::default();
        assert_eq!(pairs.draw_leg(&key(7), 1_000), Err(NoLeg::NoPair));
    }

    #[test]
    fn a_pair_without_its_node_gives_no_leg() {
        let pairs = Pairs::default();
        let asker = super::super::super::Asker { key: key(7).fingerprint(), keys: 1 };
        pairs.make_for(1_000, false, Some(&asker)).expect("a pair");
        // Its node never joined: a token would wait for nobody.
        assert_eq!(pairs.draw_leg(&key(7), 1_000), Err(NoLeg::NoPair));
    }
}
