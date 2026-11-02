//! The forward road's tokens, of the contract's form
//! `ephm1.<expiry-ms>.forward.<mac>` (`docs/relay.md`, "Tokens"): a MAC of
//! HMAC-SHA256 under a secret of this relay's, so that only the relay that
//! minted a token takes it (Q49), and a token of the default relay is
//! refused here, as a client sends one only where it was minted.

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// The contract's longest life of a token: 72 h.
pub const LIFETIME_MS: u64 = 72 * 3600 * 1000;

/// The secret that a relay's tokens are made with.
pub struct Tokens {
    secret: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tokens(..)")
    }
}

impl Tokens {
    /// Tokens under `secret`.
    pub fn new(secret: [u8; 32]) -> Tokens {
        Tokens { secret: Zeroizing::new(secret) }
    }

    /// Tokens under a secret of this run: a restart ends each token, as a
    /// new `MINT_SECRET` ends the default relay's.
    pub fn random() -> Result<Tokens, String> {
        use rand::TryRng;
        let mut secret = [0u8; 32];
        rand::rngs::SysRng.try_fill_bytes(&mut secret).map_err(|e| format!("no randomness for a secret: {e}"))?;
        Ok(Tokens::new(secret))
    }

    fn mac(&self, expiry: u64) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.secret[..]).expect("HMAC takes a key of any length");
        mac.update(format!("ephm1.{expiry}.forward").as_bytes());
        mac
    }

    /// A token that ends `lifetime_ms` after `now_ms`, and its end.
    pub fn mint(&self, now_ms: u64, lifetime_ms: u64) -> (String, u64) {
        let expiry = now_ms + lifetime_ms.min(LIFETIME_MS);
        let tag = self.mac(expiry).finalize().into_bytes();
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag);
        (format!("ephm1.{expiry}.forward.{tag}"), expiry)
    }

    /// Whether `token` is one of this relay's, not ended at `now_ms`; the
    /// MAC is compared in constant time.
    pub fn check(&self, token: &str, now_ms: u64) -> bool {
        let mut parts = token.split('.');
        let (Some("ephm1"), Some(expiry), Some("forward"), Some(tag), None) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        let Ok(expiry) = expiry.parse::<u64>() else { return false };
        if expiry <= now_ms || expiry > now_ms + LIFETIME_MS {
            return false;
        }
        let Ok(tag) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(tag) else { return false };
        self.mac(expiry).verify_slice(&tag).is_ok()
    }
}

/// The time in milliseconds since the epoch, as the contract counts it.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_token_is_taken_until_its_end_and_by_its_relay_alone() {
        let tokens = Tokens::new([1; 32]);
        let (token, expiry) = tokens.mint(1_000, 60_000);
        assert_eq!(expiry, 61_000);
        assert!(token.starts_with("ephm1.61000.forward."), "{token}");
        assert!(tokens.check(&token, 60_999));
        assert!(!tokens.check(&token, 61_000), "ended");
        assert!(!Tokens::new([2; 32]).check(&token, 1_000), "another relay's secret");
    }

    #[test]
    fn a_changed_or_malformed_token_is_refused() {
        let tokens = Tokens::new([1; 32]);
        let (token, _) = tokens.mint(1_000, 60_000);
        let later = token.replacen("ephm1.61000", "ephm1.99000", 1);
        assert!(!tokens.check(&later, 1_000), "a later expiry under the old MAC");
        for bad in ["", "ephm1", "ephm1.x.forward.y", "ephm1.61000.reverse.AAAA", &format!("{token}.extra")] {
            assert!(!tokens.check(bad, 1_000), "{bad:?}");
        }
        let (long, _) = tokens.mint(1_000, u64::MAX / 2);
        assert!(tokens.check(&long, 1_000), "the lifetime is cut to 72 h, not refused");
    }
}
