//! The forward road's tokens, of the contract's form
//! `ephm1.<expiry-ms>.forward.<mac>` (`docs/relay.md`, "Tokens"): a MAC of
//! HMAC-SHA256 under a secret of this relay's, so that only the relay that
//! minted a token takes it (Q49), and a token of the default relay is
//! refused here, as a client sends one only where it was minted. Beside
//! them, the tokens of one session of the cleartext road (T-326),
//! `once1.<expiry-ms>.<nonce>.<mac>`, which live minutes and which one
//! upgrade spends, as each hop of that road reads its header.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// The contract's longest life of a token: 72 h.
pub const LIFETIME_MS: u64 = 72 * 3600 * 1000;

/// The life of a token of one session (T-326): its upgrade follows its mint
/// at once, so minutes are enough, and a hop that read it has no more.
pub const ONCE_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// The tokens of one session spent and not ended that a relay keeps: past
/// them such a token is refused, never taken twice.
pub const SPENT_MAX: usize = 65_536;

/// The secret that a relay's tokens are made with, and the tokens of one
/// session that an upgrade spent, by their nonce, with their end.
pub struct Tokens {
    secret: Zeroizing<[u8; 32]>,
    spent: Mutex<HashMap<String, u64>>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tokens(..)")
    }
}

impl Tokens {
    /// Tokens under `secret`.
    pub fn new(secret: [u8; 32]) -> Tokens {
        Tokens { secret: Zeroizing::new(secret), spent: Mutex::new(HashMap::new()) }
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

    /// A challenge for a key (T-448), `c1.<end-ms>.<nonce>.<mac>`, which
    /// this relay alone makes and takes, until `life_ms` after `now_ms`;
    /// with its end.
    pub fn challenge(&self, now_ms: u64, life_ms: u64) -> Result<(String, u64), String> {
        use rand::TryRng;
        let mut nonce = [0u8; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut nonce).map_err(|e| format!("no randomness for a challenge: {e}"))?;
        let ends = now_ms + life_ms;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let tag = self.challenge_mac(ends, &nonce).finalize().into_bytes();
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag);
        Ok((format!("c1.{ends}.{nonce}.{tag}"), ends))
    }

    /// The end of `challenge` when it is one of this relay's and has not
    /// ended at `now_ms`; the MAC is compared in constant time.
    pub fn check_challenge(&self, challenge: &str, now_ms: u64) -> Option<u64> {
        let mut parts = challenge.split('.');
        let (Some("c1"), Some(ends), Some(nonce), Some(tag), None) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let ends: u64 = ends.parse().ok().filter(|e| *e > now_ms)?;
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(tag).ok()?;
        self.challenge_mac(ends, nonce).verify_slice(&tag).is_ok().then_some(ends)
    }

    /// A challenge's MAC: under the tokens' secret, apart from them by its
    /// first word.
    fn challenge_mac(&self, ends: u64, nonce: &str) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.secret[..]).expect("HMAC takes a key of any length");
        mac.update(format!("c1.{ends}.{nonce}").as_bytes());
        mac
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

    /// A token of one session (T-326), which [`Tokens::take`] takes at one
    /// upgrade alone, until [`ONCE_LIFETIME_MS`] after `now_ms`; with its end.
    pub fn mint_once(&self, now_ms: u64) -> Result<(String, u64), String> {
        use rand::TryRng;
        let mut nonce = [0u8; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut nonce).map_err(|e| format!("no randomness for a token: {e}"))?;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let expiry = now_ms + ONCE_LIFETIME_MS;
        let tag = self.once_mac(expiry, &nonce).finalize().into_bytes();
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag);
        Ok((format!("once1.{expiry}.{nonce}.{tag}"), expiry))
    }

    /// A token of one session's MAC: under the tokens' secret, apart from
    /// the others by its first word.
    fn once_mac(&self, expiry: u64, nonce: &str) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.secret[..]).expect("HMAC takes a key of any length");
        mac.update(format!("once1.{expiry}.{nonce}").as_bytes());
        mac
    }

    /// The nonce and the end of `token` when it is a token of one session
    /// of this relay's that has not ended at `now_ms`, spent or not; the MAC
    /// is compared in constant time.
    fn once_of<'t>(&self, token: &'t str, now_ms: u64) -> Option<(&'t str, u64)> {
        let mut parts = token.split('.');
        let (Some("once1"), Some(expiry), Some(nonce), Some(tag), None) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let expiry: u64 = expiry.parse().ok().filter(|e| *e > now_ms && *e <= now_ms + ONCE_LIFETIME_MS)?;
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(tag).ok()?;
        self.once_mac(expiry, nonce).verify_slice(&tag).is_ok().then_some((nonce, expiry))
    }

    /// Whether `token` is a token of one session of this relay's that no
    /// upgrade took and that has not ended at `now_ms`: the cleartext road
    /// takes no other (T-326).
    pub fn is_once(&self, token: &str, now_ms: u64) -> bool {
        let Some((nonce, _)) = self.once_of(token, now_ms) else { return false };
        !self.spent.lock().unwrap_or_else(|e| e.into_inner()).contains_key(nonce)
    }

    /// Take `token` for one upgrade: a token of the contract's form until
    /// its end ([`Tokens::check`]); a token of one session the first time
    /// alone, also for two upgrades at once, and never again (T-326). With
    /// [`SPENT_MAX`] spent and not ended, one more is refused.
    pub fn take(&self, token: &str, now_ms: u64) -> bool {
        if self.check(token, now_ms) {
            return true;
        }
        let Some((nonce, expiry)) = self.once_of(token, now_ms) else { return false };
        let mut spent = self.spent.lock().unwrap_or_else(|e| e.into_inner());
        spent.retain(|_, end| *end > now_ms);
        if spent.len() >= SPENT_MAX || spent.contains_key(nonce) {
            return false;
        }
        spent.insert(nonce.to_string(), expiry);
        true
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

    #[test]
    fn a_challenge_is_this_relays_until_its_end_and_no_token() {
        let tokens = Tokens::new([1; 32]);
        let (challenge, ends) = tokens.challenge(1_000, 60_000).unwrap();
        assert_eq!(ends, 61_000);
        assert_eq!(tokens.check_challenge(&challenge, 60_999), Some(61_000));
        assert_eq!(tokens.check_challenge(&challenge, 61_000), None, "ended");
        assert_eq!(Tokens::new([2; 32]).check_challenge(&challenge, 1_000), None, "another relay's");
        assert!(!tokens.check(&challenge, 1_000), "a challenge is no token");
        let (token, _) = tokens.mint(1_000, 60_000);
        assert_eq!(tokens.check_challenge(&token, 1_000), None, "a token is no challenge");
        let later = challenge.replacen("c1.61000", "c1.99000", 1);
        assert_eq!(tokens.check_challenge(&later, 1_000), None, "a later end under the old MAC");
        assert_ne!(tokens.challenge(1_000, 60_000).unwrap().0, challenge, "each is drawn");
    }

    /// T-326: a token of one session is taken once, also by a second use
    /// at once; until its end alone, by its relay alone; it is no token of
    /// the contract's form, nor a challenge; and a token of 72 h is taken at
    /// each upgrade, as before.
    #[test]
    fn a_token_of_one_session_is_taken_once_and_no_other_is_one() {
        let tokens = Tokens::new([1; 32]);
        let (once, expiry) = tokens.mint_once(1_000).unwrap();
        assert_eq!(expiry, 1_000 + ONCE_LIFETIME_MS);
        assert!(once.starts_with(&format!("once1.{expiry}.")), "{once}");
        assert!(tokens.is_once(&once, 2_000) && !tokens.check(&once, 2_000), "no token of the contract's form");
        assert_eq!(tokens.check_challenge(&once, 2_000), None, "no challenge");
        assert!(!Tokens::new([2; 32]).is_once(&once, 2_000), "another relay's secret");
        assert!(!tokens.is_once(&once, expiry), "ended");
        assert!(tokens.take(&once, 2_000), "the first upgrade");
        assert!(!tokens.take(&once, 2_001) && !tokens.is_once(&once, 2_001), "a second use");
        assert_ne!(tokens.mint_once(1_000).unwrap().0, once, "each is drawn");
        let later = once.replacen(&format!("once1.{expiry}"), &format!("once1.{}", expiry + 1), 1);
        assert!(!tokens.is_once(&later, 2_000), "a later end under the old MAC");
        let (forward, _) = tokens.mint(1_000, 60_000);
        assert!(!tokens.is_once(&forward, 2_000), "a token of 72 h is no token of one session");
        assert!(tokens.take(&forward, 2_000) && tokens.take(&forward, 2_001), "taken at each upgrade");
    }

    /// The spent tokens of one session are kept until their end, then
    /// forgotten; past [`SPENT_MAX`] one more is refused, not taken twice.
    #[test]
    fn the_spent_tokens_are_kept_until_their_end_and_bounded() {
        let tokens = Tokens::new([1; 32]);
        let (first, expiry) = tokens.mint_once(1_000).unwrap();
        assert!(tokens.take(&first, 1_001));
        let (second, _) = tokens.mint_once(expiry).unwrap();
        assert!(tokens.take(&second, expiry + 1), "the first is forgotten at its end");
        assert_eq!(tokens.spent.lock().unwrap().len(), 1);
        let full: HashMap<String, u64> = (0..SPENT_MAX).map(|i| (format!("n{i}"), u64::MAX)).collect();
        *tokens.spent.lock().unwrap() = full;
        let (third, _) = tokens.mint_once(expiry).unwrap();
        assert!(!tokens.take(&third, expiry + 2), "refused when the record of spent tokens is full");
    }
}
