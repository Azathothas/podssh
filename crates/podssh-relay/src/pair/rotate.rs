//! A pair's stop token, rotated in podssh's relay role (T-615), beside the
//! contract, which rotates none. `POST /v1/rotate/<name>` with the stop
//! token and `{"digest": HEX}`, the SHA-256 of a token that the pair's owner
//! drew, makes that one the token to come; its first use, of any request
//! that takes the stop token, makes it the pair's, and the role then refuses
//! each before it. The new token crosses no wire before that use, and an
//! owner that stops between the two keeps a token that the role takes: the
//! old one while it has not kept the new, the new one after. A relay of the
//! contract answers the path as one that it does not have (404, or 405),
//! which is no refusal: it rotates nothing.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{checked, refused, Pair, PairContext, PairError};

/// The path of a rotation, before the pair's name.
pub const PATH: &str = "/v1/rotate/";

/// What a rotation gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotated {
    /// The relay took the token to come; with that token, it is the pair's.
    Asked,
    /// The relay rotates no stop token: 404 or 405 at the path.
    NotServed,
}

/// Ask the relay of `pair`, by its stop token, for `next` as the stop token
/// to come; with `next` as `pair`'s own stop token, that first use makes it
/// the pair's. A `403` is the contract's refusal of a token: the pair was
/// stopped, or it ended, or another rotation took the place of this one.
pub async fn rotate(ctx: &PairContext<'_>, pair: &Pair, next: &str) -> Result<Rotated, PairError> {
    let path = format!("{PATH}{}", checked(&pair.name)?);
    let body = serde_json::json!({ "digest": digest_hex(next) }).to_string();
    let response = podssh_ws::client::https_with_token(
        "POST",
        &ctx.relay.host,
        ctx.relay.port,
        &path,
        body.as_bytes(),
        pair.stop_token(),
        16 * 1024,
        ctx.trust,
        ctx.proxy,
        ctx.timeout,
    )
    .await
    .map_err(PairError::Connect)?;
    match response.status {
        200..=299 => Ok(Rotated::Asked),
        404 | 405 => Ok(Rotated::NotServed),
        status => Err(refused(status, &response)),
    }
}

/// The SHA-256 of `token` in hex, as the role keeps a token.
fn digest_hex(token: &str) -> String {
    Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// A new stop token: 64 characters of `[0-9a-z]`, the shape of the relay's
/// own (measured 2026-10-09); a byte of 252 or more is drawn again, so that
/// each character is as likely.
pub fn draw() -> Result<Zeroizing<String>, String> {
    use rand::TryRng;
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Zeroizing::new(String::with_capacity(64));
    let mut bytes = Zeroizing::new([0u8; 64]);
    while out.len() < 64 {
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes[..])
            .map_err(|e| format!("no randomness for a stop token: {e}"))?;
        for byte in bytes.iter().filter(|b| **b < 252) {
            if out.len() < 64 {
                out.push(char::from(ALPHABET[usize::from(*byte % 36)]));
            }
        }
    }
    Ok(out)
}

impl Pair {
    /// This pair with `stop_token` in the place of its stop token, and the
    /// rest the same: the copy that a rotation keeps. Each copy zeroes its
    /// tokens when it is dropped.
    pub fn with_stop(&self, stop_token: &str) -> Pair {
        Pair {
            relay: self.relay.clone(),
            name: self.name.clone(),
            node_token: self.node_token.clone(),
            connect_token: self.connect_token.clone(),
            stop_token: Zeroizing::new(stop_token.to_string()),
            expires_ms: self.expires_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_stop_token_has_the_relay_s_shape_and_a_rotated_copy_keeps_the_rest() {
        let (first, second) = (draw().unwrap(), draw().unwrap());
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()), "{}", first.as_str());
        assert_ne!(first, second, "each is drawn");
        assert!(crate::cache::valid_token(&first));
        let (name, token) = (format!("p-{}", "0".repeat(32)), "a".repeat(64));
        let body = format!(
            r#"{{"name":"{name}","node_token":"{token}","connect_token":"{token}","stop_token":"{token}","expires":3600000}}"#
        );
        let relay = crate::relay::Relay { host: "relay.test".into(), port: 443 };
        let pair = super::super::parse(&relay, body.as_bytes(), 0).unwrap();
        let rotated = pair.with_stop(&first);
        assert_eq!(rotated.stop_token(), first.as_str());
        assert_eq!((rotated.node_token(), rotated.connect_token()), (pair.node_token(), pair.connect_token()));
        assert_eq!((rotated.name.as_str(), rotated.expires_ms), (name.as_str(), 3_600_000));
        assert_eq!(digest_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
