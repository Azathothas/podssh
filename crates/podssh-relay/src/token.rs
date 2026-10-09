//! Getting a relay token: `PODSSH_RELAY_TOKEN` if set, else a cached one,
//! else a fresh one minted with `POST /v1/mint` (self-service, no account).
//! Tokens go into the `X-Relay-Token` header and nowhere else: not into
//! output, errors, URLs or argv.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_ws::{https_post_json, ConnectError, ProxyChoice, Trust};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::cache as token_cache;
use crate::relay::{parse_relay, Relay, DEFAULT_RELAY_HOST};

/// Environment variable carrying a token to use instead of minting.
pub const TOKEN_ENV: &str = "PODSSH_RELAY_TOKEN";

/// Where a token came from. A rejected cached token is replaced once by a
/// fresh one; a rejected token from the environment is reported instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Environment,
    Cache,
    Minted,
}

/// A relay token in memory, wiped on drop. Its `Debug` never shows it.
pub struct Token {
    secret: Zeroizing<String>,
    pub origin: Origin,
    /// Set when a minted token could not be cached (podssh then mints on
    /// every run), so the caller can say so once.
    pub cache_warning: Option<String>,
    /// The relay that minted it (`host` or `host:port`), when known.
    pub minted_at: Option<String>,
}

impl Token {
    /// The token, for the request header and nothing else.
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("secret", &"<redacted>")
            .field("origin", &self.origin)
            .field("minted_at", &self.minted_at)
            .finish()
    }
}

/// Why no token could be had.
#[derive(Debug)]
pub enum TokenError {
    /// `PODSSH_RELAY_TOKEN` is set to something that is not a token.
    BadEnvironment,
    /// The mint endpoint could not be reached.
    Connect(ConnectError),
    /// `429`: the relay is limiting how fast tokens are minted.
    RateLimited { retry_after: Option<String> },
    /// `503`: this relay does not issue tokens.
    NotIssued,
    /// Any other answer.
    Failed { status: u16, detail: String },
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::BadEnvironment => write!(f, "{TOKEN_ENV} is set but does not look like a relay token"),
            TokenError::Connect(e) => write!(f, "could not mint a relay token: {e}"),
            TokenError::RateLimited { retry_after: Some(s) } => {
                write!(f, "the relay is rate-limiting token minting; retry in {s} s")
            }
            TokenError::RateLimited { retry_after: None } => {
                write!(f, "the relay is rate-limiting token minting; retry shortly")
            }
            TokenError::NotIssued => {
                write!(f, "this relay does not issue tokens (HTTP 503); ask its operator for one and set {TOKEN_ENV}")
            }
            TokenError::Failed { status, detail } => write!(f, "minting a relay token failed: HTTP {status}{detail}"),
        }
    }
}

/// What minting needs: the relay host to mint at (and to send the token to),
/// and how to reach it.
pub struct MintContext<'a> {
    pub relay: &'a Relay,
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    pub timeout: Duration,
}

/// The name a token is cached under: one for each relay deployment. The
/// hosts of the default deployment share the default host's token (a pool
/// host accepts it, measured 2026-10-08); any other host has its own, with
/// its port when that is not 443. So a token never goes to a deployment that
/// did not mint it (the operator, 2026-10-08).
pub fn token_key(relay: &Relay) -> String {
    if relay.host == DEFAULT_RELAY_HOST || crate::pool::same_deployment(DEFAULT_RELAY_HOST, &relay.host) {
        DEFAULT_RELAY_HOST.to_string()
    } else {
        relay_name(relay)
    }
}

/// `host`, or `host:port` when the port is not 443.
pub fn relay_name(relay: &Relay) -> String {
    if relay.port == 443 {
        relay.host.clone()
    } else {
        format!("{}:{}", relay.host, relay.port)
    }
}

/// Whether a cached token may be sent under `key`: only when its entry names
/// the relay that minted it, and that relay has the same key. An entry with
/// no minting relay was cached under the first host of a list, also when
/// another host minted it, so it is not used: one more mint costs less than
/// a token sent to the wrong deployment.
pub fn usable(key: &str, minted_at: Option<&str>) -> bool {
    minted_at.and_then(|m| parse_relay(m).ok()).is_some_and(|r| token_key(&r) == key)
}

/// The token to use. With `fresh`, skip the environment and the cache (after
/// the relay rejected a cached token).
pub async fn obtain(ctx: &MintContext<'_>, fresh: bool) -> Result<Token, TokenError> {
    let key = token_key(ctx.relay);
    if !fresh {
        if let Some(value) = std::env::var(TOKEN_ENV).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
            if !token_cache::valid_token(&value) {
                return Err(TokenError::BadEnvironment);
            }
            let secret = Zeroizing::new(value);
            return Ok(Token { secret, origin: Origin::Environment, cache_warning: None, minted_at: None });
        }
        if let Some(cached) = token_cache::load(&key, now_ms()).filter(|c| usable(&key, c.minted_at.as_deref())) {
            let secret = Zeroizing::new(cached.token);
            return Ok(Token { secret, origin: Origin::Cache, cache_warning: None, minted_at: cached.minted_at });
        }
    }
    let (token, expires) = mint(ctx).await?;
    let minted_at = relay_name(ctx.relay);
    let cache_warning = token_cache::store(&key, &token, expires, &minted_at).err();
    Ok(Token { secret: Zeroizing::new(token), origin: Origin::Minted, cache_warning, minted_at: Some(minted_at) })
}

#[derive(Deserialize)]
struct MintResponse {
    token: String,
    /// Milliseconds since the epoch.
    expires: i64,
}

/// `POST /v1/mint` with `{}`; the relay answers `{token, expires, scope}`.
async fn mint(ctx: &MintContext<'_>) -> Result<(String, i64), TokenError> {
    let response =
        https_post_json(&ctx.relay.host, ctx.relay.port, "/v1/mint", b"{}", ctx.trust, ctx.proxy, ctx.timeout)
            .await
            .map_err(TokenError::Connect)?;
    match response.status {
        200..=299 => {
            // Never quote a 2xx body in an error: it may hold a token.
            let parsed: MintResponse = serde_json::from_slice(&response.body).map_err(|_| TokenError::Failed {
                status: response.status,
                detail: ": the response was not the expected JSON".into(),
            })?;
            if !token_cache::valid_token(&parsed.token) {
                return Err(TokenError::Failed {
                    status: response.status,
                    detail: ": the response did not contain a usable token".into(),
                });
            }
            Ok((parsed.token, parsed.expires))
        }
        429 => Err(TokenError::RateLimited { retry_after: response.header("retry-after").map(str::to_string) }),
        503 => Err(TokenError::NotIssued),
        status => {
            let body = response.body_text(200);
            Err(TokenError::Failed {
                status,
                detail: if body.is_empty() { String::new() } else { format!(": {body}") },
            })
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
