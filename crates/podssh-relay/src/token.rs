//! Getting a relay token: `PODSSH_RELAY_TOKEN` if set, else a cached one,
//! else a fresh one minted with `POST /v1/mint` (self-service, no account).
//! Tokens go into the `X-Relay-Token` header and nowhere else: not into
//! output, errors, URLs or argv.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_ws::{https_post_json, ConnectError, ProxyChoice, Trust};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::cache as token_cache;
use crate::relay::Relay;

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
}

impl Token {
    /// The token, for the request header and nothing else.
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token").field("secret", &"<redacted>").field("origin", &self.origin).finish()
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
            TokenError::NotIssued => write!(
                f,
                "this relay does not issue tokens (HTTP 503); ask its operator for one and set {TOKEN_ENV}"
            ),
            TokenError::Failed { status, detail } => write!(f, "minting a relay token failed: HTTP {status}{detail}"),
        }
    }
}

/// What minting needs: the relay host to mint at, how to reach it, and the
/// name the token is cached under (the primary host of the relay list: a token
/// is valid on every host of one relay deployment).
pub struct MintContext<'a> {
    pub relay: &'a Relay,
    pub cache_key: &'a str,
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    pub timeout: Duration,
}

/// The token to use. With `fresh`, skip the environment and the cache (after
/// the relay rejected a cached token).
pub async fn obtain(ctx: &MintContext<'_>, fresh: bool) -> Result<Token, TokenError> {
    if !fresh {
        if let Some(value) = std::env::var(TOKEN_ENV).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
            if !token_cache::valid_token(&value) {
                return Err(TokenError::BadEnvironment);
            }
            return Ok(Token { secret: Zeroizing::new(value), origin: Origin::Environment, cache_warning: None });
        }
        if let Some(cached) = token_cache::load(ctx.cache_key, now_ms()) {
            return Ok(Token { secret: Zeroizing::new(cached.token), origin: Origin::Cache, cache_warning: None });
        }
    }
    let (token, expires) = mint(ctx).await?;
    let cache_warning = token_cache::store(ctx.cache_key, &token, expires).err();
    Ok(Token { secret: Zeroizing::new(token), origin: Origin::Minted, cache_warning })
}

#[derive(Deserialize)]
struct MintResponse {
    token: String,
    /// Milliseconds since the epoch.
    expires: i64,
}

/// `POST /v1/mint` with `{}`; the relay answers `{token, expires, scope}`.
async fn mint(ctx: &MintContext<'_>) -> Result<(String, i64), TokenError> {
    let response = https_post_json(
        &ctx.relay.host,
        ctx.relay.port,
        "/v1/mint",
        b"{}",
        ctx.trust,
        ctx.proxy,
        ctx.timeout,
    )
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
            Err(TokenError::Failed { status, detail: if body.is_empty() { String::new() } else { format!(": {body}") } })
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
