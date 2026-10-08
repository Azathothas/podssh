//! Opening a forward session through the relay: a token from the environment,
//! the cache or a fresh mint, then the WebSocket upgrade, retried once with a
//! fresh token when the relay rejects a cached one. Shared by `proxy` and
//! `ssh`, which differ only in how they report a failure.

use std::time::Duration;

use podssh_ws::dial::DialError;
use podssh_ws::{connect, ConnectError, Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};

use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::relay::Relay;
use crate::relay_token::{self, MintContext, Origin, TokenError};

/// Bound on reaching the relay: proxy, TCP, TLS, upgrade, and minting.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Environment variable that forbids every network connection. Test suites
/// set it for the binaries they run, so no test can reach the relay by
/// accident; it is not meant for users.
pub const OFFLINE_ENV: &str = "PODSSH_OFFLINE";

/// Whether [`OFFLINE_ENV`] is set (to anything but empty or `0`).
pub fn offline() -> bool {
    std::env::var(OFFLINE_ENV).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Why no session could be opened.
#[derive(Debug)]
pub enum OpenError {
    /// [`OFFLINE_ENV`] is set.
    Offline,
    Token(TokenError),
    Connect { error: ConnectError, origin: Origin, target: String },
}

impl OpenError {
    /// What to print, one message per line, without a `podssh:` prefix.
    pub fn lines(&self) -> Vec<String> {
        match self {
            OpenError::Offline => vec![format!("{OFFLINE_ENV} is set, so podssh does not connect anywhere")],
            OpenError::Token(e) => vec![e.to_string()],
            OpenError::Connect { error, origin, target } => {
                let mut lines = vec![error.to_string()];
                let hint = match error {
                    ConnectError::Refused { status: 400 | 403, body } if is_policy_refusal(body) => {
                        Some(format!("the relay's policy does not allow {target}"))
                    }
                    ConnectError::Refused { status: 403, .. } if *origin == Origin::Environment => {
                        Some(format!("the token in {} was rejected", relay_token::TOKEN_ENV))
                    }
                    ConnectError::Refused { status: 502, .. } => Some(format!("the relay could not reach {target}")),
                    ConnectError::Dial(DialError::ProxyRefused { .. }) => {
                        Some("the HTTP proxy does not allow connections to the relay".to_string())
                    }
                    _ => None,
                };
                lines.extend(hint);
                lines
            }
        }
    }

    /// The sysexits code `podssh proxy` exits with.
    pub fn sysexit(&self) -> i32 {
        match self {
            OpenError::Offline => EX_UNAVAILABLE,
            OpenError::Token(TokenError::BadEnvironment) => EX_CONFIG,
            OpenError::Token(TokenError::Connect(c)) => exit_for(c),
            OpenError::Token(_) => EX_UNAVAILABLE,
            OpenError::Connect { error, .. } => exit_for(error),
        }
    }
}

/// Open `path` (`/connect/<host>/<port>[?…]`) on `relay`. `target` is
/// `host:port`, for messages. `warn` receives non-fatal notes (a token that
/// could not be cached).
pub async fn open(
    relay: &Relay,
    path: &str,
    trust: &Trust,
    target: &str,
    warn: &mut dyn FnMut(&str),
) -> Result<RelaySession, OpenError> {
    if offline() {
        return Err(OpenError::Offline);
    }
    let proxy = ProxyChoice::FromEnvironment;
    let ctx = MintContext { relay, trust, proxy: &proxy, timeout: CONNECT_TIMEOUT };
    let mut token = relay_token::obtain(&ctx, false).await.map_err(OpenError::Token)?;
    if let Some(why) = token.cache_warning.take() {
        warn(&format!("the relay token could not be cached, so one is minted per run: {why}"));
    }
    let config = WsClientConfig {
        endpoint: Endpoint { host: relay.host.clone(), port: relay.port, path: path.to_string() },
        trust: trust.clone(),
        server_name: relay.host.clone(),
        timeout: CONNECT_TIMEOUT,
        idle_timeout: Some(podssh_ws::DEFAULT_IDLE_TIMEOUT),
        proxy: proxy.clone(),
    };
    let mut result = connect(&config, token.secret()).await;
    // A cached token the relay no longer accepts: forget it and mint once.
    // Not for a policy refusal, which a new token cannot fix.
    if let Err(ConnectError::Refused { status: 403, body }) = &result {
        if token.origin == Origin::Cache && !is_policy_refusal(body) {
            crate::token_cache::remove(&relay.host);
            token = relay_token::obtain(&ctx, true).await.map_err(OpenError::Token)?;
            result = connect(&config, token.secret()).await;
        }
    }
    let origin = token.origin;
    drop(token);
    result.map_err(|error| OpenError::Connect { error, origin, target: target.to_string() })
}

/// The relay's wording for a policy refusal (spec: "not in the ALLOW list").
pub fn is_policy_refusal(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    body.contains("allow list") || body.contains("not allowed") || body.contains("blocked")
}

/// The sysexits code for a connection failure.
fn exit_for(e: &ConnectError) -> i32 {
    match e {
        ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_)) => EX_CONFIG,
        ConnectError::Refused { status: 401 | 403, .. } => EX_NOPERM,
        // The relay answers 400 for a target in a blocked address range.
        ConnectError::Refused { status: 400, body } if is_policy_refusal(body) => EX_NOPERM,
        ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}
