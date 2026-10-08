//! The pairs of the reverse road (feature `pair`): `POST /v1/pair` makes one,
//! `GET /v1/status/<name>` says whether its node is online, and
//! `POST /v1/stop/<name>` ends it. They live on the relay's control host
//! only; no pool host was measured to serve `/v1/*`.
//!
//! A pair is three tokens, and each is a credential: in memory they are wiped
//! on drop, on disk they are in a private file, and no output, error or
//! `Debug` shows one. The relay reads them from `X-Relay-Token` only.

use std::path::{Path, PathBuf};
use std::time::Duration;

use podssh_ws::dial::ProxyChoice;
use podssh_ws::{ConnectError, Trust};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cache::{self, valid_token, MIN_REMAINING_MS};
use crate::relay::{check_node_name, parse_relay, Relay};
use crate::token::relay_name;

/// A pair, as `POST /v1/pair` gives it.
pub struct Pair {
    /// The control host that made the pair.
    pub relay: Relay,
    /// The relay's name of the pair, in `/v1/node/<name>` and
    /// `/v1/connect/<name>`.
    pub name: String,
    node_token: Zeroizing<String>,
    connect_token: Zeroizing<String>,
    stop_token: Zeroizing<String>,
    /// When the relay forgets the pair, in milliseconds since the epoch.
    pub expires_ms: i64,
}

impl Pair {
    /// For the node's socket, `/v1/node/<name>`, and nothing else.
    pub fn node_token(&self) -> &str {
        &self.node_token
    }

    /// For the operator's socket, `/v1/connect/<name>`, and for the status.
    pub fn connect_token(&self) -> &str {
        &self.connect_token
    }

    /// For `/v1/stop/<name>`. Never printed.
    pub fn stop_token(&self) -> &str {
        &self.stop_token
    }

    /// A second copy, for a runner that owns its pair while the caller keeps
    /// its own. Each copy zeroes its tokens when it is dropped.
    #[cfg(feature = "blocking")]
    pub(crate) fn duplicate(&self) -> Pair {
        Pair {
            relay: self.relay.clone(),
            name: self.name.clone(),
            node_token: self.node_token.clone(),
            connect_token: self.connect_token.clone(),
            stop_token: self.stop_token.clone(),
            expires_ms: self.expires_ms,
        }
    }
}

impl std::fmt::Debug for Pair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pair")
            .field("relay", &self.relay)
            .field("name", &self.name)
            .field("tokens", &"<redacted>")
            .field("expires_ms", &self.expires_ms)
            .finish()
    }
}

/// Where and how to ask the control host.
pub struct PairContext<'a> {
    pub relay: &'a Relay,
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    pub timeout: Duration,
}

/// Why a pairing call failed. No variant holds a token, and none quotes the
/// body of a 2xx answer, which holds them.
#[derive(Debug)]
pub enum PairError {
    Connect(ConnectError),
    /// `429`: the brake that pairs share with mints.
    RateLimited { retry_after: Option<String> },
    /// `503`: the relay makes no pairs, with what it said (an answer that is
    /// not a 2xx holds no token). Seen once on 2026-10-09 and gone at the
    /// next request.
    NotIssued { detail: String },
    /// `403 reverse: forbidden`: a wrong token, an expired pair or a stopped
    /// one look the same.
    Forbidden,
    /// The pair has less than 10 minutes left.
    ShortLived { left_ms: i64 },
    /// A 2xx answer that is not a usable pair, with what is wrong with it.
    BadAnswer(&'static str),
    /// A label that cannot be a file name, or no pair under a label.
    BadLabel(String),
    /// The pair could not be kept or read in a private file.
    Store(String),
    Failed { status: u16, detail: String },
}

impl std::fmt::Display for PairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairError::Connect(e) => write!(f, "{e}"),
            PairError::RateLimited { retry_after: Some(s) } => {
                write!(f, "the relay is limiting new pairs; try again in {s} s")
            }
            PairError::RateLimited { retry_after: None } => write!(f, "the relay is limiting new pairs; try again later"),
            PairError::NotIssued { detail } => write!(f, "the relay makes no pairs (503){detail}"),
            PairError::Forbidden => {
                write!(f, "the relay refused the token (403 reverse: forbidden): the pair is stopped or has expired")
            }
            PairError::ShortLived { left_ms } => {
                write!(f, "the pair has {} min left, under the 10 min that podssh needs", left_ms / 60_000)
            }
            PairError::BadAnswer(what) => write!(f, "the relay's answer is not a usable pair: {what}"),
            PairError::BadLabel(why) | PairError::Store(why) => write!(f, "{why}"),
            PairError::Failed { status, detail } => write!(f, "the relay answered {status}{detail}"),
        }
    }
}

impl std::error::Error for PairError {}

#[derive(Deserialize)]
struct PairAnswer {
    name: String,
    node_token: String,
    connect_token: String,
    stop_token: String,
    /// Milliseconds since the epoch.
    expires: i64,
}

/// A pair from the body of a 2xx answer of `/v1/pair`: the name as T-076
/// checks names, each token's shape, and at least 10 minutes left.
pub fn parse(relay: &Relay, body: &[u8], now_ms: i64) -> Result<Pair, PairError> {
    let answer: PairAnswer = serde_json::from_slice(body).map_err(|_| PairError::BadAnswer("not the expected JSON"))?;
    let PairAnswer { name, node_token, connect_token, stop_token, expires } = answer;
    let (node_token, connect_token, stop_token) =
        (Zeroizing::new(node_token), Zeroizing::new(connect_token), Zeroizing::new(stop_token));
    check_node_name(&name).map_err(|_| PairError::BadAnswer("the name could change the relay path"))?;
    if ![&node_token, &connect_token, &stop_token].iter().all(|t| valid_token(t)) {
        return Err(PairError::BadAnswer("a token does not have the shape of a token"));
    }
    let left_ms = expires.saturating_sub(now_ms);
    if left_ms < MIN_REMAINING_MS {
        return Err(PairError::ShortLived { left_ms });
    }
    Ok(Pair { relay: relay.clone(), name, node_token, connect_token, stop_token, expires_ms: expires })
}

/// `POST /v1/pair` with `{}`. A `409` means "pair again", which is done once.
pub async fn create(ctx: &PairContext<'_>) -> Result<Pair, PairError> {
    for _ in 0..2 {
        let response = podssh_ws::client::https_post_json(
            &ctx.relay.host,
            ctx.relay.port,
            "/v1/pair",
            b"{}",
            ctx.trust,
            ctx.proxy,
            ctx.timeout,
        )
        .await
        .map_err(PairError::Connect)?;
        match response.status {
            200..=299 => return parse(ctx.relay, &response.body, now_ms()),
            409 => continue,
            status => return Err(refused(status, &response)),
        }
    }
    Err(PairError::Failed { status: 409, detail: ": the relay asked twice to pair again".into() })
}

/// Whether the pair's node is online, and its sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Presence {
    pub online: bool,
    pub sessions: u64,
}

/// `GET /v1/status/<name>`, with `connect_token`: the one token that the relay
/// accepts there (measured 2026-10-09; the other two get `403`).
pub async fn status(ctx: &PairContext<'_>, pair: &Pair) -> Result<Presence, PairError> {
    let path = format!("/v1/status/{}", checked(&pair.name)?);
    let response = with_token(ctx, "GET", &path, pair.connect_token()).await?;
    match response.status {
        200..=299 => serde_json::from_slice(&response.body).map_err(|_| PairError::BadAnswer("not the expected status")),
        status => Err(refused(status, &response)),
    }
}

/// What `/v1/stop/<name>` answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Stopped {
    /// `false` when no node was online; the credentials end either way.
    pub stopped: bool,
    pub sessions: u64,
}

/// `POST /v1/stop/<name>` with `stop_token`. The relay ends the pair's
/// credentials whatever it answers (`{"stopped": false}` was seen to end
/// them), so a caller forgets its copies whatever the result: see [`revoke`].
pub async fn stop(ctx: &PairContext<'_>, pair: &Pair) -> Result<Stopped, PairError> {
    let path = format!("/v1/stop/{}", checked(&pair.name)?);
    let response = with_token(ctx, "POST", &path, pair.stop_token()).await?;
    match response.status {
        200..=299 => serde_json::from_slice(&response.body).map_err(|_| PairError::BadAnswer("not the expected answer to stop")),
        status => Err(refused(status, &response)),
    }
}

/// Stop the pair stored under `label`, and delete the local copy whatever the
/// relay answered. When the relay could not be reached, it answered nothing:
/// the copy is kept, because its `stop_token` is the only way to stop the
/// pair before it expires.
pub async fn revoke(ctx: &PairContext<'_>, label: &str) -> Result<Stopped, PairError> {
    let pair = load(label)?.ok_or_else(|| PairError::BadLabel(format!("no pair is stored under {label:?}")))?;
    let result = stop(ctx, &pair).await;
    if !matches!(result, Err(PairError::Connect(_))) {
        remove(label)?;
    }
    result
}

async fn with_token(
    ctx: &PairContext<'_>,
    method: &str,
    path: &str,
    token: &str,
) -> Result<podssh_ws::http::Response, PairError> {
    podssh_ws::client::https_with_token(
        method,
        &ctx.relay.host,
        ctx.relay.port,
        path,
        b"{}",
        token,
        16 * 1024,
        ctx.trust,
        ctx.proxy,
        ctx.timeout,
    )
    .await
    .map_err(PairError::Connect)
}

/// An answer that is not a 2xx. Its body is quoted (it holds no token), safe
/// to print and short.
fn refused(status: u16, response: &podssh_ws::http::Response) -> PairError {
    match status {
        403 => PairError::Forbidden,
        429 => PairError::RateLimited { retry_after: response.header("retry-after").map(str::to_string) },
        503 => {
            let body = response.body_text(200);
            PairError::NotIssued { detail: if body.is_empty() { String::new() } else { format!(": {body}") } }
        }
        _ => {
            let body = response.body_text(200);
            PairError::Failed { status, detail: if body.is_empty() { String::new() } else { format!(": {body}") } }
        }
    }
}

fn checked(name: &str) -> Result<&str, PairError> {
    check_node_name(name).map(|()| name).map_err(PairError::BadLabel)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A pair as it is written: borrowed, so the tokens are not copied.
#[derive(Serialize)]
struct StoredRef<'a> {
    relay: String,
    name: &'a str,
    node_token: &'a str,
    connect_token: &'a str,
    stop_token: &'a str,
    expires: i64,
}

/// A pair as it is read; its tokens go into `Zeroizing` at once.
#[derive(Deserialize)]
struct Stored {
    relay: String,
    name: String,
    node_token: String,
    connect_token: String,
    stop_token: String,
    expires: i64,
}

/// The operator's part of a pair: what an operator needs to connect, and no
/// token of the node's or of the stop.
#[derive(Serialize)]
struct OperatorPart<'a> {
    relay: String,
    name: &'a str,
    connect_token: &'a str,
    expires: i64,
}

/// `pair-<label>.json`. A label is the user's name for a pair (T-083); it must
/// be a name that T-076 accepts, so it cannot leave the cache directory.
pub fn file_name(label: &str) -> Result<String, PairError> {
    check_node_name(label).map_err(|why| PairError::BadLabel(format!("the label {why}")))?;
    Ok(format!("pair-{label}.json"))
}

/// Keep `pair` under `label`, in the first cache directory that takes a
/// private file.
pub fn store(label: &str, pair: &Pair) -> Result<PathBuf, PairError> {
    store_in_first(&cache::candidate_dirs(), label, pair)
}

/// [`store`] over explicit directories (for tests).
pub fn store_in_first(dirs: &[PathBuf], label: &str, pair: &Pair) -> Result<PathBuf, PairError> {
    let name = file_name(label)?;
    let stored = StoredRef {
        relay: relay_name(&pair.relay),
        name: &pair.name,
        node_token: pair.node_token(),
        connect_token: pair.connect_token(),
        stop_token: pair.stop_token(),
        expires: pair.expires_ms,
    };
    let body = Zeroizing::new(serde_json::to_vec(&stored).map_err(|e| PairError::Store(e.to_string()))?);
    cache::store_file_in_first(dirs, &name, &body).map_err(PairError::Store)
}

/// The pair kept under `label`, if any. Its expiry is not checked here: a
/// caller says so with the remedy.
pub fn load(label: &str) -> Result<Option<Pair>, PairError> {
    load_from(&cache::candidate_dirs(), label)
}

/// [`load`] over explicit directories (for tests).
pub fn load_from(dirs: &[PathBuf], label: &str) -> Result<Option<Pair>, PairError> {
    let Some(text) = cache::load_file_from(dirs, &file_name(label)?) else { return Ok(None) };
    parse_stored(&Zeroizing::new(text), &format!("the pair stored under {label:?}")).map(Some)
}

/// A pair from a file of the store's form, as a user names one: a regular
/// file of this user that nobody else can read (`podssh node --pair-file`).
pub fn read_file(path: &Path) -> Result<Pair, PairError> {
    let text = Zeroizing::new(cache::read_private(path).map_err(PairError::Store)?);
    parse_stored(&text, &format!("the pair in {}", path.display()))
}

/// A pair as the store writes it; `what` names it in an error, with no token.
fn parse_stored(text: &str, what: &str) -> Result<Pair, PairError> {
    let stored: Stored = serde_json::from_str(text).map_err(|_| {
        // The operator's part has the connect token alone: a node needs the
        // whole pair.
        let operator_part = serde_json::from_str::<serde_json::Value>(text)
            .is_ok_and(|v| v.get("connect_token").is_some() && v.get("node_token").is_none());
        PairError::Store(if operator_part {
            format!("{what} is the operator's part of a pair, with no node token")
        } else {
            format!("{what} is not readable")
        })
    })?;
    let Stored { relay, name, node_token, connect_token, stop_token, expires } = stored;
    let (node_token, connect_token, stop_token) =
        (Zeroizing::new(node_token), Zeroizing::new(connect_token), Zeroizing::new(stop_token));
    let relay = parse_relay(&relay).map_err(|_| PairError::Store(format!("{what} names no relay")))?;
    Ok(Pair { relay, name, node_token, connect_token, stop_token, expires_ms: expires })
}

/// The labels of the pairs in the store, sorted.
pub fn labels() -> Vec<String> {
    labels_from(&cache::candidate_dirs())
}

/// [`labels`] over explicit directories (for tests).
pub fn labels_from(dirs: &[PathBuf]) -> Vec<String> {
    cache::names_from(dirs, "pair-", ".json")
        .into_iter()
        .filter_map(|name| Some(name.strip_prefix("pair-")?.strip_suffix(".json")?.to_string()))
        .filter(|label| file_name(label).is_ok())
        .collect()
}

/// Forget the pair kept under `label`, in each directory where it is ours.
pub fn remove(label: &str) -> Result<(), PairError> {
    remove_from(&cache::candidate_dirs(), label)
}

/// [`remove`] over explicit directories (for tests).
pub fn remove_from(dirs: &[PathBuf], label: &str) -> Result<(), PairError> {
    cache::remove_named_from(dirs, &file_name(label)?);
    Ok(())
}

/// Write the operator's part of `pair` to `path`, a new file that only its
/// owner can read (mode 0600). An existing file is never replaced.
pub fn write_operator_file(path: &Path, pair: &Pair) -> std::io::Result<()> {
    let part = OperatorPart {
        relay: relay_name(&pair.relay),
        name: &pair.name,
        connect_token: pair.connect_token(),
        expires: pair.expires_ms,
    };
    let body = Zeroizing::new(serde_json::to_vec_pretty(&part).map_err(std::io::Error::other)?);
    let mut file = cache::create_new_private(path)?;
    std::io::Write::write_all(&mut file, &body)?;
    file.sync_all()
}
