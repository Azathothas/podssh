//! The request for a quick tunnel (T-300): `POST
//! https://api.trycloudflare.com/tunnel` with an empty body, as cloudflared
//! 2026.10.6 sends it (`cmd/cloudflared/tunnel/quick_tunnel.go`), but
//! through `HTTPS_PROXY` when it is set, with podssh's TLS (measured, T-299:
//! the API took the request through a CONNECT proxy, with a User-Agent that
//! was not cloudflared's). The reply names the tunnel and gives its
//! credentials; the secret stays in memory that is wiped, and is never
//! shown, as a token is not.
//!
//! A refusal for now, 429 or a 5xx, is asked again for up to [`BUDGET`],
//! after the API's `Retry-After` or the relay's backoff (T-401), where
//! cloudflared asks once: the API limits a host that made a few tunnels
//! (429, "error code: 1015", and a Retry-After of 1542 to 2994 s, which
//! cfrs's testers met: Azathothas/cfrs GitHub #42 and #57). A wait past the
//! budget ends the request at once, and says until when. Each text of the
//! API reaches a line through `one_line`, with no control character.

use std::borrow::Cow;
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use podssh_ws::text::one_line;
use serde::Deserialize;
use zeroize::Zeroizing;

pub const HOST: &str = "api.trycloudflare.com";
pub const PATH: &str = "/tunnel";
/// cloudflared waits 15 s for the reply.
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// How long refusals for now are asked again: past it, a later run does
/// better than a node that waits and serves nothing.
pub const BUDGET: Duration = Duration::from_secs(300);
/// The shortest wait between two requests, whatever the API asks.
pub const LEAST_WAIT: Duration = Duration::from_secs(1);
/// The most characters of the API's text that a line shows.
const SHOWN: usize = 200;

/// A quick tunnel: its name and its credentials.
pub struct Tunnel {
    pub id: [u8; 16],
    /// `NAME.trycloudflare.com`.
    pub hostname: String,
    pub account_tag: String,
    pub secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel").field("hostname", &self.hostname).field("secret", &"(not shown)").finish()
    }
}

/// Why no tunnel came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The API answered with this status, and this text.
    Status { status: u16, detail: String },
    /// The API named its errors.
    Errors(String),
    /// The reply did not read as a tunnel.
    Malformed(&'static str),
}

impl Refused {
    /// Whether a later request may get a tunnel: 429 (RFC 6585, section 4)
    /// and each 5xx say "not now"; any other answer says "not so".
    pub fn for_now(&self) -> bool {
        matches!(self, Refused::Status { status, .. } if *status == 429 || (500..600).contains(status))
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Status { status, detail } => write!(f, "{HOST} answered {status}{detail}"),
            Refused::Errors(errors) => write!(f, "{HOST} made no tunnel: {errors}"),
            Refused::Malformed(why) => write!(f, "{HOST} gave a reply that is not a tunnel: {why}"),
        }
    }
}

/// Why the requests gave no tunnel, by what a later run can do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// The API refuses for now, past the budget: a later run can get one.
    ForNow(String),
    /// A later request gets the same: the API's answer, or no way to it.
    Refused(String),
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failed::ForNow(why) | Failed::Refused(why) => f.write_str(why),
        }
    }
}

#[derive(Deserialize)]
struct Reply<'a> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    #[serde(borrow)]
    result: Option<Created<'a>>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Created<'a> {
    #[serde(borrow)]
    id: Cow<'a, str>,
    #[serde(borrow)]
    hostname: Cow<'a, str>,
    #[serde(borrow)]
    account_tag: Cow<'a, str>,
    #[serde(borrow)]
    secret: Cow<'a, str>,
}

/// The API's text as a line shows it: no control character, one line, cut.
fn shown(text: &str) -> String {
    one_line(text).chars().take(SHOWN).collect()
}

/// The tunnel in the reply of `status` with `body`. The body of a reply
/// that succeeded is never quoted: it holds the secret.
pub fn read_reply(status: u16, body: &[u8]) -> Result<Tunnel, Refused> {
    if !(200..300).contains(&status) {
        let text = shown(&String::from_utf8_lossy(body));
        return Err(Refused::Status {
            status,
            detail: if text.is_empty() { String::new() } else { format!(": {text}") },
        });
    }
    let reply: Reply<'_> = serde_json::from_slice(body).map_err(|_| Refused::Malformed("not the expected JSON"))?;
    if !reply.errors.is_empty() {
        let errors: Vec<String> =
            reply.errors.iter().map(|e| format!("[{}] {}", e.code, one_line(&e.message))).collect();
        return Err(Refused::Errors(shown(&errors.join("; "))));
    }
    let created = match (reply.success, reply.result) {
        (true, Some(created)) => created,
        _ => return Err(Refused::Errors("the reply did not say success".into())),
    };
    let id = uuid_bytes(&created.id).ok_or(Refused::Malformed("an id that is not a UUID"))?;
    let hostname = created.hostname.to_ascii_lowercase();
    let label =
        hostname.strip_suffix(".trycloudflare.com").ok_or(Refused::Malformed("a name not under trycloudflare.com"))?;
    if label.is_empty() || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(Refused::Malformed("a name that is not one label"));
    }
    let secret = Zeroizing::new(
        STANDARD.decode(created.secret.as_bytes()).map_err(|_| Refused::Malformed("a secret that is not base64"))?,
    );
    if secret.is_empty() || created.account_tag.is_empty() {
        return Err(Refused::Malformed("no credentials"));
    }
    Ok(Tunnel { id, hostname, account_tag: created.account_tag.into_owned(), secret })
}

/// The 16 bytes of a UUID written with its hyphens.
pub fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
    if text.len() != 36 || hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (k, pair) in hex.chunks(2).enumerate() {
        out[k] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The wait that a `Retry-After` of `value` asks for, with the clock at
/// `now` (seconds since the Unix epoch): seconds, or an HTTP date (RFC 9110,
/// section 10.2.3). `None` for a value that is neither: the backoff then
/// stands for it.
pub fn retry_after(value: &str, now: i64) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        // More seconds than a u64 holds is a wait past any budget.
        return Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)));
    }
    let at = podssh_ws::clock::parse_http_date(value)?;
    Some(Duration::from_secs(at.saturating_sub(now).max(0) as u64))
}

/// What follows a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Then {
    /// Ask again after this wait.
    Again(Duration),
    /// Stop, for this reason.
    Stop(Failed),
}

/// After `refused`, whose `Retry-After` was `retry`, at the `attempt`-th
/// request (the first is 1), with `left` of the budget and the clock at
/// `now`: ask again, or stop.
pub fn then(refused: &Refused, retry: Option<&str>, attempt: u32, left: Duration, now: i64) -> Then {
    if !refused.for_now() {
        return Then::Stop(Failed::Refused(refused.to_string()));
    }
    let asked = retry.and_then(|value| retry_after(value, now));
    if let Some(wait) = asked.filter(|wait| *wait > left) {
        let secs = wait.as_secs();
        let until = podssh_ws::clock::http_date(now.saturating_add(i64::try_from(secs).unwrap_or(i64::MAX)));
        let why = format!("{refused}; it asks to wait {secs} s, until {until}");
        let why = format!("{why}, past the {} s that podssh asks again for: run again then", BUDGET.as_secs());
        return Then::Stop(Failed::ForNow(why));
    }
    if left.is_zero() {
        let why = format!("{refused}; still refused after {} s of requests: run again later", BUDGET.as_secs());
        return Then::Stop(Failed::ForNow(why));
    }
    let wait = asked.unwrap_or_else(|| crate::open::backoff(attempt).min(left));
    Then::Again(wait.max(LEAST_WAIT))
}

/// Ask for a tunnel with `post`, one request a call; after a refusal for
/// now, ask again as [`then`] says, with a line to `say` before each wait.
/// `now` reads the clock, in seconds since the Unix epoch, for a
/// Retry-After that is a date. A request that fails before an answer is
/// not asked again: a proxy's refusal or a TLS failure comes again.
pub async fn ask<P, F>(mut post: P, say: &dyn Fn(String), now: impl Fn() -> i64) -> Result<Tunnel, Failed>
where
    P: FnMut() -> F,
    F: Future<Output = Result<podssh_ws::http::Response, String>>,
{
    let started = tokio::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt = attempt.saturating_add(1);
        let response = post().await.map_err(Failed::Refused)?;
        let retry = response.header("retry-after").map(one_line);
        let status = response.status;
        // The reply holds the secret: its bytes are wiped once read.
        let body = Zeroizing::new(response.body);
        let refused = match read_reply(status, &body) {
            Ok(tunnel) => return Ok(tunnel),
            Err(refused) => refused,
        };
        let left = BUDGET.saturating_sub(started.elapsed());
        match then(&refused, retry.as_deref(), attempt, left, now()) {
            Then::Again(wait) => {
                say(format!("{refused}; asking again in {} s", wait.as_secs().max(1)));
                tokio::time::sleep(wait).await;
            }
            Then::Stop(failed) => return Err(failed),
        }
    }
}

/// Ask for a tunnel, through `proxy` when there is one, with `trust`, as
/// [`ask`] does, with this host's clock.
pub async fn request(
    trust: &podssh_ws::Trust,
    proxy: &podssh_ws::ProxyChoice,
    say: &dyn Fn(String),
) -> Result<Tunnel, Failed> {
    let post = move || async move {
        podssh_ws::client::https_post_json(HOST, 443, PATH, b"", trust, proxy, TIMEOUT)
            .await
            .map_err(|e| format!("the request for a quick tunnel to {HOST} failed: {e}"))
    };
    ask(post, say, unix_now).await
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
