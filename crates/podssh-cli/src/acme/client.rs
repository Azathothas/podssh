//! ACME's requests (RFC 8555, sections 6 and 7): each one a connection of
//! its own through HTTPS_PROXY, with the TLS of podssh-ws, as `podssh update`
//! fetches a file; a JWS POST with the nonce of the last answer, sent again
//! with a new one when the CA says `badNonce`, as RFC 8555, section 6.5, asks;
//! and a problem document said in one line.

use std::time::Duration;

use podssh_ws::client::open_tls;
use podssh_ws::http::{self, Response};
use podssh_ws::{ProxyChoice, Trust};
use serde_json::{json, Value};

use super::jws::Account;
use crate::update::fetch::Url;

/// The type of each JWS POST (RFC 8555, section 6.2).
const JOSE: &str = "application/jose+json";
/// The type of a chain of certificates (RFC 8555, section 9.1).
pub const PEM_CHAIN: &str = "application/pem-certificate-chain";
/// The largest answer: a directory, an order, a chain.
const MAX_ANSWER: usize = 256 << 10;
/// A nonce refused this many times in a row ends the request. Pebble refuses
/// 5 % of good ones on purpose, and its test runs 15 %.
const BAD_NONCE_TRIES: usize = 8;
const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";

/// An answer of the CA, or why none came.
pub type Answer = Result<Response, String>;

/// How the CA is reached.
#[derive(Debug, Clone)]
pub struct Http {
    pub trust: Trust,
    pub proxy: ProxyChoice,
    /// The limit of the connection and of each answer.
    pub timeout: Duration,
}

impl Http {
    /// One request to `url`, on a connection of its own.
    pub async fn send(&self, method: &str, url: &str, jose: bool, accept: &str, body: &[u8]) -> Answer {
        let u = Url::parse(url).map_err(|why| format!("{url}: {why}"))?;
        let shown = u.shown();
        let mut tls = open_tls(&u.host, u.port, &u.host, &self.trust, &self.proxy, self.timeout)
            .await
            .map_err(|e| format!("{shown}: {e}"))?;
        let host = match u.port {
            443 => u.host.clone(),
            port => podssh_ws::dial::authority(&u.host, port),
        };
        let mut headers = vec![("Accept", accept)];
        if jose {
            headers.push(("Content-Type", JOSE));
        }
        let exchange = http::exchange(&mut tls, method, &host, &u.path, &headers, body, MAX_ANSWER);
        match tokio::time::timeout(self.timeout, exchange).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(format!("{shown}: {e}")),
            Err(_) => Err(format!("{shown}: no answer within {} s", self.timeout.as_secs())),
        }
    }
}

/// The URLs of a CA's directory (RFC 8555, section 7.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    /// The CA's terms, which a new account agrees to.
    pub terms: Option<String>,
}

impl Directory {
    pub fn parse(body: &[u8]) -> Result<Directory, String> {
        let v: Value = serde_json::from_slice(body).map_err(|e| format!("the directory is not JSON: {e}"))?;
        let url = |key: &str| v[key].as_str().map(str::to_string).ok_or_else(|| format!("the directory has no {key}"));
        if v["meta"]["externalAccountRequired"].as_bool() == Some(true) {
            return Err("the CA asks for an external account binding, which podssh does not give".into());
        }
        let terms = v["meta"]["termsOfService"].as_str().map(str::to_string);
        let (new_nonce, new_account, new_order) = (url("newNonce")?, url("newAccount")?, url("newOrder")?);
        Ok(Directory { new_nonce, new_account, new_order, terms })
    }
}

/// An account at a CA, and the nonce for its next request.
pub struct Client {
    pub http: Http,
    pub directory: Directory,
    key: Account,
    /// The account's URL, once newAccount gave it.
    kid: Option<String>,
    nonce: Option<String>,
}

impl Client {
    /// Read the directory at `url`.
    pub async fn open(http: Http, url: &str, key: Account) -> Result<Client, String> {
        let answer = http.send("GET", url, false, "application/json", b"").await?;
        if answer.status != 200 {
            return Err(format!("the directory {url}: {}", problem(&answer)));
        }
        let directory = Directory::parse(&answer.body)?;
        Ok(Client { http, directory, key, kid: None, nonce: None })
    }

    pub fn key(&self) -> &Account {
        &self.key
    }

    /// The account of the key: made on its first use, else found by it
    /// (RFC 8555, section 7.3). True when the CA made it now.
    pub async fn account(&mut self) -> Result<bool, String> {
        let url = self.directory.new_account.clone();
        let answer = self.post(&url, Some(&json!({"termsOfServiceAgreed": true})), "application/json").await?;
        let made = match answer.status {
            201 => true,
            200 => false,
            _ => return Err(format!("the account: {}", problem(&answer))),
        };
        let kid = answer.header("location").ok_or("the CA gave the account no Location")?;
        self.kid = Some(kid.to_string());
        Ok(made)
    }

    /// A JWS POST of `payload` to `url`, or a POST-as-GET with `None`.
    pub async fn post(&mut self, url: &str, payload: Option<&Value>, accept: &str) -> Answer {
        for _ in 0..BAD_NONCE_TRIES {
            let nonce = self.nonce().await?;
            let body = self.key.sign(self.kid.as_deref(), &nonce, url, payload)?;
            let answer = self.http.send("POST", url, true, accept, body.as_bytes()).await?;
            self.nonce = replay_nonce(&answer);
            if answer.status == 400 && problem_type(&answer).as_deref() == Some(BAD_NONCE) {
                continue;
            }
            return Ok(answer);
        }
        Err(format!("the CA refused {BAD_NONCE_TRIES} nonces in a row (badNonce)"))
    }

    /// The JSON of a POST-as-GET of `url` (an order, an authorization).
    pub async fn get_json(&mut self, url: &str) -> Result<(Value, Response), String> {
        let answer = self.post(url, None, "application/json").await?;
        Ok((json_of(&answer)?, answer))
    }

    /// The nonce of the last answer, else a new one (RFC 8555, section 7.2).
    async fn nonce(&mut self) -> Result<String, String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }
        let answer = self.http.send("GET", &self.directory.new_nonce, false, "*/*", b"").await?;
        replay_nonce(&answer).ok_or_else(|| format!("newNonce gave no Replay-Nonce (HTTP {})", answer.status))
    }
}

/// The `Replay-Nonce` of an answer, when it has the shape of one: base64url
/// alone (RFC 8555, section 6.5.1), as it goes into a header of JSON.
fn replay_nonce(answer: &Response) -> Option<String> {
    let nonce = answer.header("replay-nonce")?;
    let ok = !nonce.is_empty() && nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then(|| nonce.to_string())
}

/// The JSON of an answer of 200 or 201, else the CA's problem.
pub fn json_of(answer: &Response) -> Result<Value, String> {
    if !matches!(answer.status, 200 | 201) {
        return Err(problem(answer));
    }
    serde_json::from_slice(&answer.body).map_err(|e| format!("the CA's answer is not JSON: {e}"))
}

fn problem_type(answer: &Response) -> Option<String> {
    let v: Value = serde_json::from_slice(&answer.body).ok()?;
    v["type"].as_str().map(str::to_string)
}

/// A problem document (RFC 7807) in one line: its type, past the prefix of
/// ACME's, its detail, and the first of its subproblems. The text is the
/// CA's, made safe for a terminal.
pub fn problem(answer: &Response) -> String {
    let Ok(v) = serde_json::from_slice::<Value>(&answer.body) else {
        return format!("HTTP {} {}: {}", answer.status, answer.reason, answer.body_text(160));
    };
    let mut text = describe(&v);
    if text.is_empty() {
        text = format!("HTTP {} {}", answer.status, answer.reason);
    }
    cut(podssh_ws::text::one_line(&text), 400)
}

/// The type and detail of a problem, and of up to three subproblems.
pub fn describe(v: &Value) -> String {
    let kind = v["type"].as_str().map(|t| t.trim_start_matches("urn:ietf:params:acme:error:"));
    let mut text = match (kind, v["detail"].as_str()) {
        (Some(kind), Some(detail)) => format!("{kind}: {detail}"),
        (Some(kind), None) => kind.to_string(),
        (None, Some(detail)) => detail.to_string(),
        (None, None) => String::new(),
    };
    for sub in v["subproblems"].as_array().into_iter().flatten().take(3) {
        text.push_str(&format!("; {}", describe(sub)));
    }
    text
}

fn cut(text: String, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text,
    }
}

/// How long to wait before asking again: the answer's Retry-After, in
/// seconds or as a date, from 1 to 10 s; else 2 s.
pub fn retry_after(answer: &Response, now_secs: i64) -> Duration {
    let asked = answer.header("retry-after").and_then(|v| seconds_of(v.trim(), now_secs));
    Duration::from_secs(asked.unwrap_or(2).clamp(1, 10))
}

/// Retry-After's seconds, or the seconds until its date (RFC 9110).
fn seconds_of(value: &str, now_secs: i64) -> Option<u64> {
    if let Ok(secs) = value.parse::<u64>() {
        return Some(secs);
    }
    let at = podssh_ws::clock::parse_http_date(value)?;
    Some(u64::try_from(at.saturating_sub(now_secs)).unwrap_or(0))
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
