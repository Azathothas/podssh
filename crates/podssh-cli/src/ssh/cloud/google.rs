//! The OAuth token of GCP's IAP (T-351), from a file that the user names,
//! private as a pair file is: in `PODSSH_IAP_TOKEN_FILE`, else in Google's
//! own `GOOGLE_APPLICATION_CREDENTIALS`. The file holds one of:
//!
//! - a token, as `gcloud auth print-access-token` prints it; read again
//!   for each link, so that a token written there later serves a new link;
//! - the JSON key of a service account (`gcloud iam service-accounts keys
//!   create`): podssh signs a JWT with its key, RS256 through aws-lc-rs in
//!   the binary, and asks Google's token endpoint for a token with it, as
//!   Google's documents give the flow (RFC 7523);
//! - a user's credentials of `gcloud auth application-default login`
//!   (`authorized_user`): the refresh token gets a token.
//!
//! A token goes in the upgrade's header alone, and lives in memory that is
//! wiped. A token that Google gave serves each link until five minutes
//! before its end. The token endpoint is reached as the tunnel is, through
//! the proxy, and is the one host besides IAP that a key's flow talks to.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::signature::RSA_PKCS1_SHA256;
use base64::Engine as _;
use podssh_ws::{ProxyChoice, Trust};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

/// The file of a token or of a key, which the user names.
pub const TOKEN_FILE_ENV: &str = "PODSSH_IAP_TOKEN_FILE";
/// Google's own variable for the file of a key.
pub const GOOGLE_ENV: &str = "GOOGLE_APPLICATION_CREDENTIALS";
/// Google's token endpoint: a key's flow talks to it and to no other host.
pub const TOKEN_HOST: &str = "oauth2.googleapis.com";
pub const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const TOKEN_PATH: &str = "/token";
/// The scope of gcloud's own tokens, which IAP takes.
pub const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// A JWT's life: Google takes one of an hour at most.
const JWT_LIFE: u64 = 3600;
/// A token with less than this left is not used for a new link.
const MARGIN: Duration = Duration::from_secs(300);
/// The longest answer of the token endpoint.
const MAX_ANSWER: usize = 64 * 1024;

/// Why no token came, and so the code of a command that says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenFault {
    /// The file, or the variable that names it (78).
    Config(String),
    /// Google refused the key or the refresh token (77).
    Refused(String),
    /// Google's token endpoint did not answer (69).
    Unreachable(String),
}

/// Where the tokens come from.
enum Source {
    /// A token in a file.
    File(PathBuf),
    /// A key of a service account.
    ServiceAccount { email: String, key_id: Option<String>, key: KeyPair },
    /// A user's refresh token.
    User { client_id: String, client_secret: Zeroizing<String>, refresh_token: Zeroizing<String> },
}

/// The token of each link of a session.
pub struct Tokens {
    source: Source,
    /// The variable and the file, for the messages: no secret.
    named: String,
    trust: Trust,
    /// A token that Google gave, and when it ends.
    cached: Mutex<Option<(Zeroizing<String>, Instant)>>,
}

impl Tokens {
    /// The source that the environment names.
    pub fn from_env(trust: Trust) -> Result<Tokens, TokenFault> {
        Tokens::from_vars(&|name| std::env::var(name).ok(), trust)
    }

    /// The source that `read` gives the variables of: the file of
    /// `PODSSH_IAP_TOKEN_FILE`, else of `GOOGLE_APPLICATION_CREDENTIALS`.
    pub fn from_vars(read: &dyn Fn(&str) -> Option<String>, trust: Trust) -> Result<Tokens, TokenFault> {
        let found = [TOKEN_FILE_ENV, GOOGLE_ENV]
            .into_iter()
            .find_map(|var| read(var).map(|p| (var, p.trim().to_string())).filter(|(_, p)| !p.is_empty()));
        let Some((var, path)) = found else {
            return Err(TokenFault::Config(format!(
                "IAP needs a token: name its file in {TOKEN_FILE_ENV} (a token of gcloud auth print-access-token, \
                 or the key of a service account), or a key's file in {GOOGLE_ENV}"
            )));
        };
        let named = format!("{var}: {path}");
        let text = Zeroizing::new(
            podssh_relay::cache::read_private(Path::new(&path))
                .map_err(|why| TokenFault::Config(format!("{var}: {why}")))?,
        );
        let source = parse(&text, PathBuf::from(&path)).map_err(|why| TokenFault::Config(format!("{named}: {why}")))?;
        Ok(Tokens { source, named, trust, cached: Mutex::new(None) })
    }

    /// A token for a new link: the file's, or one of Google's with at least
    /// five minutes left.
    pub async fn token(&self) -> Result<Zeroizing<String>, TokenFault> {
        if let Source::File(path) = &self.source {
            return self.read_file(path);
        }
        if let Some(token) = self.cached_token() {
            return Ok(token);
        }
        let (token, life) = self.ask().await?;
        let until = Instant::now() + life;
        *self.cached.lock().unwrap_or_else(PoisonError::into_inner) = Some((token.clone(), until));
        Ok(token)
    }

    fn cached_token(&self) -> Option<Zeroizing<String>> {
        let cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        cached.as_ref().filter(|(_, until)| Instant::now() + MARGIN < *until).map(|(token, _)| token.clone())
    }

    fn read_file(&self, path: &Path) -> Result<Zeroizing<String>, TokenFault> {
        let read = podssh_relay::cache::read_private(path);
        let text = Zeroizing::new(read.map_err(|why| TokenFault::Config(format!("{}: {why}", self.named)))?);
        let token = text.trim();
        podssh_ws::iap::check_token(token).map_err(|why| TokenFault::Config(format!("{}: {why}", self.named)))?;
        Ok(Zeroizing::new(token.to_string()))
    }

    /// A token from Google's token endpoint, and its life.
    async fn ask(&self) -> Result<(Zeroizing<String>, Duration), TokenFault> {
        let body = match &self.source {
            Source::ServiceAccount { email, key_id, key } => {
                let jwt = assertion(email, key_id.as_deref(), key, unix_now()).map_err(TokenFault::Config)?;
                let mut body = Zeroizing::new(String::with_capacity(96 + jwt.len()));
                body.push_str("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=");
                body.push_str(&jwt);
                body
            }
            Source::User { client_id, client_secret, refresh_token } => {
                let (id, secret, refresh) = (form(client_id), form(client_secret), form(refresh_token));
                let mut body = Zeroizing::new(String::with_capacity(96 + id.len() + secret.len() + refresh.len()));
                body.push_str("grant_type=refresh_token&client_id=");
                body.push_str(&id);
                body.push_str("&client_secret=");
                body.push_str(&secret);
                body.push_str("&refresh_token=");
                body.push_str(&refresh);
                body
            }
            Source::File(_) => return Err(TokenFault::Config("a token of a file is not asked for".into())),
        };
        let answer = exchange(&body, &self.trust).await?;
        let key = matches!(self.source, Source::ServiceAccount { .. });
        read_answer(answer, key).map_err(|fault| match fault {
            TokenFault::Refused(why) => TokenFault::Refused(format!("{}: {why}", self.named)),
            other => other,
        })
    }
}

/// The source in the text of a file.
fn parse(text: &str, path: PathBuf) -> Result<Source, String> {
    let trimmed = text.trim();
    if !trimmed.starts_with('{') {
        podssh_ws::iap::check_token(trimmed)?;
        return Ok(Source::File(path));
    }
    // serde_json's message gives a line and a column, never the text.
    let mut json: Value = serde_json::from_str(trimmed).map_err(|e| format!("it is not a token, nor JSON: {e}"))?;
    match json.get("type").and_then(Value::as_str) {
        Some("service_account") => service_account(&mut json),
        Some("authorized_user") => authorized_user(&mut json),
        Some(other) => {
            let other = podssh_ws::text::one_line(other);
            Err(format!("a key of type {other:?}: podssh takes service_account and authorized_user"))
        }
        None => Err("its JSON has no type: podssh takes a key of service_account or authorized_user".into()),
    }
}

fn service_account(json: &mut Value) -> Result<Source, String> {
    let email = text_of(json, "client_email")?;
    if let Some(uri) = json.get("token_uri").and_then(Value::as_str) {
        if uri != TOKEN_URI {
            let uri = podssh_ws::text::one_line(uri);
            return Err(format!("its token_uri is {uri:?}: podssh asks {TOKEN_URI} alone for a token"));
        }
    }
    let key_id = json.get("private_key_id").and_then(Value::as_str).map(str::to_string);
    let pem = secret_of(json, "private_key")?;
    let der = pem_der(&pem)?;
    let key = KeyPair::from_pkcs8(&der).map_err(|e| format!("aws-lc-rs refused its private_key: {e}"))?;
    Ok(Source::ServiceAccount { email, key_id, key })
}

fn authorized_user(json: &mut Value) -> Result<Source, String> {
    let client_id = text_of(json, "client_id")?;
    let client_secret = secret_of(json, "client_secret")?;
    let refresh_token = secret_of(json, "refresh_token")?;
    Ok(Source::User { client_id, client_secret, refresh_token })
}

fn text_of(json: &Value, name: &str) -> Result<String, String> {
    let value = json.get(name).and_then(Value::as_str).filter(|s| !s.is_empty());
    value.map(str::to_string).ok_or_else(|| format!("it has no {name}"))
}

/// A secret of the JSON, taken out of it into memory that is wiped.
fn secret_of(json: &mut Value, name: &str) -> Result<Zeroizing<String>, String> {
    match json.get_mut(name).map(Value::take) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Zeroizing::new(value)),
        _ => Err(format!("it has no {name}")),
    }
}

/// The DER of a PEM's `PRIVATE KEY` (PKCS#8), as a key of Google's holds it.
fn pem_der(pem: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .and_then(|rest| rest.trim_end().strip_suffix("-----END PRIVATE KEY-----"))
        .ok_or("its private_key is not a PEM PRIVATE KEY")?;
    let mut text = Zeroizing::new(String::with_capacity(body.len()));
    text.extend(body.chars().filter(|c| !c.is_whitespace()));
    let der = base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .map_err(|_| "its private_key is not base64".to_string())?;
    Ok(Zeroizing::new(der))
}

/// The JWT of a service account's request for a token, signed RS256 with
/// aws-lc-rs at `now`, seconds since the Unix epoch: Google's claims, an
/// hour of life.
pub fn assertion(email: &str, key_id: Option<&str>, key: &KeyPair, now: u64) -> Result<Zeroizing<String>, String> {
    let mut header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    if let Some(id) = key_id {
        header["kid"] = Value::from(id);
    }
    let claims = serde_json::json!({
        "iss": email, "scope": SCOPE, "aud": TOKEN_URI, "iat": now, "exp": now + JWT_LIFE,
    });
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signing = format!("{}.{}", b64.encode(header.to_string()), b64.encode(claims.to_string()));
    let mut signature = vec![0u8; key.public_modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), signing.as_bytes(), &mut signature)
        .map_err(|_| "aws-lc-rs could not sign the JWT".to_string())?;
    Ok(Zeroizing::new(format!("{signing}.{}", b64.encode(&signature))))
}

/// `value` escaped for a form, as an OAuth request's body takes it.
fn form(value: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(value.len() * 3));
    for &b in value.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// One POST of `body` to Google's token endpoint, through the proxy, its
/// TLS checked as the tunnel's is.
async fn exchange(body: &str, trust: &Trust) -> Result<podssh_ws::http::Response, TokenFault> {
    let timeout = podssh_relay::open::CONNECT_TIMEOUT;
    let proxy = ProxyChoice::FromEnvironment;
    let unreachable = |why: String| TokenFault::Unreachable(format!("{TOKEN_HOST}: {why}"));
    let mut tls = podssh_ws::client::open_tls(TOKEN_HOST, 443, TOKEN_HOST, trust, &proxy, timeout)
        .await
        .map_err(|e| unreachable(e.to_string()))?;
    let headers = [("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json")];
    let asked =
        podssh_ws::http::exchange(&mut tls, "POST", TOKEN_HOST, TOKEN_PATH, &headers, body.as_bytes(), MAX_ANSWER);
    match tokio::time::timeout(timeout, asked).await {
        Err(_) => Err(unreachable(format!("no answer within {} s", timeout.as_secs()))),
        Ok(Err(e)) => Err(unreachable(e.to_string())),
        Ok(Ok(answer)) => Ok(answer),
    }
}

/// The token and its life in the endpoint's answer, whose body is wiped
/// after; a refusal gives Google's words, which quote no secret, and for a
/// key, this host's clock, as a JWT is checked against Google's.
pub fn read_answer(
    mut answer: podssh_ws::http::Response,
    key: bool,
) -> Result<(Zeroizing<String>, Duration), TokenFault> {
    let mut json: Value = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
    answer.body.zeroize();
    if answer.status != 200 {
        let error = json.get("error").and_then(Value::as_str).unwrap_or_default();
        let said = json.get("error_description").and_then(Value::as_str).unwrap_or_default();
        let words = podssh_ws::text::one_line(&format!("{error} {said}"));
        let mut line = format!("Google refused the request for a token (HTTP {})", answer.status);
        if !words.is_empty() {
            line.push_str(&format!(": {words}"));
        }
        if key {
            let clock = podssh_ws::clock::http_date(unix_now() as i64);
            line.push_str(&format!("; Google checks a JWT's times against its clock; this host's clock reads {clock}"));
        }
        let refused = (400..500).contains(&answer.status);
        return Err(if refused { TokenFault::Refused(line) } else { TokenFault::Unreachable(line) });
    }
    let token = match json.get_mut("access_token").map(Value::take) {
        Some(Value::String(token)) => Zeroizing::new(token),
        _ => return Err(TokenFault::Unreachable("Google's answer holds no access_token".into())),
    };
    podssh_ws::iap::check_token(&token).map_err(TokenFault::Unreachable)?;
    let life = json.get("expires_in").and_then(Value::as_u64).unwrap_or(3600);
    Ok((token, Duration::from_secs(life)))
}

#[cfg(test)]
mod tests;
