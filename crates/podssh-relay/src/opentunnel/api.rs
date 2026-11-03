//! OpenTunnel's HTTP API (anomalyco/opentunnel:docs/protocol.md at v0.6.1,
//! "HTTP API"), one request on each connection over podssh-ws's HTTP/1.1:
//! `POST /api/tunnel` makes a tunnel and gives its token once; the bind of a
//! CSR and the reads of the certificate take that token as a bearer, in a
//! header alone, which no message quotes. The retries are [`super::retry`]'s.
//! What the API answers is checked before it is used: a tunnel's id is one
//! label, and its name is that id under the service's domain, as each goes
//! into a certificate's names and a client's name.

use std::fmt;
use std::time::Duration;

use podssh_ws::http::Response;
use serde_json::Value;
use zeroize::Zeroizing;

use super::dial::Dial;
use super::retry::{self, Repeat};
use super::Service;

/// The largest answer read: a certificate and its chain fit many times.
pub const MAX_BODY: usize = 64 * 1024;
/// The bound of one request, its connection and its answer.
pub const REQUEST_LIMIT: Duration = Duration::from_secs(30);

/// A tunnel: its id, and its name, `<id>.<domain>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    pub id: String,
    pub hostname: String,
}

/// A tunnel that the API made, and its token, given once.
pub struct Created {
    pub tunnel: Tunnel,
    pub token: Zeroizing<String>,
}

impl fmt::Debug for Created {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Created").field("tunnel", &self.tunnel).finish_non_exhaustive()
    }
}

/// Where a tunnel's certificate is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cert {
    /// The service answers a challenge of the CA's.
    Challenge,
    Issuing,
    /// Issued: the leaf, its chain, as PEM, and its expiry in ISO 8601.
    Ready {
        certificate: String,
        chain: String,
        expiry: String,
    },
    /// Given up, with the service's reason.
    Failed(String),
}

/// A request that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The API answered with a refusal: its status, its tag and its message,
    /// on one line each, and the seconds of its `Retry-After`.
    Refused { status: u16, tag: String, message: String, retry_after: Option<u64> },
    /// No answer: the connection, TLS or the exchange failed, or the answer
    /// was not one of the API's.
    Unreached(String),
}

impl ApiError {
    /// The status of a refusal.
    pub fn status(&self) -> Option<u16> {
        match self {
            ApiError::Refused { status, .. } => Some(*status),
            ApiError::Unreached(_) => None,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Refused { status, tag, message, retry_after } => {
                write!(f, "OpenTunnel answered {status}")?;
                if !tag.is_empty() {
                    write!(f, " ({tag})")?;
                }
                write!(f, ": {message}")?;
                if let Some(secs) = retry_after {
                    write!(f, " (Retry-After: {secs} s)")?;
                }
                Ok(())
            }
            ApiError::Unreached(why) => f.write_str(why),
        }
    }
}

/// One try's failure: before the request left, or after.
enum Attempt {
    NotSent(String),
    Lost(String),
}

/// The API of one service.
#[derive(Clone)]
pub struct Api {
    service: Service,
    dial: Dial,
    /// The waits of the retries, divided by this: a test's are short.
    hurry: u32,
}

impl Api {
    pub fn new(service: Service, dial: Dial) -> Api {
        Api { service, dial, hurry: 1 }
    }

    /// The same, with each wait between retries divided by `factor`.
    pub fn hurried(self, factor: u32) -> Api {
        Api { hurry: factor.max(1), ..self }
    }

    pub fn service(&self) -> &Service {
        &self.service
    }

    pub fn dial(&self) -> &Dial {
        &self.dial
    }

    /// A new tunnel, and its token. Retried only where it cannot have
    /// arrived, as a second would be a second tunnel.
    pub async fn create(&self) -> Result<Created, ApiError> {
        let response = self.send(Repeat::Once, "POST", "/api/tunnel", None, b"{}").await?;
        let value = json(&response)?;
        let tunnel = tunnel(value.get("tunnel").unwrap_or(&Value::Null))?;
        let token = value.get("token").and_then(Value::as_str).unwrap_or_default();
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ApiError::Unreached("the new tunnel came with no token that a header can carry".into()));
        }
        Ok(Created { tunnel, token: Zeroizing::new(token.to_string()) })
    }

    /// Bind `csr` (PEM) to the tunnel `id`: the first time, the service
    /// orders its certificate; the CSR that the tunnel has already gets its
    /// certificate as it is, so it is retried as a read.
    pub async fn bind_csr(&self, token: &str, id: &str, csr: &str) -> Result<Cert, ApiError> {
        let body = serde_json::json!({ "csr": csr }).to_string();
        let path = format!("/api/tunnel/{}/certificate", checked_id(id)?);
        let response = self.send(Repeat::Idempotent, "POST", &path, Some(token), body.as_bytes()).await?;
        cert(&json(&response)?)
    }

    /// The tunnel's certificate now.
    pub async fn certificate(&self, token: &str, id: &str) -> Result<Cert, ApiError> {
        let path = format!("/api/tunnel/{}/certificate", checked_id(id)?);
        let response = self.send(Repeat::Idempotent, "GET", &path, Some(token), b"").await?;
        cert(&json(&response)?)
    }

    /// Whether the API's host answers `/health`, once, with no retry: the
    /// status. `doctor` reads it, and makes no tunnel.
    pub async fn health(&self) -> Result<u16, String> {
        match self.once("GET", "/health", None, b"").await {
            Ok(response) => Ok(response.status),
            Err(Attempt::NotSent(why) | Attempt::Lost(why)) => Err(why),
        }
    }

    /// One request, again after each passing failure as `repeat` allows.
    async fn send(
        &self,
        repeat: Repeat,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &[u8],
    ) -> Result<Response, ApiError> {
        let mut attempt = 0u32;
        loop {
            let retry_after = match self.once(method, path, token, body).await {
                Ok(response) if (200..300).contains(&response.status) => return Ok(response),
                Ok(response) => {
                    let after = response.header("retry-after").map(str::to_string);
                    let stop = attempt >= retry::RETRIES
                        || !retry::retryable(response.status, repeat)
                        || retry::too_long(response.status, after.as_deref());
                    if stop {
                        return Err(refusal(&response));
                    }
                    after
                }
                Err(Attempt::NotSent(why)) if attempt >= retry::RETRIES => return Err(ApiError::Unreached(why)),
                Err(Attempt::NotSent(_)) => None,
                Err(Attempt::Lost(why)) if attempt >= retry::RETRIES || repeat == Repeat::Once => {
                    return Err(ApiError::Unreached(why));
                }
                Err(Attempt::Lost(_)) => None,
            };
            tokio::time::sleep(retry::wait(attempt, retry_after.as_deref()) / self.hurry).await;
            attempt += 1;
        }
    }

    /// One try, on a connection of its own.
    async fn once(&self, method: &str, path: &str, token: Option<&str>, body: &[u8]) -> Result<Response, Attempt> {
        let shown = self.service.shown();
        let mut io = match tokio::time::timeout(REQUEST_LIMIT, (self.dial)(&self.service)).await {
            Err(_) => {
                return Err(Attempt::NotSent(format!("{shown}: no connection within {} s", REQUEST_LIMIT.as_secs())))
            }
            Ok(Err(why)) => return Err(Attempt::NotSent(why)),
            Ok(Ok(io)) => io,
        };
        let bearer = token.map(|token| Zeroizing::new(format!("Bearer {token}")));
        let mut headers = vec![("Content-Type", "application/json"), ("Accept", "application/json")];
        if let Some(bearer) = &bearer {
            headers.push(("Authorization", bearer.as_str()));
        }
        let host = self.service.authority();
        let asked = podssh_ws::http::exchange(&mut io, method, &host, path, &headers, body, MAX_BODY);
        match tokio::time::timeout(REQUEST_LIMIT, asked).await {
            Err(_) => Err(Attempt::Lost(format!("{shown}: no answer within {} s", REQUEST_LIMIT.as_secs()))),
            // The error of an exchange names no header, so never the token.
            Ok(Err(e)) => Err(Attempt::Lost(format!("{shown}: {e}"))),
            Ok(Ok(response)) => Ok(response),
        }
    }
}

/// A refusal of the API's: its error body, or its status and Cloudflare's
/// meaning of it.
fn refusal(response: &Response) -> ApiError {
    let retry_after = retry::retry_after_secs(response.header("retry-after"));
    let body = String::from_utf8_lossy(&response.body);
    let parsed: Option<Value> = serde_json::from_str(&body).ok();
    let field =
        |name: &str| parsed.as_ref().and_then(|v| v.get(name)).and_then(Value::as_str).map(podssh_ws::text::one_line);
    match (field("_tag"), field("message")) {
        (Some(tag), message) => {
            let message = message.unwrap_or_default().chars().take(300).collect();
            ApiError::Refused { status: response.status, tag, message, retry_after }
        }
        (None, _) => ApiError::Refused {
            status: response.status,
            tag: String::new(),
            message: retry::status_words(response.status, &body),
            retry_after,
        },
    }
}

fn json(response: &Response) -> Result<Value, ApiError> {
    serde_json::from_slice(&response.body)
        .map_err(|e| ApiError::Unreached(format!("OpenTunnel answered {} with no JSON: {e}", response.status)))
}

/// An id that a path can carry: one label of `[a-z0-9-]`.
fn checked_id(id: &str) -> Result<&str, ApiError> {
    if super::wire::is_route(id) && id != super::wire::ROOT_ROUTE {
        Ok(id)
    } else {
        Err(ApiError::Unreached("the tunnel's id is not one label of a-z, 0-9 and -".into()))
    }
}

/// A `TunnelInfo`: its id, one label, and its name, that label and a domain
/// of two labels or more.
fn tunnel(value: &Value) -> Result<Tunnel, ApiError> {
    let field = |name: &str| value.get(name).and_then(Value::as_str).unwrap_or_default().to_ascii_lowercase();
    let (id, hostname) = (field("id"), field("hostname"));
    checked_id(&id)?;
    let domain = hostname.strip_prefix(&format!("{id}.")).unwrap_or_default();
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|label| super::wire::is_route(label) && *label != "@") {
        return Err(ApiError::Unreached(format!(
            "the tunnel's name {:?} is not its id under a domain",
            podssh_ws::text::one_line(&hostname)
        )));
    }
    Ok(Tunnel { id, hostname })
}

/// A `CertificateInfo`'s state.
fn cert(value: &Value) -> Result<Cert, ApiError> {
    let state = value.get("state").unwrap_or(&Value::Null);
    let field = |name: &str| state.get(name).and_then(Value::as_str).map(str::to_string);
    match state.get("type").and_then(Value::as_str) {
        Some("challenge") => Ok(Cert::Challenge),
        Some("issuing") => Ok(Cert::Issuing),
        Some("ready") => match (field("certificate"), field("chain"), field("expiry")) {
            (Some(certificate), chain, Some(expiry)) => {
                Ok(Cert::Ready { certificate, chain: chain.unwrap_or_default(), expiry })
            }
            _ => Err(ApiError::Unreached("a ready certificate came with no certificate or no expiry".into())),
        },
        Some("failed") => Ok(Cert::Failed(podssh_ws::text::one_line(&field("reason").unwrap_or_default()))),
        _ => Err(ApiError::Unreached("a certificate's state of no known type".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_tunnel_is_one_label_under_a_domain_of_two_or_more() {
        let ok =
            tunnel(&json!({ "id": "abcdefghijkl", "hostname": "abcdefghijkl.opentunnel.xyz", "state": "offline" }));
        assert_eq!(ok.unwrap(), Tunnel { id: "abcdefghijkl".into(), hostname: "abcdefghijkl.opentunnel.xyz".into() });
        for bad in [
            json!({ "id": "abc", "hostname": "other.opentunnel.xyz" }),
            json!({ "id": "abc", "hostname": "abc.xyz" }),
            json!({ "id": "a/b", "hostname": "a/b.opentunnel.xyz" }),
            json!({ "id": "abc", "hostname": "abc.evil..xyz" }),
            json!({ "hostname": "abc.opentunnel.xyz" }),
        ] {
            assert!(tunnel(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_certificate_s_states_are_read() {
        assert_eq!(cert(&json!({ "id": "c", "state": { "type": "issuing" } })), Ok(Cert::Issuing));
        let ready = json!({ "id": "c", "state": { "type": "ready", "certificate": "LEAF", "chain": "CA", "expiry": "2027-01-31T00:00:00.000Z" } });
        let want =
            Cert::Ready { certificate: "LEAF".into(), chain: "CA".into(), expiry: "2027-01-31T00:00:00.000Z".into() };
        assert_eq!(cert(&ready), Ok(want));
        assert_eq!(cert(&json!({ "state": { "type": "failed", "reason": "dns" } })), Ok(Cert::Failed("dns".into())));
        assert!(cert(&json!({ "state": { "type": "ready" } })).is_err());
        assert!(cert(&json!({ "state": {} })).is_err());
    }

    #[test]
    fn a_refusal_names_its_tag_its_message_and_its_wait() {
        let limited = Response {
            status: 429,
            reason: "Too Many Requests".into(),
            headers: vec![("retry-after".into(), "1800".into())],
            body: br#"{"_tag":"RateLimitedError","message":"Too many tunnels created from this address; try again in 30 minutes"}"#.to_vec(),
        };
        let refused = refusal(&limited);
        assert_eq!(refused.status(), Some(429));
        let text = refused.to_string();
        assert!(text.starts_with("OpenTunnel answered 429 (RateLimitedError): Too many tunnels"), "{text}");
        assert!(text.ends_with("(Retry-After: 1800 s)"), "{text}");
        let cloudflare = Response { status: 525, reason: String::new(), headers: Vec::new(), body: b"<html>".to_vec() };
        assert_eq!(
            refusal(&cloudflare).to_string(),
            "OpenTunnel answered 525: Cloudflare 525: the SSL handshake with the server failed"
        );
    }
}
