//! One order of a certificate for one name (RFC 8555, section 7.4): its
//! authorization proven by TLS-ALPN-01 on the role's own listener (RFC 8737),
//! the order finalized with a CSR of a new key, and the chain fetched and
//! checked against that key and the name before it is kept.

use std::time::{Duration, Instant};

use base64::Engine as _;
use podssh_ws::tls_server::Served;
use serde_json::{json, Value};

use super::certs::{self, Key, Leaf};
use super::client::{self, Client, PEM_CHAIN};

/// How long one authorization, or one stage of the order, may wait for the CA.
const STAGE: Duration = Duration::from_secs(180);
/// The statuses after which an object of the CA never changes again.
const FINAL: &[&str] = &["invalid", "deactivated", "expired", "revoked"];

/// A certificate that the CA issued: its key, and its chain in PEM.
pub struct Issued {
    pub key: Key,
    pub chain: String,
    pub leaf: Leaf,
}

/// Order a certificate for `name`, each challenge served through `served`.
pub async fn order(client: &mut Client, name: &str, served: &Served) -> Result<Issued, String> {
    let identifiers = json!({"identifiers": [{"type": "dns", "value": name}]});
    let url = client.directory.new_order.clone();
    let answer = client.post(&url, Some(&identifiers), "application/json").await?;
    if answer.status != 201 {
        return Err(format!("the order: {}", client::problem(&answer)));
    }
    let order_url = answer.header("location").ok_or("the CA gave the order no Location")?.to_string();
    let order = client::json_of(&answer)?;
    for authorization in strings(&order["authorizations"]) {
        authorize(client, &authorization, name, served).await?;
    }
    let ready = poll(client, &order_url, "the order", &["ready", "valid"]).await?;
    if ready["status"] != "ready" {
        return Err("the CA gave an order that was finalized before, whose key podssh does not hold".into());
    }
    let finalize = ready["finalize"].as_str().ok_or("the order has no finalize URL")?.to_string();
    let key = Key::generate()?;
    let csr = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(certs::csr(name, &key)?);
    let answer = client.post(&finalize, Some(&json!({ "csr": csr })), "application/json").await?;
    client::json_of(&answer).map_err(|why| format!("the finalization: {why}"))?;
    let valid = poll(client, &order_url, "the order", &["valid"]).await?;
    let at = valid["certificate"].as_str().ok_or("the valid order names no certificate")?.to_string();
    let answer = client.post(&at, None, PEM_CHAIN).await?;
    if answer.status != 200 {
        return Err(format!("the certificate: {}", client::problem(&answer)));
    }
    let chain = String::from_utf8(answer.body).map_err(|_| "the certificate's chain is not text")?;
    // The chain must load with the key made for it, and name the name.
    let (_, leaf) = certs::load(chain.as_bytes(), key.pem().as_bytes()).map_err(|why| format!("the chain: {why}"))?;
    if !leaf.names.iter().any(|n| n == name) {
        return Err(format!("the CA's certificate names {:?}, not {name}", leaf.names));
    }
    Ok(Issued { key, chain, leaf })
}

/// Prove the authorization at `url`, unless the CA holds it valid already.
async fn authorize(client: &mut Client, url: &str, name: &str, served: &Served) -> Result<(), String> {
    let (authz, _) = client.get_json(url).await?;
    match authz["status"].as_str() {
        Some("valid") => return Ok(()),
        Some("pending") => {}
        other => return Err(format!("the authorization of {name} is {}", other.unwrap_or("of no status"))),
    }
    let challenges = authz["challenges"].as_array().cloned().unwrap_or_default();
    let Some(challenge) = challenges.iter().find(|c| c["type"] == "tls-alpn-01") else {
        let offered: Vec<&str> = challenges.iter().filter_map(|c| c["type"].as_str()).collect();
        return Err(format!("the CA offers no tls-alpn-01 for {name}, only {}", offered.join(", ")));
    };
    let (Some(token), Some(at)) = (challenge["token"].as_str(), challenge["url"].as_str()) else {
        return Err("the challenge has no token or no URL".into());
    };
    let authorization = client.key().key_authorization(token);
    let (cert, key) = certs::challenge(name, &authorization, now_secs())?;
    served.set_challenge(name, podssh_ws::tls_server::certified(cert.as_bytes(), key.as_bytes())?);
    // The challenge's certificate goes when this does, on each path out.
    let _served = Answering { served, name };
    let answer = client.post(at, Some(&json!({})), "application/json").await?;
    client::json_of(&answer).map_err(|why| format!("the challenge: {why}"))?;
    poll(client, url, &format!("the authorization of {name}"), &["valid"]).await?;
    Ok(())
}

/// While it lives, a validation of the name gets the challenge's certificate.
struct Answering<'a> {
    served: &'a Served,
    name: &'a str,
}

impl Drop for Answering<'_> {
    fn drop(&mut self) {
        self.served.clear_challenge(self.name);
    }
}

/// Ask `url` until its status is one of `until`, as the CA's Retry-After
/// says, for [`STAGE`] at most; a final status ends it with the CA's reason.
async fn poll(client: &mut Client, url: &str, what: &str, until: &[&str]) -> Result<Value, String> {
    let end = Instant::now() + STAGE;
    loop {
        let (v, answer) = client.get_json(url).await?;
        let status = v["status"].as_str().unwrap_or_default().to_string();
        if until.contains(&status.as_str()) {
            return Ok(v);
        }
        if FINAL.contains(&status.as_str()) {
            return Err(format!("{what} is {status}: {}", reason(&v)));
        }
        if Instant::now() >= end {
            return Err(format!("{what} is still {status} after {} s", STAGE.as_secs()));
        }
        tokio::time::sleep(client::retry_after(&answer, now_secs())).await;
    }
}

/// Why an order or an authorization failed: its error, else the error of
/// a challenge (RFC 8555, sections 7.1.3 and 7.1.4).
pub fn reason(v: &Value) -> String {
    let error = Some(&v["error"])
        .filter(|e| e.is_object())
        .or_else(|| v["challenges"].as_array()?.iter().map(|c| &c["error"]).find(|e| e.is_object()));
    match error.map(client::describe) {
        Some(text) if !text.is_empty() => podssh_ws::text::one_line(&text),
        _ => "the CA gave no reason".into(),
    }
}

/// The strings of a JSON array.
fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|s| s.as_str().map(str::to_string)).collect()
}

pub fn now_secs() -> i64 {
    crate::pairs::now_ms().div_euclid(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An authorization that failed, in the shape of RFC 8555's example
    /// (section 7.1.4) and Pebble's words for a listener it cannot reach.
    #[test]
    fn the_reason_of_a_failure_is_the_error_of_the_challenge_or_of_the_order() {
        let authz = json!({
            "status": "invalid",
            "identifier": {"type": "dns", "value": "relay.podssh.test"},
            "challenges": [
                {"type": "http-01", "status": "pending", "url": "https://ca.test/c/1", "token": "a"},
                {"type": "tls-alpn-01", "status": "invalid", "url": "https://ca.test/c/2", "token": "b",
                 "error": {"type": "urn:ietf:params:acme:error:unauthorized",
                           "detail": "Failed to connect to 127.0.0.1:5001 for the tls-alpn-01 challenge"}}
            ]
        });
        assert_eq!(reason(&authz), "unauthorized: Failed to connect to 127.0.0.1:5001 for the tls-alpn-01 challenge");
        let order = json!({"status": "invalid", "error": {"type": "urn:ietf:params:acme:error:badCSR", "detail": "x"}});
        assert_eq!(reason(&order), "badCSR: x");
        assert_eq!(reason(&json!({"status": "invalid"})), "the CA gave no reason");
    }

    #[test]
    fn the_strings_of_an_array_are_its_strings_alone() {
        assert_eq!(strings(&json!(["a", 1, "b"])), ["a", "b"]);
        assert!(strings(&json!(null)).is_empty());
    }
}
