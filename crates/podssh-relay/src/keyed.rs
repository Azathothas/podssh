//! A request to a relay that mints for the keys of a list (T-448): podssh's
//! relay role with `--mint keys:FILE`. The request goes as the contract
//! sends it, `{}`; such a relay answers `401` with a challenge of its own,
//! and the request goes once more with this client's Ed25519 key, the
//! challenge and the key's signature of [`message`]. A relay of the
//! contract never answers `401`, so nothing changes for it.
//!
//! The key is the client's of the cache (`client.key`), the one that a
//! node's allowlist lets in, so that one line on each list lets a user in
//! everywhere. The signature binds the relay's name as this request sends
//! it, the path and the challenge, which the relay takes once.

use std::time::Duration;

use base64::Engine as _;
use podssh_ws::http::Response;
use podssh_ws::{https_post_json, ConnectError, ProxyChoice, Trust};
use serde_json::{json, Value};

use crate::identity::file;
use crate::session::OsEntropy;

/// The first bytes of each signed message: its purpose and its version, so
/// that no signature of the key serves another proof.
pub const LABEL: &[u8] = b"podssh relay key, version 1\0";

/// What the key signs: the label, the relay's name as the request's `Host`
/// sends it, the path, and the relay's challenge, apart by a zero byte.
pub fn message(host: &str, path: &str, challenge: &str) -> Vec<u8> {
    [LABEL, host.as_bytes(), b"\0", path.as_bytes(), b"\0", challenge.as_bytes()].concat()
}

/// The `Host` of a request to `host:port`, as podssh-ws writes it.
pub fn host_header(host: &str, port: u16) -> String {
    if port == 443 {
        host.to_string()
    } else {
        podssh_ws::dial::authority(host, port)
    }
}

/// The challenge of a relay's `401`, when it gives one.
pub fn challenge_of(response: &Response) -> Option<String> {
    if response.status != 401 {
        return None;
    }
    let body: Value = serde_json::from_slice(&response.body).ok()?;
    let challenge = body.get("challenge")?.as_str()?;
    // Shown in no message, and sent back as it came: a bound on its size
    // and its characters is all that it needs.
    (challenge.len() <= 512 && challenge.bytes().all(|b| b.is_ascii_graphic())).then(|| challenge.to_string())
}

/// The body that proves the key `identity` for `challenge`.
pub fn proof(identity: &crate::identity::Identity, host: &str, path: &str, challenge: &str) -> Vec<u8> {
    let signature = identity.sign(&message(host, path, challenge));
    json!({
        "key": identity.public().hex(),
        "challenge": challenge,
        "signature": base64::engine::general_purpose::STANDARD.encode(signature),
    })
    .to_string()
    .into_bytes()
}

/// `POST path` with `{}`; when the relay asks for a key, once more with this
/// client's.
pub async fn post(
    host: &str,
    port: u16,
    path: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<Response, ConnectError> {
    let first = https_post_json(host, port, path, b"{}", trust, proxy, timeout).await?;
    let Some(challenge) = challenge_of(&first) else { return Ok(first) };
    let key = file::load(&file::client_place(), &mut OsEntropy).map_err(|why| {
        ConnectError::Config(format!("the relay mints for the keys of its list; this client's key: {why}"))
    })?;
    let body = proof(&key.identity, &host_header(host, port), path, &challenge);
    https_post_json(host, port, path, &body, trust, proxy, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_names_its_purpose_the_relay_the_path_and_the_challenge() {
        let m = message("relay-a.test:8443", "/v1/mint", "c1.x");
        assert!(m.starts_with(LABEL));
        assert!(m.ends_with(b"relay-a.test:8443\0/v1/mint\0c1.x"));
        assert_ne!(message("relay-b.test", "/v1/mint", "c1.x"), message("relay-a.test", "/v1/mint", "c1.x"));
        assert_ne!(message("h", "/v1/pair", "c"), message("h", "/v1/mint", "c"));
        assert_eq!(host_header("relay-a.test", 443), "relay-a.test");
        assert_eq!(host_header("::1", 8443), "[::1]:8443");
    }

    #[test]
    fn a_proof_verifies_under_its_key_alone() {
        let identity = crate::identity::Identity::from_seed(&[7; 32]);
        let body: Value = serde_json::from_slice(&proof(&identity, "h", "/v1/mint", "c1.x")).unwrap();
        let key = crate::identity::PublicKey::parse(body["key"].as_str().unwrap()).unwrap();
        let signature = base64::engine::general_purpose::STANDARD.decode(body["signature"].as_str().unwrap()).unwrap();
        let signature: [u8; 64] = signature.try_into().unwrap();
        assert!(key.verifies(&message("h", "/v1/mint", "c1.x"), &signature));
        assert!(!key.verifies(&message("h", "/v1/mint", "c1.y"), &signature), "another challenge");
        let other = crate::identity::Identity::from_seed(&[8; 32]).public();
        assert!(!other.verifies(&message("h", "/v1/mint", "c1.x"), &signature), "another key");
    }

    #[test]
    fn only_a_401_with_a_challenge_asks_for_a_key() {
        let answer = |status: u16, body: &str| Response {
            status,
            reason: String::new(),
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        };
        assert_eq!(challenge_of(&answer(401, r#"{"challenge":"c1.abc"}"#)).as_deref(), Some("c1.abc"));
        assert_eq!(challenge_of(&answer(200, r#"{"challenge":"c1.abc"}"#)), None);
        assert_eq!(challenge_of(&answer(401, "no")), None);
        assert_eq!(challenge_of(&answer(401, r#"{"challenge":"a b"}"#)), None);
    }
}
