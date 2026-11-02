//! Tokens and pairs for the keys of a list (T-448): `--mint keys:FILE`. A
//! mint or a pair that comes as the contract sends it, `{}`, gets `401` and a
//! challenge that this relay made; the request that comes back with a key of
//! FILE (the format of `podssh node --allow`), the challenge and the key's
//! signature of `crate::keyed::message` gets its token or its pair, and each
//! other request `403`. A challenge lives a minute and is taken once, so a
//! signature that was seen cannot be sent again. The list is read again for
//! each request, so that a key added counts at once, as a node reads its own.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use base64::Engine as _;
use podssh_ws::http::request::Request;
use serde_json::{json, Value};

use super::Config;
use crate::identity::allow::Allowlist;
use crate::identity::PublicKey;
use crate::keyed::message;

/// How long a challenge may be answered.
pub const CHALLENGE_MS: u64 = 60_000;

/// The challenges answered, each until its end, so that none is taken twice.
#[derive(Default)]
pub struct Answered(Mutex<HashMap<String, u64>>);

impl Answered {
    /// Take `challenge`, which ends at `ends`: false when it was taken before.
    fn take(&self, challenge: &str, ends: u64, now_ms: u64) -> bool {
        let mut taken = self.0.lock().unwrap_or_else(|e| e.into_inner());
        taken.retain(|_, end| *end > now_ms);
        taken.insert(challenge.to_string(), ends).is_none()
    }
}

/// What a request proved.
#[derive(Debug, PartialEq, Eq)]
pub enum Proof {
    /// A key of the list, which signed this relay's challenge.
    Key(PublicKey),
    /// No proof: the answer is `401` with this challenge, and its end.
    Ask(String, u64),
    /// A proof that fails: `403`, with why.
    Refused(String),
}

/// Whether `body`, of a request to `path` with the head `head`, proves a key
/// of the list in `file`; `sni` is the name that its TLS asked for.
pub fn prove(
    cfg: &Config,
    file: &Path,
    head: &Request,
    sni: Option<&str>,
    path: &str,
    body: &[u8],
    now_ms: u64,
) -> Proof {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let field = |name: &str| value.get(name).and_then(Value::as_str);
    let (Some(key), Some(challenge), Some(signature)) = (field("key"), field("challenge"), field("signature")) else {
        return match cfg.tokens.challenge(now_ms, CHALLENGE_MS) {
            Ok((challenge, ends)) => Proof::Ask(challenge, ends),
            Err(why) => Proof::Refused(why),
        };
    };
    let host = head.header("host").unwrap_or_default();
    // A request that names another relay than the one that its TLS reached
    // was sent on by a relay in the middle, with a signature made for it.
    if sni.is_some_and(|sni| !same_name(host, sni)) {
        return Proof::Refused("the request's Host is not the name that its TLS asked for".into());
    }
    let Some(ends) = cfg.tokens.check_challenge(challenge, now_ms) else {
        return Proof::Refused("the challenge is not this relay's, or it ended; ask again".into());
    };
    let Some(key) = PublicKey::parse(key) else {
        return Proof::Refused("the key is not an Ed25519 key in 64 hex digits".into());
    };
    let list = match Allowlist::read(file) {
        Ok(list) => list,
        // The owner's file, which the client never sees named.
        Err(_) => return Proof::Refused("this relay cannot read its list of keys".into()),
    };
    if !list.admits(&key) {
        return Proof::Refused(format!("the key {} is not on this relay's list", key.fingerprint()));
    }
    let signature = base64::engine::general_purpose::STANDARD.decode(signature).ok();
    let Some(signature) = signature.and_then(|s| <[u8; 64]>::try_from(s).ok()) else {
        return Proof::Refused("the signature is not 64 bytes in base64".into());
    };
    if !key.verifies(&message(host, path, challenge), &signature) {
        return Proof::Refused(format!("the signature does not verify for the key {}", key.fingerprint()));
    }
    if !cfg.answered.take(challenge, ends, now_ms) {
        return Proof::Refused("this challenge was answered before; ask again".into());
    }
    Proof::Key(key)
}

/// The `401` that asks for a key: the challenge and its end, in JSON.
pub fn ask(challenge: &str, ends: u64) -> Vec<u8> {
    let body = json!({ "challenge": challenge, "expires": ends, "sign": "podssh relay key, version 1" }).to_string();
    format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: podssh-key\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Whether the `Host` of a request names `sni`, with no port and in any
/// case.
fn same_name(host: &str, sni: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => match host.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
            _ => host,
        },
    };
    name.trim_end_matches('.').eq_ignore_ascii_case(sni.trim_end_matches('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::keyed::proof;
    use podssh_ws::http::request;

    fn cfg() -> Config {
        Config {
            version: "test".into(),
            mint: super::super::Mint::Anyone,
            tokens: super::super::tokens::Tokens::new([4; 32]),
            policy: Default::default(),
            limits: Default::default(),
            pairs: Default::default(),
            answered: Default::default(),
            brake: Default::default(),
            events: None,
        }
    }

    fn head() -> Request {
        request::parse_request(b"POST /v1/mint HTTP/1.1\r\nHost: relay-a.test:8443\r\n\r\n").unwrap()
    }

    /// A list that holds the key of the seed 1, in a private scratch file.
    fn list() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("podssh-keys-{}-{:?}", std::process::id(), std::thread::current().id()));
        crate::cache::private_dir(&dir).unwrap();
        let path = dir.join("allow");
        let _ = std::fs::remove_file(&path);
        let line = format!("{} the test's key\n", Identity::from_seed(&[1; 32]).public().fingerprint());
        std::fs::write(&path, line).unwrap();
        path
    }

    fn challenge(c: &Config, file: &Path) -> String {
        match prove(c, file, &head(), None, "/v1/mint", b"{}", 1_000) {
            Proof::Ask(challenge, ends) => {
                assert_eq!(ends, 1_000 + CHALLENGE_MS);
                challenge
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_key_of_the_list_that_signs_the_challenge_proves_itself_once() {
        let (c, file) = (cfg(), list());
        let ours = Identity::from_seed(&[1; 32]);
        let asked = challenge(&c, &file);
        let body = proof(&ours, "relay-a.test:8443", "/v1/mint", &asked);
        assert_eq!(
            prove(&c, &file, &head(), Some("relay-a.test"), "/v1/mint", &body, 2_000),
            Proof::Key(ours.public())
        );
        let again = prove(&c, &file, &head(), None, "/v1/mint", &body, 3_000);
        assert!(matches!(&again, Proof::Refused(w) if w.contains("answered before")), "a replay: {again:?}");
    }

    #[test]
    fn another_key_another_signature_another_relay_or_a_late_answer_is_refused() {
        let (c, file) = (cfg(), list());
        let refused =
            |body: &[u8], sni: Option<&str>, now: u64| match prove(&c, &file, &head(), sni, "/v1/mint", body, now) {
                Proof::Refused(why) => why,
                other => panic!("{other:?}"),
            };
        let theirs = Identity::from_seed(&[2; 32]);
        let asked = challenge(&c, &file);
        assert!(refused(&proof(&theirs, "relay-a.test:8443", "/v1/mint", &asked), None, 2_000)
            .contains("not on this relay's list"));
        // The listed key, with a signature of another key's.
        let mut forged: Value =
            serde_json::from_slice(&proof(&theirs, "relay-a.test:8443", "/v1/mint", &asked)).unwrap();
        forged["key"] = Identity::from_seed(&[1; 32]).public().hex().into();
        assert!(refused(forged.to_string().as_bytes(), None, 2_000).contains("does not verify"));
        let ours = Identity::from_seed(&[1; 32]);
        // Signed for another path, or another relay.
        assert!(
            refused(&proof(&ours, "relay-a.test:8443", "/v1/pair", &asked), None, 2_000).contains("does not verify")
        );
        assert!(refused(&proof(&ours, "relay-b.test", "/v1/mint", &asked), None, 2_000).contains("does not verify"));
        assert!(refused(&proof(&ours, "relay-a.test:8443", "/v1/mint", &asked), Some("relay-b.test"), 2_000)
            .contains("Host"));
        // Too late, and another relay's challenge.
        assert!(refused(&proof(&ours, "relay-a.test:8443", "/v1/mint", &asked), None, 1_000 + CHALLENGE_MS)
            .contains("ended"));
        let theirs_relay = Config { tokens: super::super::tokens::Tokens::new([9; 32]), ..cfg() };
        let other = challenge(&theirs_relay, &file);
        assert!(
            refused(&proof(&ours, "relay-a.test:8443", "/v1/mint", &other), None, 2_000).contains("not this relay's")
        );
    }

    #[test]
    fn a_name_is_the_same_with_its_port_its_case_and_its_dot() {
        assert!(same_name("relay-a.test:8443", "relay-a.test"));
        assert!(same_name("Relay-A.test.", "relay-a.test"));
        assert!(same_name("[::1]:8443", "::1"));
        assert!(!same_name("relay-b.test", "relay-a.test"));
        let text = String::from_utf8(ask("c1.x", 5)).unwrap();
        assert!(
            text.starts_with("HTTP/1.1 401 ")
                && text.ends_with(r#""challenge":"c1.x","expires":5,"sign":"podssh relay key, version 1"}"#),
            "{text}"
        );
    }
}
