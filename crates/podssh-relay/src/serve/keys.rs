//! Tokens and pairs for the keys of a list (T-448): `--mint keys:FILE`; and
//! for the members of the net (T-455): `--mint net`, with a list beside it
//! or none. A mint or a pair that comes as the contract sends it, `{}`, gets
//! `401` and a challenge that this relay made; the request that comes back
//! with a key, the challenge and the key's signature of
//! `crate::keyed::message` gets its token or its pair when the key is one of
//! FILE (the format of `podssh node --allow`) or a member that the net lets
//! mint, and each other request `403`. A challenge lives a minute and is
//! taken once, so a signature that was seen cannot be sent again. The list,
//! and the net's document, are read again for each request, so that a key
//! added counts at once and one removed at its next request, as a node reads
//! its own. The signature is checked before whom the key is: the net's words
//! name the net and its member, for the key's holder alone.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use base64::Engine as _;
use podssh_ws::http::request::Request;
use serde_json::{json, Value};

use super::{Config, Mint};
use crate::identity::allow::Allowlist;
use crate::identity::PublicKey;
use crate::keyed::message;

/// The members of a net, for whom a role mints (T-455). The binary reads the
/// net's document and checks its owner's signature, which this library does
/// not do, as it holds no SSH code; it answers for each key, now.
pub trait Members: Send + Sync {
    /// The member that `key` is, in words, when it may mint now; else why
    /// not, in words that name the key.
    fn mints(&self, key: &PublicKey) -> Result<String, String>;
    /// Whom it mints for, in the words of the role's first line; `Err` when
    /// it mints for nobody now, which stops the role's start.
    fn shown(&self) -> Result<String, String>;
}

/// Whom a keyed mint lets in: the keys of a list, the members of a net, or
/// both.
#[derive(Clone, Copy)]
pub struct Whom<'a> {
    pub list: Option<&'a Path>,
    pub net: Option<&'a dyn Members>,
}

impl<'a> Whom<'a> {
    /// Whom `mint` asks a key of; none for a mint that asks no key.
    pub fn of(mint: &'a Mint) -> Option<Whom<'a>> {
        match mint {
            Mint::Keys(file) => Some(Whom::list(file)),
            Mint::Net(net, list) => Some(Whom { list: list.as_deref(), net: Some(net.as_ref()) }),
            Mint::Anyone | Mint::Nobody => None,
        }
    }

    /// The keys of the list in `file` alone.
    pub fn list(file: &'a Path) -> Whom<'a> {
        Whom { list: Some(file), net: None }
    }

    /// Whether `key` is let in: `Ok` with the net's words for its member
    /// (none for a key of the list), `Err` with why not.
    fn admits(&self, key: &PublicKey) -> Result<Option<String>, String> {
        let mut refused = Vec::new();
        if let Some(file) = self.list {
            match Allowlist::read(file) {
                Ok(list) if list.admits(key) => return Ok(None),
                Ok(_) => refused.push(format!("the key {} is not on this relay's list", key.fingerprint())),
                // The owner's file, which the client never sees named.
                Err(_) => refused.push("this relay cannot read its list of keys".to_string()),
            }
        }
        if let Some(net) = self.net {
            match net.mints(key) {
                Ok(member) => return Ok(Some(member)),
                Err(why) => refused.push(why),
            }
        }
        Err(refused.join(", and "))
    }
}

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
    /// A key that this relay mints for, which signed its challenge; with the
    /// net's words for its member when it is one (T-455).
    Key(PublicKey, Option<String>),
    /// No proof: the answer is `401` with this challenge, and its end.
    Ask(String, u64),
    /// A proof that fails: `403`, with why.
    Refused(String),
}

/// Whether `body`, of a request to `path` with the head `head`, proves a key
/// that `whom` lets in; `sni` is the name that its TLS asked for.
pub fn prove(
    cfg: &Config,
    whom: &Whom<'_>,
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
    let signature = base64::engine::general_purpose::STANDARD.decode(signature).ok();
    let Some(signature) = signature.and_then(|s| <[u8; 64]>::try_from(s).ok()) else {
        return Proof::Refused("the signature is not 64 bytes in base64".into());
    };
    if !key.verifies(&message(host, path, challenge), &signature) {
        return Proof::Refused(format!("the signature does not verify for the key {}", key.fingerprint()));
    }
    // Whom the key is, once its holder proved itself: the net's words name
    // the net and the member, which a stranger with a member's public key
    // and no signature of it must not learn (T-455).
    let member = match whom.admits(&key) {
        Ok(member) => member,
        Err(why) => return Proof::Refused(why),
    };
    if !cfg.answered.take(challenge, ends, now_ms) {
        return Proof::Refused("this challenge was answered before; ask again".into());
    }
    Proof::Key(key, member)
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
            egress: Default::default(),
            limits: Default::default(),
            pairs: Default::default(),
            resumes: Default::default(),
            answered: Default::default(),
            brake: Default::default(),
            events: None,
        }
    }

    fn head() -> Request {
        request::parse_request(b"POST /v1/mint HTTP/1.1\r\nHost: relay-a.test:8443\r\n\r\n").unwrap()
    }

    /// A private scratch file of a list, and its directory, which goes when
    /// the test ends, pass or fail: the gate counts what tests leave.
    struct List {
        dir: std::path::PathBuf,
        path: std::path::PathBuf,
    }

    impl std::ops::Deref for List {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for List {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A list that holds the key of the seed 1, in a private scratch file.
    fn list() -> List {
        let dir =
            std::env::temp_dir().join(format!("podssh-keys-{}-{:?}", std::process::id(), std::thread::current().id()));
        crate::cache::private_dir(&dir).unwrap();
        let path = dir.join("allow");
        let _ = std::fs::remove_file(&path);
        let line = format!("{} the test's key\n", Identity::from_seed(&[1; 32]).public().fingerprint());
        std::fs::write(&path, line).unwrap();
        List { dir, path }
    }

    fn challenge(c: &Config, whom: &Whom<'_>) -> String {
        match prove(c, whom, &head(), None, "/v1/mint", b"{}", 1_000) {
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
        let whom = Whom::list(&file);
        let ours = Identity::from_seed(&[1; 32]);
        let asked = challenge(&c, &whom);
        let body = proof(&ours, "relay-a.test:8443", "/v1/mint", &asked);
        assert_eq!(
            prove(&c, &whom, &head(), Some("relay-a.test"), "/v1/mint", &body, 2_000),
            Proof::Key(ours.public(), None)
        );
        let again = prove(&c, &whom, &head(), None, "/v1/mint", &body, 3_000);
        assert!(matches!(&again, Proof::Refused(w) if w.contains("answered before")), "a replay: {again:?}");
    }

    #[test]
    fn another_key_another_signature_another_relay_or_a_late_answer_is_refused() {
        let (c, file) = (cfg(), list());
        let whom = Whom::list(&file);
        let refused =
            |body: &[u8], sni: Option<&str>, now: u64| match prove(&c, &whom, &head(), sni, "/v1/mint", body, now) {
                Proof::Refused(why) => why,
                other => panic!("{other:?}"),
            };
        let theirs = Identity::from_seed(&[2; 32]);
        let asked = challenge(&c, &whom);
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
        let other = challenge(&theirs_relay, &whom);
        assert!(
            refused(&proof(&ours, "relay-a.test:8443", "/v1/mint", &other), None, 2_000).contains("not this relay's")
        );
    }

    /// A net of one member, the key of `seed`, as the binary answers for
    /// one (T-455).
    struct OneMember(u8);

    impl Members for OneMember {
        fn mints(&self, key: &PublicKey) -> Result<String, String> {
            match *key == Identity::from_seed(&[self.0; 32]).public() {
                true => Ok("the member lab of the net home (serial 2)".into()),
                false => Err(format!("the key {} is not a member of the net that this relay holds", key.fingerprint())),
            }
        }

        fn shown(&self) -> Result<String, String> {
            Ok("the members of the net home".into())
        }
    }

    #[test]
    fn a_member_of_the_net_mints_and_a_stranger_hears_of_the_net_only_by_its_own_signature() {
        let (c, net) = (cfg(), OneMember(1));
        let whom = Whom { list: None, net: Some(&net) };
        let (ours, theirs) = (Identity::from_seed(&[1; 32]), Identity::from_seed(&[2; 32]));
        let asked = challenge(&c, &whom);
        let body = proof(&ours, "relay-a.test:8443", "/v1/mint", &asked);
        let member = Some("the member lab of the net home (serial 2)".to_string());
        assert_eq!(prove(&c, &whom, &head(), None, "/v1/mint", &body, 2_000), Proof::Key(ours.public(), member));
        // A stranger, by its own signature: the net's words, with its key.
        let asked = challenge(&c, &whom);
        let refused = prove(
            &c,
            &whom,
            &head(),
            None,
            "/v1/mint",
            &proof(&theirs, "relay-a.test:8443", "/v1/mint", &asked),
            2_000,
        );
        let print = theirs.public().fingerprint();
        assert!(
            matches!(&refused, Proof::Refused(w) if w.contains("not a member") && w.contains(&print)),
            "{refused:?}"
        );
        // The member's key, with no signature of it: no word of the net.
        let mut forged: Value =
            serde_json::from_slice(&proof(&theirs, "relay-a.test:8443", "/v1/mint", &asked)).unwrap();
        forged["key"] = ours.public().hex().into();
        let refused = prove(&c, &whom, &head(), None, "/v1/mint", forged.to_string().as_bytes(), 2_000);
        assert!(
            // Words with a space, which no fingerprint holds.
            matches!(&refused, Proof::Refused(w) if w.contains("does not verify") && !w.contains(" member")),
            "{refused:?}"
        );
    }

    #[test]
    fn a_key_of_the_list_or_a_member_of_the_net_beside_it_mints_and_another_hears_both_refusals() {
        let (c, file, net) = (cfg(), list(), OneMember(3));
        let whom = Whom { list: Some(&file), net: Some(&net) };
        let proved = |seed: u8| {
            let asked = challenge(&c, &whom);
            let key = Identity::from_seed(&[seed; 32]);
            prove(&c, &whom, &head(), None, "/v1/mint", &proof(&key, "relay-a.test:8443", "/v1/mint", &asked), 2_000)
        };
        assert_eq!(proved(1), Proof::Key(Identity::from_seed(&[1; 32]).public(), None), "the list's key");
        assert!(matches!(proved(3), Proof::Key(_, Some(_))), "the net's member");
        let refused = match proved(2) {
            Proof::Refused(why) => why,
            other => panic!("{other:?}"),
        };
        assert!(
            refused.contains("not on this relay's list, and the key") && refused.contains("not a member"),
            "{refused}"
        );
        // Whom each mint asks a key of, and its word in /health.
        let both = Mint::Net(std::sync::Arc::new(OneMember(3)), Some(file.to_path_buf()));
        assert!(Whom::of(&both).is_some_and(|w| w.list.is_some() && w.net.is_some()));
        assert_eq!((both.word(), Mint::Net(std::sync::Arc::new(OneMember(3)), None).word()), ("net,keys", "net"));
        assert!(Whom::of(&Mint::Anyone).is_none() && Whom::of(&Mint::Nobody).is_none());
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
