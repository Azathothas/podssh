//! The signed list of deployments (T-346): relay hosts beyond the default
//! deployment's domain, in a document that a key of this binary's trust
//! signed. `/relays.json` carries it in its field `signed`, beside the pool,
//! as `{"doc": TEXT, "key": HEX, "sig": BASE64}`: the document's exact text,
//! the Ed25519 key that signed it, and that key's signature of [`LABEL`] and
//! the text. A host outside the default's parent domain comes from such a
//! list alone. A list with no signature, of a key that is not trusted, with
//! a changed byte, that ended or lives too long, or older than the list kept
//! of its key ([`super::kept`]) keeps the default's domain alone. Each host
//! of another deployment mints a token of its own (`token::token_key`), so a
//! token goes only to the deployment that minted it (Q49).

use std::sync::{Mutex, RwLock};

use base64::Engine;
use serde_json::{json, Value};

use crate::identity::{Identity, KeyName, PublicKey};
use crate::relay::{parse_relay, Relay};
use crate::token::relay_name;

/// The form of the document, its field `podssh-relays`.
pub const FORM: u64 = 1;
/// What a key signs: this, then the document's text, so that a signature
/// of a list serves no other purpose of the key.
pub const LABEL: &[u8] = b"podssh-relays/1\0";
/// The longest life of a list, from its `issued` to its `not_after`: a key
/// that leaked signs no list that lives for ever.
pub const MAX_LIFE_S: i64 = 400 * 86_400;
/// The life of a list that the relay role signs; it signs a new one each day.
pub const ROLE_LIFE_S: i64 = 90 * 86_400;
/// How long the role serves one signature before it signs again.
pub const ROLE_RESIGN_S: i64 = 86_400;
/// The role's key file in the cache, made when it is missing: a key for this
/// one job.
pub const ROLE_KEY_FILE: &str = "relay-list.key";
/// The most deployments of a list, and the most hosts of each.
pub const MAX_DEPLOYMENTS: usize = 16;
pub const MAX_HOSTS: usize = 8;
/// The most bytes of a document: it rides in `/relays.json`, and the cache
/// keeps a few in one file.
pub const MAX_DOC: usize = 8 * 1024;
/// The variable that names more keys to trust, or `none` for no key.
pub const KEYS_ENV: &str = "PODSSH_RELAY_KEYS";
/// The keys compiled in, by their fingerprints: the default deployment's
/// operator's (`docs/relay-operator.md`, item 14), the current key and the
/// next, so that a binary in the field takes the operator's next deployment.
/// An empty list trusts the user's keys and the net's alone.
pub const BUILT_IN: &[&str] = &[];

/// A deployment of a list: its name, and its hosts in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    pub name: String,
    pub hosts: Vec<Relay>,
}

impl Deployment {
    /// Its hosts as `host` or `host:port`, separated by commas.
    pub fn shown(&self) -> String {
        self.hosts.iter().map(relay_name).collect::<Vec<_>>().join(", ")
    }
}

/// The document: a serial that only grows for its key, when it was signed
/// and when it ends (seconds since 1970), and its deployments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doc {
    pub serial: u64,
    pub issued: i64,
    pub not_after: i64,
    pub deployments: Vec<Deployment>,
}

/// Whether `name` can name a deployment: letters, digits, `-` and `_`, 63 at
/// most, not first `-`, as a member of the net is named.
pub fn check_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then_some(()).ok_or(format!("{name:?} is not a name: letters, digits, '-' and '_', 63 at most, not first '-'"))
}

/// A deployment of `--deployment NAME=HOST[:PORT][,HOST[:PORT]...]`, each
/// host as `--relay-host` takes one.
pub fn parse_deployment(word: &str) -> Result<Deployment, String> {
    let (name, hosts) = word.split_once('=').ok_or(format!("{word:?}: NAME=HOST[:PORT][,HOST[:PORT]...]"))?;
    let name = name.trim();
    check_name(name)?;
    deployment(name, hosts.split(',').map(str::trim).filter(|h| !h.is_empty()))
}

fn deployment<'a>(name: &str, hosts: impl Iterator<Item = &'a str>) -> Result<Deployment, String> {
    let mut list: Vec<Relay> = Vec::new();
    for host in hosts {
        let relay = parse_relay(host).map_err(|why| format!("the deployment {name}: {why}"))?;
        if !list.contains(&relay) {
            list.push(relay);
        }
    }
    if list.is_empty() || list.len() > MAX_HOSTS {
        return Err(format!("the deployment {name} has {} hosts: 1 to {MAX_HOSTS}", list.len()));
    }
    Ok(Deployment { name: name.to_string(), hosts: list })
}

impl Doc {
    /// The document of `text`, checked: its form, its times and its
    /// deployments. Its signature is checked apart ([`check`]).
    pub fn parse(text: &str) -> Result<Doc, String> {
        if text.len() > MAX_DOC {
            return Err(format!("the list has {} bytes, more than {MAX_DOC}", text.len()));
        }
        let value: Value = serde_json::from_str(text).map_err(|_| "the list is not JSON".to_string())?;
        let number = |field: &str| value.get(field).and_then(Value::as_u64).ok_or(format!("the list has no {field}"));
        let form = number("podssh-relays")?;
        if form != FORM {
            return Err(format!("a list of the form {form}, which this podssh does not read; podssh update"));
        }
        let serial = number("serial")?;
        let issued = i64::try_from(number("issued")?).map_err(|_| "issued is out of range".to_string())?;
        let not_after = i64::try_from(number("not_after")?).map_err(|_| "not_after is out of range".to_string())?;
        if serial == 0 || not_after <= issued {
            return Err("the list's serial is 0, or it ends before it was signed".into());
        }
        let items = value.get("deployments").and_then(Value::as_array).ok_or("the list has no deployments")?;
        if items.is_empty() || items.len() > MAX_DEPLOYMENTS {
            return Err(format!("the list has {} deployments: 1 to {MAX_DEPLOYMENTS}", items.len()));
        }
        let mut deployments: Vec<Deployment> = Vec::new();
        for item in items {
            let name = item.get("name").and_then(Value::as_str).ok_or("a deployment with no name")?;
            check_name(name)?;
            if deployments.iter().any(|d| d.name == name) {
                return Err(format!("two deployments are named {name}"));
            }
            let hosts = item.get("hosts").and_then(Value::as_array).ok_or(format!("{name} has no hosts"))?;
            let words = hosts
                .iter()
                .map(|h| h.as_str().ok_or(format!("{name}: a host that is not text")))
                .collect::<Result<Vec<&str>, String>>()?;
            deployments.push(deployment(name, words.into_iter())?);
        }
        Ok(Doc { serial, issued, not_after, deployments })
    }

    /// The document's text, as a key signs it: one line of JSON.
    pub fn to_text(&self) -> String {
        let deployments: Vec<Value> = self
            .deployments
            .iter()
            .map(|d| json!({ "name": d.name, "hosts": d.hosts.iter().map(relay_name).collect::<Vec<_>>() }))
            .collect();
        let doc = json!({
            "podssh-relays": FORM, "serial": self.serial, "issued": self.issued, "not_after": self.not_after,
            "deployments": deployments,
        });
        doc.to_string()
    }
}

/// A list as it travels: the document's exact text, the key, its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub text: String,
    pub key: PublicKey,
    pub sig: [u8; 64],
}

impl Signed {
    /// The field `signed` of a `/relays.json` body: `None` when there is none.
    pub fn of_body(body: &[u8]) -> Option<Result<Signed, String>> {
        let doc: Value = serde_json::from_slice(body).ok()?;
        doc.get("signed").filter(|v| !v.is_null()).map(Signed::of_value)
    }

    /// The object `{doc, key, sig}`, read; nothing of it is trusted yet.
    pub fn of_value(value: &Value) -> Result<Signed, String> {
        let text =
            |field: &str| value.get(field).and_then(Value::as_str).ok_or(format!("the signed list has no {field}"));
        let doc = text("doc")?;
        if doc.len() > MAX_DOC {
            return Err(format!("the list has {} bytes, more than {MAX_DOC}", doc.len()));
        }
        let key = PublicKey::parse(text("key")?).ok_or("the signed list's key is not a key")?;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(text("sig")?)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .ok_or("the signed list's signature is not 64 bytes of base64")?;
        Ok(Signed { text: doc.to_string(), key, sig })
    }

    /// The object that `/relays.json` carries, and the cache keeps.
    pub fn to_value(&self) -> Value {
        let sig = base64::engine::general_purpose::STANDARD.encode(self.sig);
        json!({ "doc": self.text, "key": self.key.hex(), "sig": sig })
    }
}

/// What a key signs for `text`.
fn message(text: &str) -> Vec<u8> {
    [LABEL, text.as_bytes()].concat()
}

/// `doc`, signed by `identity`.
pub fn sign(identity: &Identity, doc: &Doc) -> Signed {
    let text = doc.to_text();
    Signed { sig: identity.sign(&message(&text)), key: identity.public(), text }
}

/// Why a list is not used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Not a list of the form: its words.
    Form(String),
    /// Signed by a key that this binary does not trust.
    Untrusted(PublicKey),
    /// The key's signature does not verify: a byte changed on the way.
    Signature(PublicKey),
    /// Its `not_after` passed.
    Ended { not_after: i64 },
    /// It lives longer than [`MAX_LIFE_S`].
    TooLong,
    /// Its serial is below the list kept of its key.
    Older { serial: u64, kept: u64 },
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Form(why) => write!(f, "{why}"),
            Refused::Untrusted(key) => write!(f, "signed by {key}, a key that this podssh does not trust"),
            Refused::Signature(key) => write!(f, "the signature of {key} does not verify: a byte changed"),
            Refused::Ended { not_after } => write!(f, "it ended at {not_after} (seconds since 1970)"),
            Refused::TooLong => write!(f, "it lives longer than {} days", MAX_LIFE_S / 86_400),
            Refused::Older { serial, kept } => write!(f, "its serial {serial} is below {kept}, the list kept"),
        }
    }
}

/// A list that holds: its document, as it came, and why its key is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub doc: Doc,
    pub signed: Signed,
    /// Where the key is trusted from: `built in`, the variable, a line of
    /// the settings file or a member of the net.
    pub by: String,
}

/// The document of `signed` when its own key's signature of the exact text
/// verifies, with no trust and no clock: what the cache reads of a list that
/// it kept. The signature comes before the text is read, so that nothing of
/// an unsigned text is.
pub fn verified(signed: &Signed) -> Result<Doc, Refused> {
    if !signed.key.verifies(&message(&signed.text), &signed.sig) {
        return Err(Refused::Signature(signed.key));
    }
    Doc::parse(&signed.text).map_err(Refused::Form)
}

/// Check `signed` at `now_s`: a trusted key, its signature of the exact
/// text, the form, and a life that holds now and is not too long. The
/// serial is the cache's to compare ([`super::kept`]).
pub fn check(signed: &Signed, keys: &Keys, now_s: i64) -> Result<Checked, Refused> {
    let by = keys.trusts(&signed.key).ok_or(Refused::Untrusted(signed.key))?;
    let doc = verified(signed)?;
    if doc.not_after - doc.issued > MAX_LIFE_S {
        return Err(Refused::TooLong);
    }
    if doc.not_after <= now_s {
        return Err(Refused::Ended { not_after: doc.not_after });
    }
    Ok(Checked { doc, signed: signed.clone(), by: by.to_string() })
}

/// The keys that this binary trusts, each with where it is trusted from.
#[derive(Debug, Clone, Default)]
pub struct Keys {
    keys: Vec<(KeyName, String)>,
}

/// The keys of the settings file and of the net, which the binary reads.
static BY_SETTINGS: RwLock<Vec<(KeyName, String)>> = RwLock::new(Vec::new());

/// Trust `keys` too, for this process: the binary gives the settings file's
/// `RelayKeys` and the relay members of the net that this host holds.
pub fn set_by_settings(keys: Vec<(KeyName, String)>) {
    *BY_SETTINGS.write().unwrap_or_else(|e| e.into_inner()) = keys;
}

/// Keys separated by commas or blanks, each a key in hex or base32, or its
/// fingerprint `SHA256:...`; `none` is no key at all.
pub fn parse_keys(text: &str) -> Result<Vec<KeyName>, String> {
    let words = text.split([',', ' ', '\t']).map(str::trim).filter(|w| !w.is_empty());
    let mut keys = Vec::new();
    for word in words {
        if word.eq_ignore_ascii_case("none") {
            continue;
        }
        keys.push(KeyName::parse(word).ok_or(format!("{word:?} is not a key: SHA256:... or its 64 hex digits"))?);
    }
    Ok(keys)
}

/// Whether `text` turns each key off: the word `none` alone.
fn is_none(text: &str) -> bool {
    text.trim().eq_ignore_ascii_case("none")
}

impl Keys {
    /// The keys of this process: those compiled in, those of the settings
    /// file and the net, and those of [`KEYS_ENV`]; `none` there trusts no
    /// key at all, the ones compiled in too.
    pub fn of_process() -> Keys {
        let env = std::env::var(KEYS_ENV).ok();
        let settings = BY_SETTINGS.read().unwrap_or_else(|e| e.into_inner()).clone();
        Keys::from_parts(env.as_deref(), settings)
    }

    /// [`Keys::of_process`] with the variable and the settings given; a word
    /// of the variable that is no key is passed over (the binary refuses it
    /// before a run).
    pub fn from_parts(env: Option<&str>, settings: Vec<(KeyName, String)>) -> Keys {
        if env.is_some_and(is_none) {
            return Keys::default();
        }
        let built = BUILT_IN.iter().filter_map(|k| KeyName::parse(k)).map(|k| (k, "built in".to_string()));
        let named = env.into_iter().flat_map(|text| {
            let words = text.split([',', ' ', '\t']).filter_map(|w| KeyName::parse(w.trim()));
            words.map(|k| (k, KEYS_ENV.to_string())).collect::<Vec<_>>()
        });
        Keys { keys: built.chain(settings).chain(named).collect() }
    }

    /// Where `key` is trusted from, when it is.
    pub fn trusts(&self, key: &PublicKey) -> Option<&str> {
        self.keys.iter().find(|(name, _)| name.matches(key)).map(|(_, by)| by.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The relay role's list (T-346): its key, its deployments, and the list
/// signed last, which it signs again each day so that it never ends while
/// the role runs.
pub struct Signer {
    identity: Identity,
    deployments: Vec<Deployment>,
    made: Mutex<Option<(i64, u64, Value)>>,
}

impl Signer {
    /// A signer of `deployments`, checked as each client reads a list.
    pub fn new(identity: Identity, deployments: Vec<Deployment>) -> Result<Signer, String> {
        let probe = Doc { serial: 1, issued: 0, not_after: ROLE_LIFE_S, deployments: deployments.clone() };
        Doc::parse(&probe.to_text())?;
        Ok(Signer { identity, deployments, made: Mutex::new(None) })
    }

    pub fn key(&self) -> PublicKey {
        self.identity.public()
    }

    pub fn deployments(&self) -> &[Deployment] {
        &self.deployments
    }

    /// The signed list at `now_s`, as `/relays.json` carries it: the one of
    /// the last day, else a new one whose serial is above it, also when the
    /// clock went back.
    pub fn current(&self, now_s: i64) -> Value {
        let mut made = self.made.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((issued, _, value)) = made.as_ref() {
            if (0..ROLE_RESIGN_S).contains(&(now_s - issued)) {
                return value.clone();
            }
        }
        let after = made.as_ref().map_or(0, |(_, serial, _)| *serial);
        let serial = u64::try_from(now_s).unwrap_or(0).max(after + 1);
        let doc = Doc { serial, issued: now_s, not_after: now_s + ROLE_LIFE_S, deployments: self.deployments.clone() };
        let value = sign(&self.identity, &doc).to_value();
        *made = Some((now_s, serial, value.clone()));
        value
    }
}

#[cfg(test)]
#[path = "signed_tests.rs"]
mod tests;
