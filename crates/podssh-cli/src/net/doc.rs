//! The net's document (T-429): its name, a serial, when it was signed and
//! when it ends, its owner's key, and its members, each with a name, an
//! Ed25519 key, its roles, its tickets, an exit's routes (T-432), a relay
//! role's host (T-617) and the names of a node's shares (T-433); as one JSON
//! object, whose bytes
//! the owner's key signs (`super::sign`). podssh writes it on one line, its
//! keys in order, so that each change is a short diff of a text file.
//!
//! A field that this podssh does not know is kept as it is when the owner
//! signs a change, so that the part of a later podssh is not lost by an
//! earlier one. A document whose `requires` names a part that this podssh
//! does not read is refused: a rule that an end cannot read must not be
//! skipped, as a policy skipped lets in each member. The policy (T-430,
//! `super::policy`) is such a part.

use std::collections::BTreeMap;

use podssh_relay::identity::KeyName;
use serde_json::{json, Map, Value};

use super::policy::{self, Policy};
use super::policy_words::Range;

/// The form of the document, its field `podssh-net`.
pub const VERSION: u64 = 1;
/// The roles that a member may have: what it offers the net.
pub const ROLES: &[&str] = &["node", "exit", "relay", "share"];
/// The kinds of a member's tickets, the roads where it can be found.
pub const TICKETS: &[&str] = &["iroh", "derp"];
/// The parts that a document's `requires` may name and that this podssh
/// reads: the policy (T-430).
const KNOWN_PARTS: &[&str] = &[policy::PART];
/// The most bytes of a document: with its signature, it fits a file of the
/// cache and one message of the end-to-end channel.
pub const MAX_DOC: usize = 60 * 1024;
/// The most members of one net.
pub const MAX_MEMBERS: usize = 1000;

/// A member of the net.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Its name in the net: `podssh ssh NAME`, `node://NAME`.
    pub name: String,
    /// Its Ed25519 key, or the key's fingerprint, as an allowlist names one.
    pub key: KeyName,
    pub roles: Vec<String>,
    /// Its tickets by kind (`iroh`, `derp`), as the user gave them.
    pub tickets: BTreeMap<String, String>,
    /// The private ranges that it routes for the net, an exit's (T-432),
    /// each as the owner wrote it: `--exit auto` finds the node by them. A
    /// word that this podssh does not read as a range is kept, and unused.
    pub routes: Vec<String>,
    /// Where a relay role serves its signed list (T-617), one host as
    /// `--relay-host` takes it, as the owner wrote it: a client asks it with
    /// no `--relay-host`. A host that this podssh does not read is kept, and
    /// unused.
    pub relay: Option<String>,
    /// The names of its shares (T-433), as the owner wrote them: `podssh
    /// share ls --net` lists them, each reached as `node://NAME/SHARE`. The
    /// node serves what its own share file holds; this is the net's list.
    pub shares: Vec<String>,
}

impl Member {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// The ranges of its routes that this podssh reads.
    pub fn ranges(&self) -> Vec<(&str, Range)> {
        self.routes.iter().filter_map(|word| Some((word.as_str(), Range::parse(word)?))).collect()
    }
}

/// A document, read and checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Doc {
    pub name: String,
    pub serial: u64,
    /// When the owner signed it, in seconds since 1970.
    pub issued: i64,
    /// When it ends, in seconds since 1970: no end takes it after.
    pub expires: i64,
    /// The owner's public key, as an OpenSSH line: `TYPE BASE64`.
    pub owner: String,
    pub members: Vec<Member>,
    /// Who may reach what (T-430); none: each member reaches each.
    pub policy: Option<Policy>,
    /// The whole object, with each field that this podssh does not know.
    whole: Map<String, Value>,
}

/// Whether `name` can name a net or a member: letters, digits, `-` and `_`,
/// 63 at most, not first `-`; never a dot, so that no DNS name is one, and
/// the label of a pair takes it.
pub fn check_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    match ok {
        true => Ok(()),
        false => Err(format!("{name:?} is not a name: letters, digits, '-' and '_', 63 at most, not first '-'")),
    }
}

/// `--roles node,exit`: each one known, each once.
pub fn parse_roles(text: &str) -> Result<Vec<String>, String> {
    let mut roles: Vec<String> = Vec::new();
    for role in text.split(',').map(str::trim).filter(|r| !r.is_empty()) {
        if !ROLES.contains(&role) {
            return Err(format!("{role:?} is not a role: {}", ROLES.join(", ")));
        }
        if !roles.iter().any(|r| r == role) {
            roles.push(role.to_string());
        }
    }
    match roles.is_empty() {
        true => Err(format!("no role: give one or more of {}", ROLES.join(", "))),
        false => Ok(roles),
    }
}

impl Doc {
    /// A first document, serial 1.
    pub fn new(name: &str, owner: &str, issued: i64, expires: i64) -> Result<Doc, String> {
        check_name(name)?;
        let whole = json!({
            "podssh-net": VERSION, "name": name, "serial": 1, "issued": issued, "expires": expires,
            "owner": owner, "members": [], "requires": [],
        });
        Doc::from_value(whole)
    }

    /// The document of `bytes`, checked: its form, its fields and its
    /// members. Its signature is checked apart (`super::sign`).
    pub fn parse(bytes: &[u8]) -> Result<Doc, String> {
        if bytes.len() > MAX_DOC {
            return Err(format!("the document has {} bytes, more than {MAX_DOC}", bytes.len()));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("the document is not JSON: {e}"))?;
        Doc::from_value(value)
    }

    fn from_value(value: Value) -> Result<Doc, String> {
        let Value::Object(whole) = value else { return Err("the document is not a JSON object".into()) };
        let number = |field: &str| whole.get(field).and_then(Value::as_u64).ok_or(format!("no number {field:?}"));
        let text = |field: &str| whole.get(field).and_then(Value::as_str).ok_or(format!("no text {field:?}"));
        let version = number("podssh-net")?;
        if version != VERSION {
            return Err(format!("a document of the form {version}, which this podssh does not read; podssh update"));
        }
        if let Some(requires) = whole.get("requires") {
            let parts = requires.as_array().ok_or("\"requires\" is not a list")?;
            for part in parts {
                let part = part.as_str().ok_or("\"requires\" holds a part that is not text")?;
                if !KNOWN_PARTS.contains(&part) {
                    return Err(format!(
                        "the document requires {part:?}, which this podssh does not read; podssh update, then take \
                         it again"
                    ));
                }
            }
        }
        let name = text("name")?.to_string();
        check_name(&name).map_err(|why| format!("the net's name {why}"))?;
        let serial = number("serial")?;
        if serial == 0 {
            return Err("the serial is 0; the first is 1".into());
        }
        let (issued, expires) = (number("issued")? as i64, number("expires")? as i64);
        if expires <= issued {
            return Err("the document ends before it was signed".into());
        }
        let owner = text("owner")?.to_string();
        podssh_ssh::russh::keys::PublicKey::from_openssh(&owner).map_err(|e| format!("the owner's key: {e}"))?;
        let list = whole.get("members").and_then(Value::as_array).ok_or("no list \"members\"")?;
        if list.len() > MAX_MEMBERS {
            return Err(format!("{} members, more than {MAX_MEMBERS}", list.len()));
        }
        let mut members: Vec<Member> = Vec::new();
        for item in list {
            let member = member_of(item)?;
            if members.iter().any(|m| m.name == member.name) {
                return Err(format!("two members are named {}", member.name));
            }
            if members.iter().any(|m| same_key(&m.key, &member.key)) {
                return Err(format!("{} has the key of another member", member.name));
            }
            members.push(member);
        }
        let policy = whole.get(policy::FIELD).map(Policy::read).transpose()?;
        Ok(Doc { name, serial, issued, expires, owner, members, policy, whole })
    }

    /// The document's bytes, as the owner signs them: one line of JSON, its
    /// keys in order, and a newline.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut text = serde_json::to_string(&Value::Object(self.whole.clone())).unwrap_or_default();
        text.push('\n');
        text.into_bytes()
    }

    /// The member of this name.
    pub fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == name)
    }

    /// The member of this key.
    pub fn member_of_key(&self, key: &podssh_relay::identity::PublicKey) -> Option<&Member> {
        self.members.iter().find(|m| m.key.matches(key))
    }

    /// A field of the document as it is, with what this podssh does not read.
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.whole.get(name)
    }

    /// The next document: the serial one higher, signed now, ending at
    /// `expires`, and `change` done to its members. Each field that this
    /// podssh does not know stays.
    pub fn next(&self, issued: i64, expires: i64, change: impl FnOnce(&mut Vec<Value>)) -> Result<Doc, String> {
        self.next_whole(issued, expires, |whole| {
            let mut list = whole.get("members").and_then(Value::as_array).cloned().unwrap_or_default();
            change(&mut list);
            whole.insert("members".into(), Value::Array(list));
        })
    }

    /// [`Doc::next`] with `change` done to the whole object: the policy's
    /// commands change a field beside the members.
    pub fn next_whole(
        &self,
        issued: i64,
        expires: i64,
        change: impl FnOnce(&mut Map<String, Value>),
    ) -> Result<Doc, String> {
        let mut whole = self.whole.clone();
        whole.insert("serial".into(), json!(self.serial + 1));
        whole.insert("issued".into(), json!(issued));
        whole.insert("expires".into(), json!(expires));
        change(&mut whole);
        let next = Doc::from_value(Value::Object(whole))?;
        let size = next.to_bytes().len();
        if size > MAX_DOC {
            return Err(format!("the document would have {size} bytes, more than {MAX_DOC}"));
        }
        Ok(next)
    }
}

/// A member's object, as `net add` writes it.
pub fn member_value(member: &Member) -> Value {
    let key = match &member.key {
        KeyName::Key(key) => key.hex(),
        KeyName::Fingerprint(print) => print.clone(),
    };
    let mut value = json!({ "name": member.name, "key": key, "roles": member.roles, "tickets": member.tickets });
    // Only an exit's, so that a member with none is written as before.
    if let (false, Some(object)) = (member.routes.is_empty(), value.as_object_mut()) {
        object.insert("routes".into(), json!(member.routes));
    }
    // Only a relay role's host, for the same reason (T-617).
    if let (Some(host), Some(object)) = (&member.relay, value.as_object_mut()) {
        object.insert("relay".into(), json!(host));
    }
    // Only a node's shares, for the same reason (T-433).
    if let (false, Some(object)) = (member.shares.is_empty(), value.as_object_mut()) {
        object.insert("shares".into(), json!(member.shares));
    }
    value
}

/// Whether two names of keys name one key; a key and a fingerprint are
/// compared by the fingerprint.
fn same_key(a: &KeyName, b: &KeyName) -> bool {
    a.fingerprint() == b.fingerprint()
}

/// One member, checked. A role or a kind of ticket that this podssh does
/// not know is kept and not used, as a later podssh may add one.
fn member_of(item: &Value) -> Result<Member, String> {
    let object = item.as_object().ok_or("a member that is not an object")?;
    let name = object.get("name").and_then(Value::as_str).ok_or("a member with no name")?;
    check_name(name).map_err(|why| format!("a member's name {why}"))?;
    let key = object.get("key").and_then(Value::as_str).ok_or(format!("{name} has no key"))?;
    let key = KeyName::parse(key).ok_or(format!("{name}: {key:?} is not a key nor a fingerprint"))?;
    let roles = match object.get("roles") {
        None => Vec::new(),
        Some(list) => list
            .as_array()
            .ok_or(format!("{name}: \"roles\" is not a list"))?
            .iter()
            .map(|r| r.as_str().map(str::to_string).ok_or(format!("{name}: a role that is not text")))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let mut tickets = BTreeMap::new();
    if let Some(found) = object.get("tickets") {
        let found = found.as_object().ok_or(format!("{name}: \"tickets\" is not an object"))?;
        for (kind, ticket) in found {
            let ticket = ticket.as_str().ok_or(format!("{name}: the ticket {kind} is not text"))?;
            tickets.insert(kind.clone(), ticket.to_string());
        }
    }
    let routes = texts(object, name, "routes", "a route")?;
    let relay = object
        .get("relay")
        .map(|host| host.as_str().map(str::to_string).ok_or(format!("{name}: \"relay\" is not text")))
        .transpose()?;
    let shares = texts(object, name, "shares", "a share")?;
    Ok(Member { name: name.to_string(), key, roles, tickets, routes, relay, shares })
}

/// The list of text `field` of the member `name`, each as it was written;
/// none when it is not there.
fn texts(object: &Map<String, Value>, name: &str, field: &str, one: &str) -> Result<Vec<String>, String> {
    let Some(list) = object.get(field) else { return Ok(Vec::new()) };
    let list = list.as_array().ok_or(format!("{name}: \"{field}\" is not a list"))?;
    list.iter().map(|r| r.as_str().map(str::to_string).ok_or(format!("{name}: {one} that is not text"))).collect()
}
