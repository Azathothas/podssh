//! The net's policy (T-430): who may reach which node, which route of it (a
//! share, T-433, is reached as a route), which exit (T-431) and which range
//! of routes (T-432), as the owner signs it in the net's document. The model
//! is Tailscale's ACLs: rules, each from members or tags to what they may
//! reach, and nothing else once a policy is there; with no policy at all,
//! each member reaches each other, as Tailscale's default policy lets each
//! device reach each.
//!
//! The node that is reached checks it, for each session, with the newest
//! document that it holds (`super::admit`); a relay never decides. A rule
//! only allows, so a word or a field of a rule that this podssh does not
//! read allows nothing here: an end never lets in more than the owner wrote.
//! A later podssh whose part narrows a rule names that part in the
//! document's `requires`, so that this one refuses the document instead of
//! skipping the part.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use serde_json::Value;

use super::doc::{check_name, Doc, Member};
use super::policy_words::{Dest, Src};

/// The document's field, and the part of `requires` that names it.
pub const FIELD: &str = "policy";
pub const PART: &str = "policy";
/// The fields of the policy that this podssh reads.
const POLICY_FIELDS: &[&str] = &["rules", "tags"];
/// The fields of a rule that this podssh reads.
const RULE_FIELDS: &[&str] = &["from", "to", "note"];
/// The forms of a word of `from` and of `to`, as a refusal names them.
const FROM_FORMS: &str = "*, a member's name or tag:TAG";
const TO_FORMS: &str = "*, NODE, NODE/ROUTE, tag:TAG, exit:NODE, exit:* or a range ADDR/BITS";

/// One rule: from these members or tags, to these nodes, routes, exits or
/// ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub from: Vec<String>,
    pub to: Vec<String>,
    /// The owner's words for the rule, which a check shows.
    pub note: Option<String>,
    /// The fields that this podssh does not read: a rule with one allows
    /// nothing here, as the field may narrow it.
    pub unread: Vec<String>,
}

/// The policy of a document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub rules: Vec<Rule>,
    /// Each tag, and the names of its members.
    pub tags: BTreeMap<String, Vec<String>>,
}

/// What a member asks to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want<'a> {
    /// `node://NODE`, its target with no route, or `node://NODE/ROUTE`.
    Node { node: &'a str, route: Option<&'a str> },
    /// Anything of the node: the door of a road before the channel, which
    /// knows no route yet.
    AnyOf(&'a str),
    /// The node's egress (T-431).
    Exit(&'a str),
    /// An address of a range of routes (T-432).
    Addr(IpAddr),
}

impl fmt::Display for Want<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Want::Node { node, route: None } => f.write_str(node),
            Want::Node { node, route: Some(route) } => write!(f, "{node}/{route}"),
            Want::AnyOf(node) => write!(f, "any service of {node}"),
            Want::Exit(node) => write!(f, "exit:{node}"),
            Want::Addr(addr) => write!(f, "{addr}"),
        }
    }
}

impl Policy {
    /// The policy of the document's field, checked for its form only: a
    /// rule's words and its other fields are read when it is used, so that
    /// a later podssh's word allows nothing here and refuses nothing.
    pub fn read(value: &Value) -> Result<Policy, String> {
        let object = value.as_object().ok_or("the policy is not a JSON object")?;
        let rules: Vec<Rule> = match object.get("rules") {
            None => Vec::new(),
            Some(list) => {
                let list = list.as_array().ok_or("the policy's \"rules\" is not a list")?;
                list.iter().enumerate().map(|(i, rule)| rule_of(i + 1, rule)).collect::<Result<_, String>>()?
            }
        };
        let mut tags = BTreeMap::new();
        if let Some(found) = object.get("tags") {
            let found = found.as_object().ok_or("the policy's \"tags\" is not an object")?;
            for (tag, names) in found {
                tags.insert(tag.clone(), texts(names, &format!("the policy's tag {tag}"))?);
            }
        }
        Ok(Policy { rules, tags })
    }

    /// Whether the tag holds the member of this name.
    pub fn tagged(&self, tag: &str, name: &str) -> bool {
        self.tags.get(tag).is_some_and(|names| names.iter().any(|n| n == name))
    }
}

/// A list of words, each text.
fn texts(value: &Value, what: &str) -> Result<Vec<String>, String> {
    let list = value.as_array().ok_or(format!("{what} is not a list"))?;
    let word = |w: &Value| w.as_str().map(str::to_string).ok_or(format!("{what} holds a word that is not text"));
    list.iter().map(word).collect()
}

/// The rule of number `n`, checked for its form.
fn rule_of(n: usize, value: &Value) -> Result<Rule, String> {
    let object = value.as_object().ok_or(format!("the policy's rule {n} is not an object"))?;
    let words = |field: &str| match object.get(field) {
        None => Ok(Vec::new()),
        Some(list) => texts(list, &format!("the {field:?} of rule {n}")),
    };
    let note = match object.get("note") {
        None => None,
        Some(text) => Some(text.as_str().ok_or(format!("the \"note\" of rule {n} is not text"))?.to_string()),
    };
    let unread = object.keys().filter(|k| !RULE_FIELDS.contains(&k.as_str())).cloned().collect();
    Ok(Rule { from: words("from")?, to: words("to")?, note, unread })
}

impl Rule {
    /// Whether this rule lets the member `from` reach `want`.
    fn lets(&self, policy: &Policy, from: &str, want: Want<'_>) -> bool {
        self.unread.is_empty()
            && self.from.iter().any(|w| Src::parse(w).holds(policy, from))
            && self.to.iter().any(|w| Dest::parse(w).reaches(policy, want))
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "from {} to {}", self.from.join(", "), self.to.join(", "))?;
        match &self.note {
            Some(note) => write!(f, " ({note})"),
            None => Ok(()),
        }
    }
}

/// Whether `doc` lets its member `from` reach `want`: `Ok` names the rule
/// that lets it, `Err` says why not, in the policy's words.
pub fn check(doc: &Doc, from: &Member, want: Want<'_>) -> Result<String, String> {
    let Some(policy) = &doc.policy else {
        return Ok(format!("the net {} has no policy, so each member reaches each", doc.name));
    };
    let (net, serial, name) = (&doc.name, doc.serial, &from.name);
    match policy.rules.iter().position(|rule| rule.lets(policy, name, want)) {
        Some(at) => Ok(format!("rule {} of the net {net}'s policy (serial {serial}): {}", at + 1, policy.rules[at])),
        None => Err(format!("no rule of the net {net}'s policy (serial {serial}) lets {name} reach {want}")),
    }
}

/// A policy that the owner sets, checked strictly, against the members of
/// `doc`: each field one that this podssh reads, each word of a form that it
/// reads, each tag defined. A name that no member has is said, not refused,
/// as its member may come later. The policy, and what to say.
pub fn checked(value: &Value, doc: &Doc) -> Result<(Policy, Vec<String>), String> {
    let object = value.as_object().ok_or("the policy is not a JSON object of \"rules\" and \"tags\"")?;
    if let Some(field) = object.keys().find(|k| !POLICY_FIELDS.contains(&k.as_str())) {
        return Err(format!("the policy's field {field:?} is not one that podssh reads: rules and tags"));
    }
    if !object.contains_key("rules") {
        let why = "the policy has no \"rules\": a list of rules, or [] for none; podssh net policy clear removes it";
        return Err(why.into());
    }
    let policy = Policy::read(value)?;
    let mut said: Vec<String> = Vec::new();
    // A name that no member has is said, not refused: a typing error, or a
    // member to come.
    let unknown = |name: &str, what: String| {
        doc.member(name).is_none().then(|| format!("{what}, but the net {} has no member {name}", doc.name))
    };
    for (tag, names) in &policy.tags {
        check_name(tag).map_err(|why| format!("the tag {why}"))?;
        for name in names {
            check_name(name).map_err(|why| format!("the tag {tag}: a member's name {why}"))?;
            said.extend(unknown(name, format!("the tag {tag} holds {name}")));
        }
    }
    for (i, rule) in policy.rules.iter().enumerate() {
        let n = i + 1;
        let undefined = |tag: &str| format!("rule {n}: the tag {tag} is not in the policy's \"tags\"");
        if let Some(field) = rule.unread.first() {
            return Err(format!("rule {n}: the field {field:?} is not one that podssh reads: from, to and note"));
        }
        if rule.from.is_empty() || rule.to.is_empty() {
            return Err(format!("rule {n} needs a \"from\" and a \"to\", each a list of one word or more"));
        }
        for word in &rule.from {
            match Src::parse(word) {
                Src::Unknown => return Err(format!("rule {n}: {word:?} is not who a rule is from: {FROM_FORMS}")),
                Src::Tag(tag) if !policy.tags.contains_key(tag) => return Err(undefined(tag)),
                Src::Member(name) => said.extend(unknown(name, format!("rule {n} is from {name}"))),
                Src::All | Src::Tag(_) => {}
            }
        }
        for word in &rule.to {
            let what = format!("rule {n} reaches {word}");
            match Dest::parse(word) {
                Dest::Unknown => return Err(format!("rule {n}: {word:?} is not what a rule reaches: {TO_FORMS}")),
                Dest::Tag(tag) if !policy.tags.contains_key(tag) => return Err(undefined(tag)),
                Dest::Node(name) | Dest::Route(name, _) => said.extend(unknown(name, what)),
                Dest::Exit(Some(name)) => said.extend(exit_named(doc, name, what)),
                Dest::All | Dest::Tag(_) | Dest::Exit(None) | Dest::Range(_) => {}
            }
        }
    }
    if policy.rules.is_empty() {
        said.push("the policy has no rule, so no member reaches another".into());
    }
    Ok((policy, said))
}

/// What to say of a rule that reaches `exit:NAME`: a name that no member
/// has, or a member with no role `exit`, which T-431's node checks.
fn exit_named(doc: &Doc, name: &str, what: String) -> Option<String> {
    match doc.member(name) {
        None => Some(format!("{what}, but the net {} has no member {name}", doc.name)),
        Some(member) if !member.has_role("exit") => Some(format!("{what}, but {name} has no role exit")),
        Some(_) => None,
    }
}
