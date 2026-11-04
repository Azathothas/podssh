//! The owner's commands of `podssh net` (T-429): `init NAME`, `add NAME
//! KEY`, `rm NAME` and `renew`, and the policy's `set FILE` and `clear`
//! (T-430, `super::policy_cmd`). Each signs a new document with the owner's
//! key, its serial one higher than the one held, and keeps it in place of
//! that one; the owner then gives the file to the other ends, or lets the
//! ends of the net pass it on. The invitation by a code (T-616,
//! `super::invite`) adds its member by the change of `add`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use podssh_relay::identity::KeyName;
use serde_json::Value;

use super::doc::{self, Doc, Member};
use super::sign;
use super::{held, now, store, NetArgs};
use crate::exitmap::sysexits;
use crate::relay_settings::Refusal;

/// How long a document lasts when `--days` names nothing: a year, as a
/// tailnet's node keys need their owner again after some months.
const DAYS: i64 = 365;
/// The longest that `--days` gives: ten years.
const MAX_DAYS: i64 = 3650;

/// Run one of the owner's subcommands.
pub(super) fn run(word: &str, args: &NetArgs, err: &mut dyn Write) -> Result<i32, Refusal> {
    let days = days(args.days.as_deref())?;
    let (issued, key) = (now(), args.owner_key.as_deref().map(Path::new));
    let expires = issued + days * 86_400;
    if word == "init" {
        return init(&args.args[0], key, issued, expires, err);
    }
    let held = held()?;
    let before = &held.signed.doc;
    let (next, said) = match word {
        "add" => add(before, args, issued, expires)?,
        "rm" => rm(before, &args.args[0], issued, expires)?,
        "policy" => super::policy_cmd::change(before, args, issued, expires, err)?,
        _ => (before.next(issued, expires, |_| {}).map_err(data)?, "renewed".to_string()),
    };
    let signing = sign::signing_for(&before.owner, key).map_err(Refusal::config)?;
    let signed = sign::sign_with(&next, &signing).map_err(Refusal::config)?;
    let path = store::keep_own(&signed).map_err(|why| Refusal { message: why, code: sysexits::EX_CANTCREAT })?;
    let until = crate::pairs::utc(next.expires * 1000);
    let _ = writeln!(
        err,
        "podssh net: {said}: the net {}, serial {}, until {until}, in {}; give the file to each other end (podssh net \
         take FILE), or let the ends of the net pass it on",
        next.name,
        next.serial,
        path.display()
    );
    Ok(0)
}

/// `--days N`: 1 to [`MAX_DAYS`], else [`DAYS`].
pub(super) fn days(text: Option<&str>) -> Result<i64, Refusal> {
    let Some(text) = text else { return Ok(DAYS) };
    match text.parse::<i64>() {
        Ok(n) if (1..=MAX_DAYS).contains(&n) => Ok(n),
        _ => Err(Refusal::usage(format!("--days {text}: a number of days, 1 to {MAX_DAYS}"))),
    }
}

fn data(why: String) -> Refusal {
    Refusal { message: why, code: sysexits::EX_DATAERR }
}

/// `init NAME`: the first document, with no member, signed by the key of
/// `--owner-key`, else `~/.ssh/id_ed25519`.
fn init(name: &str, key: Option<&Path>, issued: i64, expires: i64, err: &mut dyn Write) -> Result<i32, Refusal> {
    doc::check_name(name).map_err(|why| Refusal::usage(format!("the net's name {why}")))?;
    if let Ok(Some(held)) = store::held() {
        return Err(Refusal::config(format!(
            "this host holds the net {} already ({}); {} names another file for another net",
            held.signed.doc.name,
            held.path.display(),
            store::ENV
        )));
    }
    let key: PathBuf = match key {
        Some(path) => path.to_path_buf(),
        None => default_key().ok_or_else(|| {
            Refusal::config(
                "no owner's key: name one with --owner-key FILE, or make ~/.ssh/id_ed25519 with podssh keygen -t \
                 ed25519",
            )
        })?,
    };
    let (owner, signing) = sign::owner_of(&key).map_err(Refusal::config)?;
    let first = Doc::new(name, &owner, issued, expires).map_err(Refusal::usage)?;
    let signed = sign::sign_with(&first, &signing).map_err(Refusal::config)?;
    let path = store::keep_own(&signed).map_err(|why| Refusal { message: why, code: sysexits::EX_CANTCREAT })?;
    let _ = writeln!(
        err,
        "podssh net: the net {name}, serial 1, of the owner {}, until {}, in {}; add its members with podssh net add \
         NAME KEY, or a device by a code with podssh net invite NAME",
        sign::owner_fingerprint(&owner),
        crate::pairs::utc(expires * 1000),
        path.display()
    );
    Ok(0)
}

/// `~/.ssh/id_ed25519`, when it is there.
fn default_key() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".ssh").join("id_ed25519")).filter(|path| path.exists())
}

/// `add NAME KEY`: the member, or a new key, roles or tickets of one.
fn add(before: &Doc, args: &NetArgs, issued: i64, expires: i64) -> Result<(Doc, String), Refusal> {
    let (name, word) = (&args.args[0], &args.args[1]);
    doc::check_name(name).map_err(|why| Refusal::usage(format!("the member's name {why}")))?;
    let key = KeyName::parse(word).ok_or_else(|| {
        Refusal::usage(format!(
            "{word:?} is not a key (64 hex digits, or iroh's base32) nor a fingerprint (SHA256:...): a node says its \
             key as it starts"
        ))
    })?;
    not_auto(name)?;
    let roles = doc::parse_roles(args.roles.as_deref().unwrap_or("node")).map_err(Refusal::usage)?;
    let routes = routes(args.routes.as_deref(), &roles)?;
    let mut tickets = BTreeMap::new();
    if let Some(text) = &args.derp_ticket {
        let ticket =
            podssh_relay::derp::Ticket::parse(text).map_err(|why| Refusal::usage(format!("--derp-ticket: {why}")))?;
        if !key.matches(&ticket.node) {
            return Err(Refusal::usage(format!("--derp-ticket names the node {}, not {key}", ticket.node)));
        }
        tickets.insert("derp".to_string(), ticket.to_string());
    }
    if let Some(text) = &args.iroh_ticket {
        iroh_names(text, &key)?;
        tickets.insert("iroh".to_string(), text.clone());
    }
    with_member(before, &Member { name: name.clone(), key, roles, tickets, routes }, issued, expires)
}

/// The next document, with `member` added or in the place of the member of
/// its name, and what to say of it.
pub(super) fn with_member(before: &Doc, member: &Member, issued: i64, expires: i64) -> Result<(Doc, String), Refusal> {
    let name = member.name.as_str();
    let said = match before.member(name) {
        Some(_) => format!("replaced the member {name}"),
        None => format!("added the member {name}"),
    };
    let value = doc::member_value(member);
    let next = before.next(issued, expires, |list: &mut Vec<Value>| {
        list.retain(|m| m.get("name").and_then(Value::as_str) != Some(name));
        list.push(value);
    });
    Ok((next.map_err(data)?, said))
}

/// A member's name that is not `auto`, the word of `--exit auto` (T-432):
/// `net add` and `net invite`.
pub(super) fn not_auto(name: &str) -> Result<(), Refusal> {
    match name == crate::exit::auto::AUTO {
        true => Err(Refusal::usage(format!(
            "the member's name {name:?} is the word of --exit auto, which finds the exit by the net's routes: name the \
             member otherwise"
        ))),
        false => Ok(()),
    }
}

/// `--routes RANGES` of `add` (T-432): each a range, as the exit's own
/// `--routes` reads it, and only for a member with the role exit, as no other
/// dials an address for the net.
fn routes(text: Option<&str>, roles: &[String]) -> Result<Vec<String>, Refusal> {
    let Some(text) = text else { return Ok(Vec::new()) };
    if !roles.iter().any(|role| role == "exit") {
        return Err(Refusal::usage("--routes names the private ranges of an exit: give --roles with exit too"));
    }
    let mut words: Vec<String> = Vec::new();
    for word in text.split(',').map(str::trim) {
        if super::policy_words::Range::parse(word).is_none() {
            return Err(Refusal::usage(format!(
                "--routes {text}: {word:?} is not a range: ADDR/BITS or one address, separated by commas"
            )));
        }
        if !words.iter().any(|w| w == word) {
            words.push(word.to_string());
        }
    }
    Ok(words)
}

/// `rm NAME`: the member gone; each end that holds the new document
/// refuses it at its next session.
fn rm(before: &Doc, name: &str, issued: i64, expires: i64) -> Result<(Doc, String), Refusal> {
    if before.member(name).is_none() {
        return Err(Refusal::usage(format!("the net {} has no member {name}", before.name)));
    }
    let next = before.next(issued, expires, |list: &mut Vec<Value>| {
        list.retain(|m| m.get("name").and_then(Value::as_str) != Some(name));
    });
    Ok((next.map_err(data)?, format!("removed the member {name}")))
}

/// An iroh ticket that names the member's key, in a build with the road;
/// without it, the ticket is kept unread, for the ends that have the road.
#[cfg(feature = "iroh")]
fn iroh_names(text: &str, key: &KeyName) -> Result<(), Refusal> {
    let addr = podssh_iroh::ticket::parse(text).map_err(|why| Refusal::usage(format!("--iroh-ticket: {why}")))?;
    let node = podssh_iroh::keys::identity_key(&addr.id);
    match key.matches(&node) {
        true => Ok(()),
        false => Err(Refusal::usage(format!("--iroh-ticket names the node {node}, not {key}"))),
    }
}

#[cfg(not(feature = "iroh"))]
fn iroh_names(_: &str, _: &KeyName) -> Result<(), Refusal> {
    Ok(())
}
