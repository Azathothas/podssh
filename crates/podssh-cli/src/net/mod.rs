//! `podssh net` (T-429): the net of a user's own nodes, at parity with a
//! tailnet but with no server to trust. A net is one document that the
//! owner's key signs (`doc`, `sign`): its members, each with a name, an
//! Ed25519 key, its roles and its tickets; a serial and an end. Each end
//! keeps the newest document that it was given (`store`) and takes another
//! only with the owner's signature and a higher serial; two ends of the net
//! give each other the newer one inside the end-to-end channel (`admit`).
//! A node that is a member lets in the members (`admit`), and a member's
//! name is a destination (`lookup`); a relay role mints for the members
//! (`mint`, T-455).
//!
//! The owner's commands (`edit`): `init NAME`, `add NAME KEY`, `rm NAME`,
//! `renew`, `policy set FILE` and `policy clear`; each signs a document with
//! a higher serial. Each end's: `ls`, `show`, `take FILE`, `policy show` and
//! `policy check FROM TO` (T-430, `policy`), which says what the policy lets
//! with no connection. A new device joins by a short code (T-616): the
//! owner's `invite NAME` signs its key in as `add` would, and the device's
//! `join` takes the document as `take` does (`invite`, `join`,
//! `invitation`). stdout carries the answer (a list, a document, a verdict);
//! podssh's words go to stderr. `podssh status --net` lists the members and
//! the road that last reached each from this host (`state`, `reached`).

pub mod admit;
pub mod doc;
mod edit;
mod invitation;
mod invite;
mod join;
pub mod lookup;
pub mod mint;
pub mod policy;
mod policy_cmd;
pub(crate) mod policy_words;
// The road that last reached each node, and the net in `podssh status` (T-435).
pub mod reached;
pub mod sign;
pub mod state;
pub mod store;

use std::io::Write;
use std::path::Path;

use clap::ArgMatches;
use podssh_relay::identity::KeyName;

use crate::exitmap::sysexits;
use crate::relay_settings::Refusal;

/// What `podssh net` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetArgs {
    pub subcommand: Option<String>,
    pub args: Vec<String>,
    /// `--owner-key FILE`: the owner's key that signs.
    pub owner_key: Option<String>,
    /// `--roles LIST` of `add`.
    pub roles: Option<String>,
    /// `--iroh-ticket` and `--derp-ticket` of `add`: the member's roads.
    pub iroh_ticket: Option<String>,
    pub derp_ticket: Option<String>,
    /// `--routes RANGES` of `add`: an exit's private ranges (T-432).
    pub routes: Option<String>,
    /// `--relay-host HOST[:PORT]` of `add`: where a relay role serves its
    /// signed list (T-617).
    pub relay_host: Option<String>,
    /// `--days N`: how long a document that the owner signs lasts.
    pub days: Option<String>,
    /// `--owner KEY` of `take` and `join`: the owner that a first document
    /// must have.
    pub owner: Option<String>,
    /// `--signature` of `show`: the signature in place of the document.
    pub signature: bool,
    /// `--pair-mailbox URLS` of `invite` and `join`: where the two ends meet.
    pub pair_mailbox: Option<String>,
    /// `--key FILE` of `join`: the device's key, the member's.
    pub key: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl NetArgs {
    /// The arguments of `net` in `matches`.
    pub fn from_matches(matches: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> NetArgs {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        NetArgs {
            subcommand: get("subcommand"),
            args: matches.get_many::<String>("args").map(|v| v.cloned().collect()).unwrap_or_default(),
            owner_key: get("owner-key"),
            roles: get("roles"),
            iroh_ticket: get("iroh-ticket"),
            derp_ticket: get("derp-ticket"),
            routes: get("routes"),
            relay_host: get("relay-host"),
            days: get("days"),
            owner: get("owner"),
            signature: matches.get_flag("signature"),
            pair_mailbox: get("pair-mailbox"),
            key: get("key"),
            refused,
        }
    }
}

/// Seconds since 1970, now.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The subcommands, as a refusal names them.
const SUBCOMMANDS: &str = "init, add, rm, renew, invite, join, ls, show, take or policy";

/// Run the verb; returns the process exit code.
pub fn run(args: &NetArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let word = match checked(args) {
        Ok(word) => word,
        Err(refusal) => return refusal.report("net", err),
    };
    match dispatch(word, args, out, err) {
        Ok(code) => code,
        Err(refusal) => refusal.report("net", err),
    }
}

fn dispatch(word: &str, args: &NetArgs, out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, Refusal> {
    match word {
        "init" | "add" | "rm" | "renew" => edit::run(word, args, err),
        "policy" if policy_cmd::signs(&args.args) => edit::run(word, args, err),
        "policy" => policy_cmd::run(args, out, err),
        "invite" => invite::run(args, out, err),
        "join" => join::run(args, out, err),
        "ls" => ls(out, err),
        "show" => show(args.signature, out, err),
        "take" => take(&args.args[0], args.owner.as_deref(), err),
        _ => unreachable!("checked() knows each subcommand"),
    }
}

/// The subcommand, its count of words and its flags, checked before anything
/// is read.
fn checked(args: &NetArgs) -> Result<&str, Refusal> {
    let word =
        args.subcommand.as_deref().ok_or_else(|| Refusal::usage(format!("missing SUBCOMMAND: {SUBCOMMANDS}")))?;
    let (words, shape) = match word {
        "init" => (1, "init NAME"),
        "add" => (2, "add NAME KEY"),
        "rm" => (1, "rm NAME"),
        "take" => (1, "take FILE"),
        "invite" => (1, "invite NAME"),
        "renew" | "join" | "ls" | "show" => (0, word),
        "policy" => policy_cmd::shape(&args.args)?,
        other => return Err(Refusal::usage(format!("{other:?} is not a subcommand: {SUBCOMMANDS}"))),
    };
    if args.args.len() != words {
        return Err(Refusal::usage(format!("podssh net {shape}: {} words given", args.args.len())));
    }
    // Each flag goes with the subcommands that read it; `policy` by its verb.
    let form = match (word, args.args.first()) {
        ("policy", Some(verb)) => format!("policy {verb}"),
        _ => word.to_string(),
    };
    let signing: &[&str] = &["init", "add", "rm", "renew", "invite", "policy set", "policy clear"];
    let flags: [(&str, bool, &[&str]); 11] = [
        ("--owner-key", args.owner_key.is_some(), signing),
        ("--days", args.days.is_some(), signing),
        ("--roles", args.roles.is_some(), &["add", "invite"]),
        ("--iroh-ticket", args.iroh_ticket.is_some(), &["add"]),
        ("--derp-ticket", args.derp_ticket.is_some(), &["add"]),
        ("--routes", args.routes.is_some(), &["add"]),
        ("--relay-host", args.relay_host.is_some(), &["add"]),
        ("--owner", args.owner.is_some(), &["take", "join"]),
        ("--signature", args.signature, &["show"]),
        ("--pair-mailbox", args.pair_mailbox.is_some(), &["invite", "join"]),
        ("--key", args.key.is_some(), &["join"]),
    ];
    if let Some((flag, _, with)) = flags.iter().find(|(_, given, with)| *given && !with.contains(&form.as_str())) {
        return Err(Refusal::usage(format!("{flag} is for podssh net {}", with.join(", "))));
    }
    if !store::on() {
        let why = store::place().err().unwrap_or_else(|| format!("{}=no: the net is off", store::ENV));
        return Err(Refusal::config(why));
    }
    Ok(word)
}

/// The document held, or the remedy.
pub(crate) fn held() -> Result<store::Held, Refusal> {
    match store::held() {
        Ok(Some(held)) => Ok(held),
        Ok(None) => Err(Refusal::config(
            "this host holds no net: its owner makes one with podssh net init NAME, and each other end takes it \
             with podssh net take FILE, or joins it by a code with podssh net join",
        )),
        Err(why) => Err(Refusal { message: why, code: sysexits::EX_DATAERR }),
    }
}

/// The net in one line, for stderr.
pub(crate) fn summary(held: &store::Held) -> String {
    let doc = &held.signed.doc;
    let state = if doc.expires <= now() { "ended" } else { "until" };
    format!(
        "the net {}, serial {}, of the owner {}, {state} {}, {} members ({})",
        doc.name,
        doc.serial,
        sign::owner_fingerprint(&doc.owner),
        crate::pairs::utc(doc.expires * 1000),
        doc.members.len(),
        held.path.display()
    )
}

/// `ls`: one line for each member, its name, roles, key and tickets, apart
/// by tabs.
fn ls(out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, Refusal> {
    let held = held()?;
    let _ = writeln!(err, "podssh net: {}", summary(&held));
    for member in &held.signed.doc.members {
        let tickets: Vec<&str> = member.tickets.keys().map(String::as_str).collect();
        let tickets = if tickets.is_empty() { "-".to_string() } else { tickets.join(",") };
        let roles = if member.roles.is_empty() { "-".to_string() } else { member.roles.join(",") };
        let _ = writeln!(out, "{}\t{roles}\t{}\t{tickets}", member.name, member.key.fingerprint());
    }
    Ok(0)
}

/// `show`: the document's bytes as the owner signed them, or its signature,
/// so that `ssh-keygen -Y verify` checks the two.
fn show(signature: bool, out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, Refusal> {
    let held = held()?;
    let _ = writeln!(err, "podssh net: {}", summary(&held));
    let body = if signature { held.signed.signature.as_bytes() } else { &held.signed.bytes[..] };
    let _ = out.write_all(body);
    Ok(0)
}

/// `take FILE`: a document that the owner signed, kept when the rule of
/// `store::take` allows it.
fn take(file: &str, owner: Option<&str>, err: &mut dyn Write) -> Result<i32, Refusal> {
    let owner = owner.map(owner_named).transpose()?;
    let path = Path::new(file);
    if !path.exists() {
        return Err(Refusal { message: format!("{file}: no such file"), code: sysexits::EX_NOINPUT });
    }
    let signed = sign::read_file(path).map_err(|why| Refusal { message: why, code: sysexits::EX_DATAERR })?;
    let doc = &signed.doc;
    let owner_shown = sign::owner_fingerprint(&doc.owner);
    match store::take(&signed, owner.as_ref(), now()) {
        Ok(store::Taken::Kept { path, before }) => {
            let before = match before {
                Some(serial) => format!(" in place of serial {serial}"),
                None => format!(", the first of this host: its owner {owner_shown} signs each later one"),
            };
            let _ = writeln!(
                err,
                "podssh net: took the net {}, serial {}{before}, in {}",
                doc.name,
                doc.serial,
                path.display()
            );
            Ok(0)
        }
        Ok(store::Taken::Same) => {
            let _ = writeln!(err, "podssh net: this host holds the net {}'s serial {} already", doc.name, doc.serial);
            Ok(0)
        }
        Err(why) => Err(Refusal { message: format!("{file}: not taken: {why}"), code: sysexits::EX_DATAERR }),
    }
}

/// The owner of `--owner KEY`: its fingerprint, or its OpenSSH public key.
pub(super) fn owner_named(text: &str) -> Result<KeyName, Refusal> {
    KeyName::parse(text).or_else(|| owner_key_name(text)).ok_or_else(|| {
        Refusal::usage(format!("--owner {text:?}: not a key's fingerprint (SHA256:...) nor an OpenSSH public key"))
    })
}

/// An OpenSSH public key line, as the name of its fingerprint.
fn owner_key_name(text: &str) -> Option<KeyName> {
    let key = podssh_ssh::russh::keys::PublicKey::from_openssh(text.trim()).ok()?;
    KeyName::parse(&podssh_ssh::known_hosts::fingerprint(&key))
}

#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod tests;
