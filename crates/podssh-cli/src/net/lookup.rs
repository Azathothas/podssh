//! A member's name (T-429), as MagicDNS names a host of its tailnet:
//! `node://NAME`, and `podssh ssh NAME` alone, look NAME up in the net
//! first. The net names the member's key, which the end-to-end channel then
//! checks in place of the pins, and its tickets, which race beside the pair
//! kept under NAME when the command line gives none. A name has no dot, so
//! no DNS name is a member's; a fault of the net's file names nothing, and
//! the destination is read as before.

use podssh_relay::derp::Ticket;

use super::doc::{check_name, Member};
use super::store;

/// The member named `name`, of the document held.
pub fn member(name: &str) -> Option<Member> {
    if !store::on() || check_name(name).is_err() {
        return None;
    }
    store::held_or_none()?.signed.doc.member(name).cloned()
}

/// `[user@]NAME`, where NAME is a member with the role `node`: the user and
/// the name, which the caller reads as `node://[user@]NAME`. A word with a
/// dot, a colon, a slash or a bracket is a host, never a member.
pub fn bare(text: &str) -> Option<(Option<String>, String)> {
    let (user, name) = match text.rsplit_once('@') {
        Some((user, name)) if !user.is_empty() => (Some(user.to_string()), name),
        Some(_) => return None,
        None => (None, text),
    };
    if name.contains(['.', ':', '/', '[', ']']) {
        return None;
    }
    member(name).filter(|m| m.has_role("node")).map(|m| (user, m.name))
}

/// The member's ticket of `kind`, as the owner wrote it.
pub fn ticket(name: &str, kind: &str) -> Option<String> {
    member(name)?.tickets.get(kind).cloned()
}

/// The member's DERP ticket, when it reads as one and names the member's
/// own key: a ticket of another node is never dialled for this name.
pub fn derp_ticket(name: &str) -> Option<Ticket> {
    let member = member(name)?;
    let ticket = Ticket::parse(member.tickets.get("derp")?).ok()?;
    member.key.matches(&ticket.node).then_some(ticket)
}

/// The check of a node's key by the net: `None` when the net does not name
/// `label`; else whether `key` is the member's, and why not.
pub fn check_key(label: &str, key: &podssh_relay::identity::PublicKey) -> Option<Result<(), String>> {
    let member = member(label)?;
    Some(match member.key.matches(key) {
        true => Ok(()),
        false => Err(format!(
            "the node has the key {key}, but the net's document names {label} with the key {}; if the node's key \
             changed on purpose, its owner gives it in the net (podssh net add {label} KEY); else something on the \
             way may stand in the middle",
            member.key
        )),
    })
}
