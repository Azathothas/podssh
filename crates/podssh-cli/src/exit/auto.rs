//! `--exit auto` (T-432): the exit of a target is the member of the net
//! whose routes hold its address, as a Tailscale client sends an address of
//! a subnet to the router that advertises it. The owner lists each exit's
//! routes in the net's document (`podssh net add NAME KEY --roles node,exit
//! --routes RANGES`); the narrowest range that holds the address wins, then
//! the first member by name, so that each end of the net picks the same one.
//!
//! The target must be an address. A name is resolved at the exit, and a
//! private name (split DNS) may resolve there to an address that this host
//! cannot see, or to another one: this host's answer would pick a node by
//! an address that the node never dials.

use std::net::IpAddr;

use crate::net::doc::Doc;
use crate::relay_settings::Refusal;

/// The word of `--exit` that asks for the exit of each target.
pub const AUTO: &str = "auto";

/// Whether `--exit` named [`AUTO`].
pub fn is_auto(name: &str) -> bool {
    name == AUTO
}

/// The exit that `--exit auto` takes for an address, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picked {
    pub name: String,
    /// The route of the exit that holds the address, as the owner wrote it.
    pub range: String,
    /// The other exits whose routes hold it too, in the order of the pick.
    pub also: Vec<String>,
}

impl Picked {
    /// The line that says the pick, for `addr`.
    pub fn line(&self, addr: &str) -> String {
        let also = match self.also.is_empty() {
            true => String::new(),
            false => format!("; a route of {} holds it too", self.also.join(", ")),
        };
        format!("--exit auto: {addr} is in {}, a route of the exit {}{also}", self.range, self.name)
    }
}

/// The exit's name: `name`, or for [`AUTO`] the member whose routes hold
/// `host`.
pub fn name_for(name: &str, host: &str) -> Result<String, Refusal> {
    match is_auto(name) {
        true => pick(host).map(|picked| picked.name),
        false => Ok(name.to_string()),
    }
}

/// The flags that name one exit, which go with no auto: the file of one
/// pair, and a carrier, whose other end is one node (64).
pub fn flags(name: &str, pair_file: Option<&str>, carrier: Option<&str>) -> Result<(), Refusal> {
    if !is_auto(name) {
        return Ok(());
    }
    if pair_file.is_some() {
        return Err(Refusal::usage(
            "--pair-file names the pair of one exit, and --exit auto finds the exit of each target by the net's \
             routes: name the exit with --exit NAME",
        ));
    }
    if carrier.is_some() {
        return Err(Refusal::usage(
            "--carrier names the node at the stream's other end, and --exit auto finds the exit of each target by \
             the net's routes: name the exit with --exit NAME",
        ));
    }
    Ok(())
}

/// The exit of `host`: the member of the net held here whose routes hold
/// its address.
pub fn pick(host: &str) -> Result<Picked, Refusal> {
    let addr = address(host)?;
    let held = crate::net::held()?;
    let doc = &held.signed.doc;
    if doc.expires <= crate::net::now() {
        let ended = crate::pairs::utc(doc.expires * 1000);
        return Err(Refusal::config(format!(
            "--exit auto: the net {}'s document (serial {}) ended at {ended}; its owner renews it with podssh net renew",
            doc.name, doc.serial
        )));
    }
    pick_in(doc, addr).map_err(Refusal::config)
}

/// The address of `host`, an IPv6 one with or without its brackets.
fn address(host: &str) -> Result<IpAddr, Refusal> {
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    bare.parse().map_err(|_| {
        Refusal::usage(format!(
            "--exit auto finds the exit by the target's address, and {host} is a name, which the exit resolves \
             itself and may resolve otherwise: give the address, or name the exit with --exit NAME"
        ))
    })
}

/// The exit of `addr` in `doc`: of the members with the role exit, the one
/// whose narrowest route holds it, then the first by name.
pub(crate) fn pick_in(doc: &Doc, addr: IpAddr) -> Result<Picked, String> {
    let mut found: Vec<(u8, &str, &str)> = Vec::new();
    for member in doc.members.iter().filter(|m| m.has_role("exit")) {
        let holding = member.ranges().into_iter().filter(|(_, range)| range.contains(addr));
        if let Some((word, range)) = holding.max_by_key(|(_, range)| range.bits()) {
            found.push((range.bits(), member.name.as_str(), word));
        }
    }
    found.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    let Some(&(_, name, word)) = found.first() else {
        return Err(format!(
            "--exit auto: no exit of the net {} (serial {}) routes {addr}: its owner names an exit's ranges with \
             podssh net add NAME KEY --roles node,exit --routes RANGES, or name the exit with --exit NAME",
            doc.name, doc.serial
        ));
    };
    let also = found[1..].iter().map(|(_, other, _)| other.to_string()).collect();
    Ok(Picked { name: name.to_string(), range: word.to_string(), also })
}

#[cfg(test)]
#[path = "auto_tests.rs"]
mod tests;
