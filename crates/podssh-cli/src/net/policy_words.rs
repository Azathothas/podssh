//! The words of a rule of the net's policy (T-430), read when a rule is
//! used. `from`: `*` (each member), a member's name, or `tag:TAG`. `to`:
//! `*` (each node, route, exit and range), `NODE` (its target with no route
//! and each of its routes, as Tailscale's `host:*`), `NODE/ROUTE` (one route,
//! as `node://NODE/ROUTE` reaches it), `tag:TAG` (each member of the tag, as
//! `NODE`), `exit:NODE` and `exit:*` (an egress, T-431), `relay:NODE` and
//! `relay:*` (a relay role's mint, T-455), and a range `ADDR/BITS` or one
//! address (the routes of T-432). A word of no such form reaches nothing, so
//! that a later podssh's word lets in nobody here.

use std::net::IpAddr;

use super::doc::check_name;
use super::policy::{Policy, Want};

/// Who a rule is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Src<'a> {
    All,
    Member(&'a str),
    Tag(&'a str),
    Unknown,
}

impl<'a> Src<'a> {
    pub fn parse(word: &'a str) -> Src<'a> {
        if word == "*" {
            return Src::All;
        }
        match word.strip_prefix("tag:") {
            Some(tag) if check_name(tag).is_ok() => Src::Tag(tag),
            None if check_name(word).is_ok() => Src::Member(word),
            _ => Src::Unknown,
        }
    }

    /// Whether the member of this name is one that the word names.
    pub fn holds(&self, policy: &Policy, name: &str) -> bool {
        match *self {
            Src::All => true,
            Src::Member(member) => member == name,
            Src::Tag(tag) => policy.tagged(tag, name),
            Src::Unknown => false,
        }
    }
}

/// What a rule reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dest<'a> {
    All,
    Node(&'a str),
    Route(&'a str, &'a str),
    Tag(&'a str),
    /// `exit:NODE`, or `exit:*` (none named).
    Exit(Option<&'a str>),
    /// `relay:NODE`, the relay role of that node, or `relay:*`, each relay
    /// of the net, a role that is no member too (T-455).
    Relay(Option<&'a str>),
    Range(Range),
    Unknown,
}

impl<'a> Dest<'a> {
    pub fn parse(word: &'a str) -> Dest<'a> {
        if word == "*" {
            return Dest::All;
        }
        if let Some(tag) = word.strip_prefix("tag:") {
            return if check_name(tag).is_ok() { Dest::Tag(tag) } else { Dest::Unknown };
        }
        if let Some(node) = word.strip_prefix("exit:") {
            return match node {
                "*" => Dest::Exit(None),
                _ if check_name(node).is_ok() => Dest::Exit(Some(node)),
                _ => Dest::Unknown,
            };
        }
        if let Some(node) = word.strip_prefix("relay:") {
            return match node {
                "*" => Dest::Relay(None),
                _ if check_name(node).is_ok() => Dest::Relay(Some(node)),
                _ => Dest::Unknown,
            };
        }
        if let Some(range) = Range::parse(word) {
            return Dest::Range(range);
        }
        // A member's name has no dot and no colon, so an address is never
        // read as one.
        match word.split_once('/') {
            Some((node, route)) if check_name(node).is_ok() && podssh_ws::names::check_node_name(route).is_ok() => {
                Dest::Route(node, route)
            }
            None if check_name(word).is_ok() => Dest::Node(word),
            _ => Dest::Unknown,
        }
    }

    /// Whether the word reaches `want`.
    pub fn reaches(&self, policy: &Policy, want: Want<'_>) -> bool {
        match (*self, want) {
            (Dest::All, _) => true,
            (Dest::Node(named), Want::Node { node, .. } | Want::AnyOf(node)) => named == node,
            (Dest::Route(named, one), Want::Node { node, route: Some(route) }) => named == node && one == route,
            (Dest::Route(named, _), Want::AnyOf(node)) => named == node,
            (Dest::Tag(tag), Want::Node { node, .. } | Want::AnyOf(node)) => policy.tagged(tag, node),
            (Dest::Exit(None), Want::Exit(_) | Want::AnyOf(_) | Want::Egress(_)) => true,
            (Dest::Exit(Some(named)), Want::Exit(node) | Want::AnyOf(node) | Want::Egress(node)) => named == node,
            // A relay's mint is no door of the node: `relay:NODE` lets a
            // member mint there, and reach nothing of the node by it.
            (Dest::Relay(None), Want::Relay(_)) => true,
            (Dest::Relay(Some(named)), Want::Relay(Some(node))) => named == node,
            (Dest::Range(range), Want::Addr(addr)) => range.contains(addr),
            // Which node routes a range is T-432's: a road's door lets the
            // member come in to ask, and the channel checks the address.
            (Dest::Range(_), Want::AnyOf(_) | Want::Egress(_)) => true,
            _ => false,
        }
    }
}

/// A range of addresses: `ADDR/BITS`, or one address alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    addr: IpAddr,
    bits: u8,
}

impl Range {
    pub fn parse(word: &str) -> Option<Range> {
        let (addr, bits) = match word.split_once('/') {
            Some((addr, bits)) => (addr, Some(bits)),
            None => (word, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let most = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => most,
            // Digits alone: `u8`'s parser takes a sign too.
            Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
                text.parse::<u8>().ok().filter(|&bits| bits <= most)?
            }
            Some(_) => return None,
        };
        Some(Range { addr, bits })
    }

    /// Whether `addr` is in the range: of the same family, and the same in
    /// the range's first bits.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(one)) => same_prefix(&net.octets(), &one.octets(), self.bits),
            (IpAddr::V6(net), IpAddr::V6(one)) => same_prefix(&net.octets(), &one.octets(), self.bits),
            _ => false,
        }
    }
}

/// Whether `a` and `b` have the same first `bits` bits.
fn same_prefix(a: &[u8], b: &[u8], bits: u8) -> bool {
    let (whole, rest) = (usize::from(bits / 8), bits % 8);
    if a[..whole] != b[..whole] {
        return false;
    }
    let mask = 0xffu8.checked_shl(u32::from(8 - rest)).unwrap_or(0);
    rest == 0 || a[whole] & mask == b[whole] & mask
}
