//! What the relay role knows of its host's way out to IPv6 (T-253), so that
//! an IPv6 target that this host cannot route gets the role's `502` before
//! the upgrade, with why: the default relay upgraded such a session and then
//! closed it with `1011 target closed before sending anything`, which tells a
//! client nothing (`docs/relay.md`, "IPv6 targets").
//!
//! Two sources, each probed at run time. This host's table of IPv6 routes,
//! read as a file where Linux gives one (`/proc/net/ipv6_route`), which opens
//! no socket and sends nothing. Where no table can be read, the role's own
//! dials: a direct one that met no route (no route, no address of the
//! family) holds for a minute, and one that connected says that a route
//! exists. Through the host's proxy (T-457) the proxy's way out is the one
//! that counts, and the role knows nothing of it. The loopback is this
//! host's own, and an IPv4 address written as IPv6 is IPv4's.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::egress::{Egress, Plan};

/// The role's words for a target that its host has no route to, which the
/// client reads (`crate::relay`).
pub use crate::relay::NO_IPV6_ROUTE;

/// The table of routes, on Linux.
const ROUTES: &str = "/proc/net/ipv6_route";
/// How long a reading of the table holds before it is read again: a route
/// that comes up is seen within it.
const ROUTES_HOLD: Duration = Duration::from_secs(30);
/// How long a dial that met no route holds, where no table says otherwise.
const UNROUTED_HOLD: Duration = Duration::from_secs(60);
/// An address of the public internet that names no host: what a route out
/// covers, for the role's word in `/relays.json`.
const ANY_PUBLIC: Ipv6Addr = Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 1);
/// The flags of a route (`include/uapi/linux/ipv6_route.h`): it is up, and it
/// rejects what it takes (an `unreachable`, a `prohibit` or the null route).
const RTF_UP: u32 = 0x0001;
const RTF_REJECT: u32 = 0x0200;

/// A dial with no address of its family on this host: `EAFNOSUPPORT`, which
/// the standard library gives no kind of its own.
#[cfg(any(target_os = "linux", target_os = "android"))]
const EAFNOSUPPORT: i32 = 97;
#[cfg(windows)]
const EAFNOSUPPORT: i32 = 10047;
#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
const EAFNOSUPPORT: i32 = 47;

/// One route of the table: its prefix, its length, and whether it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Route {
    prefix: u128,
    bits: u32,
    usable: bool,
}

/// The routes of `table`, in the form of `/proc/net/ipv6_route`: a line for
/// each, the destination and its length in hex, the source and its length,
/// the next hop, the metric, two counts, the flags and the device. A line of
/// another form is passed over.
fn routes(table: &str) -> Vec<Route> {
    let route = |line: &str| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            return None;
        }
        let prefix = u128::from_str_radix(f[0], 16).ok()?;
        let bits = u32::from_str_radix(f[1], 16).ok().filter(|b| *b <= 128)?;
        let flags = u32::from_str_radix(f[8], 16).ok()?;
        Some(Route { prefix, bits, usable: flags & RTF_UP != 0 && flags & RTF_REJECT == 0 })
    };
    table.lines().filter_map(route).collect()
}

/// Whether `routes` carry `ip`, as the kernel picks: the longest prefix that
/// covers it, and of two as long, either that carries.
fn carries(routes: &[Route], ip: Ipv6Addr) -> bool {
    let ip = u128::from(ip);
    // A prefix of 0 bits covers each address; a shift by 128 would overflow.
    let covers = |r: &Route| r.bits == 0 || ip >> (128 - r.bits) == r.prefix >> (128 - r.bits);
    let Some(best) = routes.iter().filter(|r| covers(r)).map(|r| r.bits).max() else { return false };
    routes.iter().any(|r| covers(r) && r.bits == best && r.usable)
}

/// Whether `e`, of a dial, says that this host has no route to the address,
/// or no address of its family: not a refusal or a silence of the target.
fn unrouted(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{AddrNotAvailable, NetworkDown, NetworkUnreachable};
    matches!(e.kind(), NetworkUnreachable | NetworkDown | AddrNotAvailable) || e.raw_os_error() == Some(EAFNOSUPPORT)
}

/// The IPv6 address of `address` that leaves this host: none for the
/// loopback, or an IPv4 address written as IPv6.
fn out_of_host(address: &SocketAddr) -> Option<Ipv6Addr> {
    match address.ip() {
        IpAddr::V6(ip) if !ip.is_loopback() && ip.to_ipv4_mapped().is_none() => Some(ip),
        _ => None,
    }
}

/// What the role knows of IPv6 out of its host, shared by its sessions.
#[derive(Clone, Default)]
pub struct Ipv6Out(Arc<Known>);

#[derive(Default)]
struct Known {
    /// Given in place of the probes, as a host's table would read.
    given: Option<bool>,
    /// The file of the table, where not Linux's (a test's).
    file: Option<std::path::PathBuf>,
    /// The routes as last read, and when; `None` inside where this host has
    /// no table to read.
    table: Mutex<Option<(Instant, Option<Vec<Route>>)>>,
    /// When a direct dial last met no route.
    unrouted: Mutex<Option<Instant>>,
    /// Whether a direct dial to an IPv6 address out of this host connected.
    reached: AtomicBool,
}

impl std::fmt::Debug for Ipv6Out {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ipv6Out").field(&self.0.given).finish()
    }
}

impl Ipv6Out {
    /// A host with no IPv6 route out, as its table would read, with no probe.
    pub fn none() -> Ipv6Out {
        Ipv6Out(Arc::new(Known { given: Some(false), ..Known::default() }))
    }

    /// A host with an IPv6 route out, with no probe.
    pub fn routed() -> Ipv6Out {
        Ipv6Out(Arc::new(Known { given: Some(true), ..Known::default() }))
    }

    /// The probes, with the table read from `file`: a test's, or one that
    /// does not exist, for a host with no table.
    #[cfg(test)]
    fn reading(file: std::path::PathBuf) -> Ipv6Out {
        Ipv6Out(Arc::new(Known { file: Some(file), ..Known::default() }))
    }

    /// Whether this host routes `ip` out, and by what that is known; `None`
    /// where nothing tells. The table wins over a dial, as a dial meets one
    /// address alone.
    pub fn routes(&self, ip: Ipv6Addr) -> (Option<bool>, &'static str) {
        if ip.is_loopback() || ip.to_ipv4_mapped().is_some() {
            return (Some(true), "the loopback, or IPv4");
        }
        if let Some(given) = self.0.given {
            return (Some(given), "given");
        }
        if let Some(table) = self.table() {
            return (Some(carries(&table, ip)), "the routes of this host");
        }
        let unrouted = *self.0.unrouted.lock().unwrap_or_else(PoisonError::into_inner);
        if unrouted.is_some_and(|at| at.elapsed() < UNROUTED_HOLD) {
            return (Some(false), "a dial that met no route");
        }
        if self.0.reached.load(Ordering::Relaxed) {
            return (Some(true), "a dial that connected");
        }
        (None, "nothing before a dial")
    }

    /// `plan` without the IPv6 addresses that this host dials itself and
    /// cannot route, so that a name of both families keeps its IPv4 ones.
    /// `Err` holds the words of the `502` when nothing is left.
    pub fn keep(&self, plan: Plan, name: &str, egress: &Egress) -> Result<Plan, String> {
        let Plan::Addresses(addresses) = plan else { return Ok(plan) };
        // The name's NO_PROXY, and the address's, as the dial reads them.
        let direct = |a: &SocketAddr| egress.proxy_for(name).and(egress.proxy_for(&a.ip().to_string())).is_none();
        let lost = |a: &SocketAddr| out_of_host(a).is_some_and(|ip| direct(a) && self.routes(ip).0 == Some(false));
        let (out, kept): (Vec<SocketAddr>, Vec<SocketAddr>) = addresses.into_iter().partition(lost);
        if kept.is_empty() && !out.is_empty() {
            return Err(NO_IPV6_ROUTE.to_string());
        }
        Ok(Plan::Addresses(kept))
    }

    /// A direct dial of `address` connected.
    pub fn reached(&self, address: &SocketAddr) {
        if out_of_host(address).is_some() {
            self.0.reached.store(true, Ordering::Relaxed);
        }
    }

    /// The client's words for a direct dial of `address` that failed with
    /// `e`; a fault that says no route out is kept, and named.
    pub fn missed(&self, address: &SocketAddr, e: &std::io::Error) -> String {
        if out_of_host(address).is_none() || !unrouted(e) {
            return format!("{address}: {e}");
        }
        *self.0.unrouted.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        format!("{NO_IPV6_ROUTE} ({address}: {e})")
    }

    /// The role's word in `/relays.json`: whether its host routes IPv6 out,
    /// `null` where nothing tells or where its proxy decides, and by what.
    pub fn doc(&self, egress: &Egress) -> Value {
        if egress.proxy_for(&ANY_PUBLIC.to_string()).is_some() {
            return json!({ "ipv6": null, "known_by": "the proxy of the relay's host decides" });
        }
        let (routed, how) = self.routes(ANY_PUBLIC);
        json!({ "ipv6": routed, "known_by": how })
    }

    /// The table of routes, read again once it is older than its hold.
    fn table(&self) -> Option<Vec<Route>> {
        let mut held = self.0.table.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((at, table)) = held.as_ref() {
            if at.elapsed() < ROUTES_HOLD {
                return table.clone();
            }
        }
        let file = self.0.file.as_deref().unwrap_or(std::path::Path::new(ROUTES));
        // A file of no route is no table: a host that hides it says nothing.
        let read = std::fs::read_to_string(file).ok().map(|text| routes(&text)).filter(|r| !r.is_empty());
        *held = Some((Instant::now(), read.clone()));
        read
    }
}

#[cfg(test)]
#[path = "ipv6_tests.rs"]
mod tests;
