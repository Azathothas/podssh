//! The roads of servers that the user names in place of the relay: the
//! forwarders (T-369), Shadowsocks servers (T-373), a forward proxy over TLS
//! (T-439), VLESS servers (T-440), a wstunnel server (T-441), a chisel
//! server (T-490) and Trojan servers (T-491). Each takes
//! the relay's place when named, and each refuses the others, as a run has
//! one road; here so that the resolver stays one file. An exit of the net
//! (T-431, `super::exit_road`) takes it first.

use super::args::SshArgs;
use super::resolve::{Env, Resolved, Transport};
use crate::relay_settings::Refusal;

/// The road of a run that resolved to the relay: a server's road when the
/// command line or the environment names one, else the relay. chisel,
/// VLESS and wstunnel come before `--via`, so that each flag wins over
/// `PODSSH_VIA`.
pub(super) fn or_relay(args: &SshArgs, env: &Env, relay: Transport) -> Result<Transport, Refusal> {
    if args.exit.is_some() {
        return super::exit_road::or_exit(args, env, relay);
    }
    let relay = crate::chisel::or_relay(args, env, relay)?;
    let relay = crate::trojan::or_relay(args, relay)?;
    let relay = crate::vless::or_relay(args, relay)?;
    let relay = crate::via::or_relay(args, env, crate::wstunnel::or_relay(args, env, relay)?)?;
    crate::shadowsocks::or_relay(args, crate::forwarder::or_relay(args, env, relay)?)
}

/// Each server's flag beside a road of its own, which [`or_relay`] never
/// took: a usage error; and the exit's word, once the first hop is known.
/// A carrier beside a destination that is no node is refused first (T-595).
pub(super) fn check(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    super::carried::check(args, resolved)?;
    super::exit_road::fill(args, resolved)?;
    let resolved: &Resolved = resolved;
    crate::forwarder::check(args, resolved)
        .and_then(|()| crate::shadowsocks::check(args, resolved))
        .and_then(|()| crate::via::check(args, resolved))
        .and_then(|()| crate::vless::check(args, resolved))
        .and_then(|()| crate::wstunnel::check(args, resolved))
        .and_then(|()| crate::chisel::check(args, resolved))
        .and_then(|()| crate::trojan::check(args, resolved))
}

/// The words of a run's road, for the refusal of a flag of another road
/// beside it (T-490; the other roads keep their own lists).
pub(crate) fn road_name(transport: &Transport) -> &'static str {
    match transport {
        Transport::Direct => "--direct",
        Transport::Relay { .. } => "the relay",
        Transport::Forwarder { .. } => "the forwarders",
        Transport::Shadowsocks { .. } => "--shadowsocks",
        Transport::Via { .. } => "--via",
        Transport::Vless { .. } => "--vless",
        Transport::Wstunnel { .. } => "--wstunnel",
        Transport::Chisel { .. } => "--chisel",
        Transport::Trojan { .. } => "--trojan",
        Transport::Node { .. } => "a node:// destination",
        Transport::Iroh { .. } => "an iroh: destination",
        Transport::Cloudflare { .. } => "a cf://HOST destination or first hop",
        Transport::Cloud { .. } => "an iap://, eice://, warp:// or tor:// destination or first hop",
        Transport::Derp { .. } => "a derp: destination",
    }
}
