//! The roads of servers that the user names in place of the relay: the
//! forwarders (T-369), Shadowsocks servers (T-373), a forward proxy over TLS
//! (T-439), VLESS servers (T-440) and a wstunnel server (T-441). Each takes
//! the relay's place when named, and each refuses the others, as a run has
//! one road; here so that the resolver stays one file. An exit of the net
//! (T-431, `super::exit_road`) takes it first.

use super::args::SshArgs;
use super::resolve::{Env, Resolved, Transport};
use crate::relay_settings::Refusal;

/// The road of a run that resolved to the relay: a server's road when the
/// command line or the environment names one, else the relay. VLESS and
/// wstunnel come before `--via`, so that each flag wins over `PODSSH_VIA`.
pub(super) fn or_relay(args: &SshArgs, env: &Env, relay: Transport) -> Result<Transport, Refusal> {
    if args.exit.is_some() {
        return super::exit_road::or_exit(args, env, relay);
    }
    let relay = crate::vless::or_relay(args, relay)?;
    let relay = crate::via::or_relay(args, env, crate::wstunnel::or_relay(args, env, relay)?)?;
    crate::shadowsocks::or_relay(args, crate::forwarder::or_relay(args, env, relay)?)
}

/// Each server's flag beside a road of its own, which [`or_relay`] never
/// took: a usage error; and the exit's word, once the first hop is known.
pub(super) fn check(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    super::exit_road::fill(args, resolved)?;
    let resolved: &Resolved = resolved;
    crate::forwarder::check(args, resolved)
        .and_then(|()| crate::shadowsocks::check(args, resolved))
        .and_then(|()| crate::via::check(args, resolved))
        .and_then(|()| crate::vless::check(args, resolved))
        .and_then(|()| crate::wstunnel::check(args, resolved))
}
