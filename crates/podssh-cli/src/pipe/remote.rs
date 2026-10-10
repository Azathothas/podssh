//! The remote ends of `podssh pipe` (T-175): each opens its road and gives
//! an end; the pump does not know the road (`docs/architecture.md`). The
//! settings of the roads come from the flags of `pipe`, as `proxy` and
//! `ssh` take them, and are read only when an address needs them.

use std::io::Write;

use podssh_relay::relay::{self, RelayList};
use podssh_ws::{ProxyChoice, Trust};

use super::address::Address;
use super::pump::End;
use super::PipeArgs;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;

/// The roads' settings, read once both addresses are checked.
pub struct Settings {
    pub relays: Option<RelayList>,
    pub trust: Trust,
    /// What an SSH hop, a node and the iroh road read: `pipe`'s flags.
    pub ssh: crate::ssh::args::SshArgs,
}

/// Whether `address` leaves this host.
pub fn is_remote(address: &Address) -> bool {
    matches!(
        address,
        Address::Relay { .. } | Address::Tcp { .. } | Address::Ssh { .. } | Address::Node(_) | Address::Iroh(_)
    )
}

/// The settings that the remote addresses of `args` need: the pins of
/// `--relay-addr`, the relay hosts, the trust.
pub fn settings(args: &PipeArgs, addresses: [&Address; 2]) -> Result<Settings, Refusal> {
    crate::pins::apply(args.ssh.relay_addr.as_deref())?;
    let relays = if addresses.iter().any(|a| matches!(a, Address::Relay { .. })) {
        Some(crate::relay_settings::relays(args.ssh.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok())?)
    } else {
        None
    };
    let ca_file =
        args.ssh.ca_file.clone().or_else(|| std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty()));
    let trust = match ca_file {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    if addresses.iter().any(|a| matches!(a, Address::Ssh { .. })) {
        super::ssh::check_options(&args.ssh.options)?;
    }
    Ok(Settings { relays, trust, ssh: args.ssh.clone() })
}

/// Open a remote end: the end, or the exit code once its lines are written.
pub async fn open(address: &Address, settings: &Settings, err: &mut dyn Write) -> Result<End, i32> {
    let mut say = |line: &str| {
        let _ = writeln!(err, "podssh pipe: {line}");
    };
    match address {
        Address::Relay { host, port } => {
            let relays = settings.relays.as_ref().expect("the relay hosts, read with the addresses");
            let road = super::relay::Road { relays, trust: &settings.trust };
            super::relay::open(&road, host, *port, &mut say).await
        }
        Address::Tcp { host, port } => tcp(host, *port, &mut say).await,
        Address::Ssh { hops, host, port } => super::ssh::open(hops, host, *port, &settings.ssh, &mut say).await,
        Address::Node(label) => super::node::open(label, &settings.ssh, &mut say).await,
        Address::Iroh(ticket) => super::iroh::open(ticket, &settings.ssh, &settings.trust, &mut say).await,
        _ => unreachable!("a local address"),
    }
}

/// `tcp:HOST:PORT`: TCP from this host, through `HTTPS_PROXY` when it is
/// set, as `ssh --direct` dials. TCP has a half-close, so each direction
/// ends by itself.
async fn tcp(host: &str, port: u16, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    if podssh_relay::open::offline() {
        say(&format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV));
        return Err(EX_UNAVAILABLE);
    }
    let target = podssh_ws::dial::authority(host, port);
    match podssh_ws::dial::dial(host, port, &ProxyChoice::FromEnvironment, podssh_relay::open::CONNECT_TIMEOUT).await {
        Ok(stream) => {
            let _ = stream.set_nodelay(true);
            let (read, write) = tokio::io::split(stream);
            Ok(End::plain(Box::new(read), Box::new(write)))
        }
        Err(e) => {
            say(&format!("could not connect to {target}: {e}"));
            Err(dial_code(&e))
        }
    }
}

/// The sysexits code of a dial that failed, as `proxy` gives it.
fn dial_code(e: &podssh_ws::DialError) -> i32 {
    use podssh_ws::DialError;
    match e {
        DialError::BadProxy(_) | DialError::InvalidTarget(_) => EX_CONFIG,
        DialError::ProxyRefused { status: 403 | 407, .. } => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}
